//! Start-up checks (PRD section 6 preamble, FR-01, FR-12 AC3, FR-14 AC3, FR-19 AC1,
//! FR-22 AC4, SEC-09, SEC-19).
//!
//! [`gather`] reads the drives (run it off the GUI thread); [`evaluate`] turns the
//! result into what the screen shows and whether the operator may continue:
//! - a broken audit chain is a blocking warning naming the first bad entry (FR-14 AC3);
//! - an interrupted operation opens the recovery screen (FR-22 AC4);
//! - divergent histories are shown side by side and every signing action is disabled
//!   (FR-12 AC3); Keystone never chooses a history;
//! - drives that are behind list the missing operations; they are copied only after the
//!   operator confirms (FR-12 AC3);
//! - CRLs close to nextUpdate raise a warning that opens Refresh CRL (FR-13 AC3);
//! - a drive whose journal cannot be read blocks every action until it is repaired or
//!   replaced (`RecoveryReport::unreadable`);
//! - with fewer than the primary and one backup connected, every signing action is
//!   disabled and only "Replace a lost drive" is offered (FR-12 AC1, ADR 0003).
#![forbid(unsafe_code)]

use keystone_core::store::{
    AuditAction, AuditEntry, AuditResult, DriveComparison, DriveHistory, DriveSet, IssuanceRecord,
    ParseError, RecoveryReport, RepairPlan, RepairStep, StoreError,
};
use time::OffsetDateTime;

use super::crl::{CrlWarning, CurrentCrl, current_crls, warnings};
use super::{Line, Status, format_utc};
use crate::backend::DriveSelection;

/// The audit-log check of one drive (FR-14 AC3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveAudit {
    /// Drive label.
    pub drive: String,
    /// Number of verified entries, or why the log is broken.
    pub result: Result<usize, AuditFailure>,
}

/// A log that did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFailure {
    /// 1-based number of the first bad entry, when the chain itself is broken.
    pub first_bad_entry: Option<u64>,
    /// What is wrong.
    pub message: String,
}

/// Everything read from the drives at start.
#[derive(Debug, Clone, Default)]
pub struct StartupData {
    /// True when the drives are empty (Flow A).
    pub new_ca: bool,
    /// The drives could not be opened together.
    pub open_error: Option<String>,
    /// Per drive.
    pub audit: Vec<DriveAudit>,
    /// Drive comparison (FR-12 AC3).
    pub comparison: Option<Result<DriveComparison, String>>,
    /// Interrupted operations (FR-22 AC4).
    pub recovery: Option<Result<RecoveryReport, String>>,
    /// The issuance record, when every drive holds the same one.
    pub record: Option<Result<IssuanceRecord, String>>,
    /// The longest verified audit log's entries (for the clock baseline, FR-17 AC2).
    pub audit_entries: Vec<AuditEntry>,
    /// Current CRL per issuer.
    pub crls: Vec<CurrentCrl>,
    /// SEC-19 self-check result: a warning to show, or why it could not run.
    pub self_check: Option<Result<Option<String>, String>>,
    /// FR-12 AC1: `(primaries, backups)` connected when that is not enough to write.
    pub not_enough_drives: Option<(usize, usize)>,
}

/// Reads everything the start-up checks need. Never writes.
pub fn gather(selection: &DriveSelection, new_ca: bool) -> StartupData {
    let mut data = StartupData {
        new_ca,
        ..StartupData::default()
    };
    if new_ca {
        return data;
    }
    let set = match DriveSet::open(&selection.ca_drives()) {
        Ok(set) => set,
        Err(error) => {
            data.open_error = Some(error.to_string());
            return data;
        }
    };
    if let Err(StoreError::NotEnoughDrives { primaries, backups }) = set.ensure_writable() {
        data.not_enough_drives = Some((primaries, backups));
    }
    let mut all_verified = true;
    for drive in set.drives() {
        let result = match drive.audit_log() {
            Ok(log) => {
                if log.len() > data.audit_entries.len() {
                    data.audit_entries = log.entries().to_vec();
                }
                Ok(log.len())
            }
            Err(error) => {
                all_verified = false;
                Err(audit_failure(&error))
            }
        };
        data.audit.push(DriveAudit {
            drive: drive.label(),
            result,
        });
    }
    data.comparison = Some(set.compare().map_err(|e| e.to_string()));
    if all_verified {
        data.recovery = Some(set.recovery_report().map_err(|e| e.to_string()));
    }
    let in_sync = matches!(data.comparison, Some(Ok(DriveComparison::InSync)));
    if in_sync {
        let record = set.issuance_record().map_err(|e| e.to_string());
        if let (Ok(record), Some(primary)) = (&record, set.drives().first())
            && let Ok(journals) = primary.journal()
        {
            data.crls = current_crls(&journals, record);
        }
        data.record = Some(record);
    }
    #[cfg(feature = "production")]
    {
        use keystone_core::hardening::selfcheck::check_running_binary;
        data.self_check = Some(
            check_running_binary(&set)
                .map(|check| check.warning())
                .map_err(|e| e.to_string()),
        );
    }
    data
}

fn audit_failure(error: &StoreError) -> AuditFailure {
    match error {
        StoreError::Parse {
            source: ParseError::Audit { entry, problem },
            ..
        } => AuditFailure {
            first_bad_entry: Some(*entry),
            message: format!("entry {entry} is the first bad entry: {problem}"),
        },
        other => AuditFailure {
            first_bad_entry: None,
            message: other.to_string(),
        },
    }
}

/// Whether the operator may go on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// Everything is consistent: continue to the clock confirmation.
    Continue,
    /// Some drives are behind: confirm the repair first.
    NeedsRepair,
    /// An operation was interrupted: open the recovery screen first.
    NeedsRecovery,
    /// Fewer than the primary and one backup are connected: only "Replace a lost
    /// drive" can write (ADR 0003). The text says what is connected.
    NeedsDriveReplacement(String),
    /// Every signing action is disabled; the text says why.
    Blocked(String),
}

/// A titled group of lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Title.
    pub title: String,
    /// Lines.
    pub lines: Vec<Line>,
}

/// One behind drive and what will be copied to it (FR-12 AC3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairView {
    /// "backup drive … is missing 2 operations from primary drive …".
    pub heading: String,
    /// One line per missing operation or audit entry.
    pub missing: Vec<String>,
}

/// One history column when the drives diverge (FR-12 AC3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryColumn {
    /// Drives holding this history.
    pub title: String,
    /// Entries after the common point.
    pub entries: Vec<String>,
}

/// What the start-up checks screen shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupView {
    /// Check results, in order.
    pub sections: Vec<Section>,
    /// What the operator may do next.
    pub gate: Gate,
    /// Behind drives, when a repair is offered.
    pub repairs: Vec<RepairView>,
    /// The plans to carry out after the operator confirms.
    pub repair_plans: Vec<RepairPlan>,
    /// Divergent histories, side by side.
    pub histories: Vec<HistoryColumn>,
    /// Entries shared by every drive before the histories split.
    pub common_entries: usize,
    /// Interrupted operations.
    pub pending_operations: usize,
    /// CRL warnings (each opens Refresh CRL).
    pub crl_warnings: Vec<CrlWarning>,
}

/// The audit action in words.
pub fn action_name(action: AuditAction) -> &'static str {
    match action {
        AuditAction::CreateMaster => "create master",
        AuditAction::SetupYubikey => "set up YubiKey and main intermediate",
        AuditAction::CreateSubIntermediate => "create sub-intermediate",
        AuditAction::Revoke => "revoke",
        AuditAction::RefreshCrl => "refresh CRL",
        AuditAction::ReplaceYubikey => "replace lost YubiKey",
        AuditAction::ClockCorrection => "clock correction",
        AuditAction::DriveRepair => "drive repair",
        AuditAction::RecoveryFinish => "finish interrupted operation",
        AuditAction::RecoveryAbandon => "abandon interrupted operation",
        AuditAction::Export => "export",
        AuditAction::BinaryHashRecorded => "record program SHA-256",
    }
}

fn result_name(result: AuditResult) -> &'static str {
    match result {
        AuditResult::Success => "success",
        AuditResult::Failure => "failure",
        AuditResult::Cancelled => "cancelled",
        AuditResult::Abandoned => "abandoned",
    }
}

/// One audit entry on one line: `#3 2026-11-01 10:00:00 UTC create master CN=… (success)`,
/// with the details that say what happened: a finished operation's original action,
/// the serials it concerns, a drive added or promoted by "Replace a lost drive".
pub fn format_entry(entry: &AuditEntry) -> String {
    let details = entry.details.as_ref();
    let replaced = details.is_some_and(|d| d.drive_added.is_some());
    let action = if replaced {
        "replace a lost drive"
    } else {
        action_name(entry.action)
    };
    let mut text = format!("#{} {} {action}", entry.seq, format_utc(entry.time.get()));
    if let Some(original) = details.and_then(|d| d.original_action) {
        text.push_str(&format!(" of \"{}\"", action_name(original)));
    }
    if !entry.subject.is_empty() {
        text.push(' ');
        text.push_str(&entry.subject);
    }
    if let Some(operation) = entry.operation {
        text.push_str(&format!(", {operation}"));
    }
    if let Some(details) = details {
        if let Some(drive) = details.drive_added {
            text.push_str(&format!(", new drive {}", drive.short()));
        }
        if let Some(drive) = details.primary_promoted {
            text.push_str(&format!(", drive {} promoted to primary", drive.short()));
        }
        if let Some(serials) = details.serials.as_ref().filter(|s| !s.is_empty()) {
            text.push_str(&format!(
                ", serial{} {}",
                if serials.len() == 1 { "" } else { "s" },
                serials
                    .iter()
                    .map(|serial| serial.to_hex())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    text.push_str(&format!(" ({})", result_name(entry.result)));
    text
}

fn repair_view(plan: &RepairPlan) -> RepairView {
    let mut missing = Vec::new();
    let mut operations = 0usize;
    for step in &plan.steps {
        match step {
            RepairStep::Operation {
                operation,
                entries,
                outputs,
                ..
            } => {
                operations += 1;
                let what = entries
                    .first()
                    .map(format_entry)
                    .unwrap_or_else(|| operation.to_string());
                missing.push(format!(
                    "{operation}: {what}; {} audit entr{}, {} file{} to copy",
                    entries.len(),
                    if entries.len() == 1 { "y" } else { "ies" },
                    outputs.len(),
                    if outputs.len() == 1 { "" } else { "s" }
                ));
            }
            RepairStep::AuditOnly { entries } => {
                missing.extend(entries.iter().map(format_entry));
            }
        }
    }
    RepairView {
        heading: format!(
            "{} is behind {}: {operations} operation{} and {} line{} to copy.",
            plan.target_label,
            plan.source_label,
            if operations == 1 { "" } else { "s" },
            missing.len(),
            if missing.len() == 1 { "" } else { "s" }
        ),
        missing,
    }
}

fn history_column(history: &DriveHistory) -> HistoryColumn {
    HistoryColumn {
        title: history.drives.join(" and "),
        entries: if history.entries.is_empty() {
            vec!["(no entries after the common point)".to_string()]
        } else {
            history.entries.iter().map(format_entry).collect()
        },
    }
}

/// Turns [`StartupData`] into the screen (`production`: this is a production build).
pub fn evaluate(data: &StartupData, production: bool, now: OffsetDateTime) -> StartupView {
    let mut view = StartupView {
        sections: Vec::new(),
        gate: Gate::Continue,
        repairs: Vec::new(),
        repair_plans: Vec::new(),
        histories: Vec::new(),
        common_entries: 0,
        pending_operations: 0,
        crl_warnings: Vec::new(),
    };
    view.sections.push(Section {
        title: "Network".to_string(),
        lines: vec![if production {
            Line::new(
                Status::Ok,
                "No network interface other than loopback was up when Keystone started.",
            )
        } else {
            Line::new(
                Status::Info,
                "Development build: the network check is compiled only into production builds (FR-01 AC2).",
            )
        }],
    });
    if let Some(self_check) = &data.self_check {
        let line = match self_check {
            Ok(None) => Line::new(
                Status::Ok,
                "This program matches the SHA-256 recorded at install, or none is recorded yet.",
            ),
            Ok(Some(warning)) => Line::new(Status::Warning, warning.clone()),
            Err(error) => Line::new(
                Status::Warning,
                format!("The program self-check could not run: {error}"),
            ),
        };
        view.sections.push(Section {
            title: "Program self-check".to_string(),
            lines: vec![line],
        });
    }
    if data.new_ca {
        view.sections.push(Section {
            title: "Drives".to_string(),
            lines: vec![Line::new(
                Status::Info,
                "The drives are empty: there is no audit log or history to check yet. You can create a new CA.",
            )],
        });
        return view;
    }
    if let Some(error) = &data.open_error {
        view.sections.push(Section {
            title: "Drives".to_string(),
            lines: vec![Line::new(
                Status::Blocked,
                format!("The drives cannot be opened together: {error}"),
            )],
        });
        view.gate = Gate::Blocked(format!("The drives cannot be opened together: {error}"));
        return view;
    }
    // Audit log (FR-14 AC3).
    let mut audit_lines = Vec::new();
    let mut broken = Vec::new();
    for audit in &data.audit {
        match &audit.result {
            Ok(count) => audit_lines.push(Line::new(
                Status::Ok,
                format!("{}: the audit log verifies ({count} entries).", audit.drive),
            )),
            Err(failure) => {
                let text = format!(
                    "{}: the audit log is broken: {}. Keystone will not sign anything until this is resolved.",
                    audit.drive, failure.message
                );
                broken.push(text.clone());
                audit_lines.push(Line::new(Status::Blocked, text));
            }
        }
    }
    view.sections.push(Section {
        title: "Audit log".to_string(),
        lines: audit_lines,
    });
    // Drive comparison (FR-12 AC3).
    let mut compare_lines = Vec::new();
    let mut comparison_block = None;
    let mut damaged = false;
    match &data.comparison {
        None => {}
        Some(Err(error)) => {
            compare_lines.push(Line::new(
                Status::Blocked,
                format!("The drives could not be compared: {error}"),
            ));
            comparison_block = Some(format!("The drives could not be compared: {error}"));
        }
        Some(Ok(DriveComparison::InSync)) => compare_lines.push(Line::new(
            Status::Ok,
            format!("All {} drives hold the same history.", data.audit.len()),
        )),
        Some(Ok(DriveComparison::Behind { plans })) => {
            view.repairs = plans.iter().map(repair_view).collect();
            view.repair_plans.clone_from(plans);
            compare_lines.push(Line::new(
                Status::Warning,
                "Some drives are behind. Check the missing operations below, then copy them. Signing stays disabled until every drive is up to date.",
            ));
        }
        Some(Ok(DriveComparison::Diverged { common, histories })) => {
            view.common_entries = *common;
            view.histories = histories.iter().map(history_column).collect();
            let text = format!(
                "The drives hold different histories after entry {common}. Both are shown side by side. Keystone never chooses one; every signing action is disabled."
            );
            compare_lines.push(Line::new(Status::Blocked, text.clone()));
            comparison_block = Some(text);
        }
        Some(Ok(DriveComparison::Damaged { problems })) => {
            damaged = true;
            for problem in problems {
                compare_lines.push(Line::new(Status::Blocked, problem.clone()));
            }
            comparison_block = Some(
                "Something on the drives cannot be verified; every signing action is disabled."
                    .to_string(),
            );
        }
    }
    if !compare_lines.is_empty() {
        view.sections.push(Section {
            title: "Drive comparison".to_string(),
            lines: compare_lines,
        });
    }
    // Connected drives (FR-12 AC1, ADR 0003).
    let mut too_few = None;
    if let Some((primaries, backups)) = data.not_enough_drives {
        let text = format!(
            "Connected: {primaries} primary and {backups} backup drive{}. Every signing action needs the primary drive and at least one backup. If a drive is lost or broken, replace it with a new, empty drive.",
            if backups == 1 { "" } else { "s" }
        );
        view.sections.push(Section {
            title: "Connected drives".to_string(),
            lines: vec![Line::new(Status::Blocked, text.clone())],
        });
        too_few = Some(text);
    }
    // Interrupted operations (FR-22 AC4).
    let mut recovery_lines = Vec::new();
    let mut unreadable = Vec::new();
    match &data.recovery {
        None => recovery_lines.push(Line::new(
            Status::Blocked,
            "Interrupted operations cannot be checked while an audit log is broken.",
        )),
        Some(Err(error)) => recovery_lines.push(Line::new(
            Status::Blocked,
            format!("Interrupted operations could not be checked: {error}"),
        )),
        Some(Ok(report)) if report.is_clean() => {
            recovery_lines.push(Line::new(Status::Ok, "No operation was interrupted."))
        }
        Some(Ok(report)) => {
            for problem in &report.unreadable {
                let text = format!(
                    "{problem} Keystone offers no action for an interrupted operation until this drive is repaired or replaced."
                );
                recovery_lines.push(Line::new(Status::Blocked, text.clone()));
                unreadable.push(text);
            }
            if report.pending.is_empty() && report.unreadable.is_empty() {
                recovery_lines.push(Line::new(Status::Ok, "No operation was interrupted."));
            }
            view.pending_operations = report.pending.len();
            for pending in &report.pending {
                recovery_lines.push(Line::new(
                    Status::Blocked,
                    format!(
                        "{} ({}) was interrupted. Open the recovery screen to see what each drive holds.",
                        pending.operation, pending.subject
                    ),
                ));
            }
        }
    }
    view.sections.push(Section {
        title: "Interrupted operations".to_string(),
        lines: recovery_lines,
    });
    // Issuance record and CRLs.
    if let Some(Err(error)) = &data.record {
        view.sections.push(Section {
            title: "Issuance record".to_string(),
            lines: vec![Line::new(
                Status::Blocked,
                format!("The issuance record could not be read: {error}"),
            )],
        });
        comparison_block
            .get_or_insert_with(|| format!("The issuance record could not be read: {error}"));
    }
    view.crl_warnings = warnings(&data.crls, now);
    if !data.crls.is_empty() {
        let mut lines: Vec<Line> = view
            .crl_warnings
            .iter()
            .map(|w| Line::new(w.status, w.text.clone()))
            .collect();
        if lines.is_empty() {
            lines.push(Line::new(
                Status::Ok,
                "Every CRL is more than 30 days from its next update.",
            ));
        }
        view.sections.push(Section {
            title: "CRLs".to_string(),
            lines,
        });
    }
    view.gate = if !broken.is_empty() {
        Gate::Blocked(broken.join(" "))
    } else if !view.histories.is_empty() {
        Gate::Blocked(comparison_block.unwrap_or_default())
    } else if !unreadable.is_empty() {
        Gate::Blocked(unreadable.join(" "))
    } else if view.pending_operations > 0 {
        // A pending operation also makes a behind drive unrepairable (Damaged), so the
        // recovery screen comes first.
        Gate::NeedsRecovery
    } else if let Some(reason) = comparison_block {
        Gate::Blocked(reason)
    } else if damaged {
        Gate::Blocked("Something on the drives cannot be verified.".to_string())
    } else if !view.repairs.is_empty() {
        Gate::NeedsRepair
    } else if let Some(text) = too_few {
        Gate::NeedsDriveReplacement(text)
    } else {
        Gate::Continue
    };
    view
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::model::Timestamp;
    use keystone_core::store::audit::GENESIS_PREV;
    use keystone_core::store::{AuditDraft, DriveSet, OperationKind};
    use std::path::Path;

    fn now() -> OffsetDateTime {
        keystone_core::build_info::build_date() + time::Duration::days(1)
    }

    fn ts(seconds: i64) -> Timestamp {
        Timestamp::utc(keystone_core::build_info::build_date() + time::Duration::seconds(seconds))
    }

    fn entry(seq: u64, subject: &str) -> AuditEntry {
        AuditEntry {
            seq,
            time: ts(60),
            operation: None,
            action: AuditAction::Export,
            subject: subject.to_string(),
            serial: None,
            fingerprint: None,
            result: AuditResult::Success,
            details: None,
            prev: GENESIS_PREV,
        }
    }

    fn base() -> StartupData {
        StartupData {
            audit: vec![
                DriveAudit {
                    drive: "primary drive aaaa".into(),
                    result: Ok(1),
                },
                DriveAudit {
                    drive: "backup drive bbbb".into(),
                    result: Ok(1),
                },
            ],
            comparison: Some(Ok(DriveComparison::InSync)),
            recovery: Some(Ok(RecoveryReport::default())),
            record: Some(Ok(IssuanceRecord::empty())),
            ..StartupData::default()
        }
    }

    struct Drives {
        _dir: tempfile::TempDir,
        roots: Vec<std::path::PathBuf>,
        export: std::path::PathBuf,
    }

    fn drives(count: usize) -> Drives {
        let dir = tempfile::tempdir().expect("tempdir");
        let roots: Vec<_> = (0..count)
            .map(|i| {
                let root = dir.path().join(format!("drive-{i}"));
                std::fs::create_dir(&root).expect("mkdir");
                root
            })
            .collect();
        let export = dir.path().join("export");
        std::fs::create_dir(&export).expect("mkdir");
        let backups: Vec<&Path> = roots[1..].iter().map(|p| p.as_path()).collect();
        DriveSet::create(&roots[0], &backups, ts(0)).expect("create CA");
        Drives {
            _dir: dir,
            roots,
            export,
        }
    }

    fn selection(d: &Drives, indexes: &[usize]) -> DriveSelection {
        DriveSelection {
            primary: (indexes[0] == 0).then(|| d.roots[0].clone()),
            backups: indexes
                .iter()
                .filter(|i| **i != 0)
                .map(|i| d.roots[*i].clone())
                .collect(),
            export: d.export.clone(),
        }
    }

    #[test]
    fn consistent_drives_allow_continuing() {
        // Covers: FR-19 AC1, SEC-09
        let view = evaluate(&base(), false, now());
        assert_eq!(view.gate, Gate::Continue);
        assert!(
            view.sections
                .iter()
                .any(|s| s.title == "Network" && s.lines[0].status == Status::Info)
        );
        let production = evaluate(&base(), true, now());
        assert_eq!(production.sections[0].lines[0].status, Status::Ok);
    }

    #[test]
    fn fr14_ac3_broken_chain_blocks_and_names_the_first_bad_entry() {
        // Covers: FR-14 AC3, SEC-09
        let mut data = base();
        data.audit[1].result = Err(AuditFailure {
            first_bad_entry: Some(3),
            message: "entry 3 is the first bad entry: the entry is not written in canonical form (it was edited)".into(),
        });
        data.recovery = None;
        let view = evaluate(&data, false, now());
        let Gate::Blocked(reason) = &view.gate else {
            panic!("expected blocked, got {:?}", view.gate);
        };
        assert!(
            reason.contains("entry 3 is the first bad entry"),
            "{reason}"
        );
        assert!(reason.contains("backup drive bbbb"));
    }

    #[test]
    fn fr12_ac3_divergent_histories_are_shown_side_by_side_and_block_signing() {
        // Covers: FR-12 AC3, SEC-22
        let mut data = base();
        data.comparison = Some(Ok(DriveComparison::Diverged {
            common: 4,
            histories: vec![
                DriveHistory {
                    drives: vec!["primary drive aaaa".into()],
                    entries: vec![entry(5, "CN=KEYSTONE TEST One")],
                },
                DriveHistory {
                    drives: vec!["backup drive bbbb".into()],
                    entries: vec![entry(5, "CN=KEYSTONE TEST Two")],
                },
            ],
        }));
        let view = evaluate(&data, false, now());
        assert!(matches!(view.gate, Gate::Blocked(_)));
        assert_eq!(view.histories.len(), 2);
        assert_eq!(view.common_entries, 4);
        assert!(view.histories[0].entries[0].contains("KEYSTONE TEST One"));
        assert!(view.histories[1].entries[0].contains("KEYSTONE TEST Two"));
        assert!(view.repair_plans.is_empty(), "never repaired automatically");
    }

    #[test]
    fn fr22_ac4_interrupted_operation_opens_recovery_first() {
        // Covers: FR-22 AC4
        let d = drives(2);
        let set = DriveSet::open(&[d.roots[0].as_path(), d.roots[1].as_path()]).expect("open");
        let _op = set
            .begin_operation(
                OperationKind::CreateMaster,
                "CN=KEYSTONE TEST Root",
                &[],
                ts(10),
            )
            .expect("begin");
        let data = gather(&selection(&d, &[0, 1]), false);
        let view = evaluate(&data, false, now());
        assert_eq!(view.gate, Gate::NeedsRecovery);
        assert_eq!(view.pending_operations, 1);
    }

    #[test]
    fn fr12_ac3_behind_drives_list_missing_operations_before_repair() {
        // Covers: FR-12 AC3
        let d = drives(3);
        let partial =
            DriveSet::open(&[d.roots[0].as_path(), d.roots[1].as_path()]).expect("open two");
        partial
            .append_audit(
                &[AuditDraft::new(
                    AuditAction::Export,
                    "CN=KEYSTONE TEST export",
                    AuditResult::Success,
                )],
                ts(20),
            )
            .expect("append");
        let data = gather(&selection(&d, &[0, 1, 2]), false);
        assert_eq!(data.audit_entries.len(), 1, "longest verified log");
        let view = evaluate(&data, false, now());
        assert_eq!(view.gate, Gate::NeedsRepair);
        assert_eq!(view.repairs.len(), 1);
        assert!(view.repairs[0].heading.contains("is behind"));
        assert!(view.repairs[0].missing[0].contains("KEYSTONE TEST export"));
        assert_eq!(view.repair_plans.len(), 1);
    }

    #[test]
    fn fr14_ac3_gather_names_the_first_bad_entry_of_a_real_log() {
        // Covers: FR-14 AC3
        let d = drives(2);
        let set = DriveSet::open(&[d.roots[0].as_path(), d.roots[1].as_path()]).expect("open");
        set.append_audit(
            &[
                AuditDraft::new(
                    AuditAction::Export,
                    "CN=KEYSTONE TEST a",
                    AuditResult::Success,
                ),
                AuditDraft::new(
                    AuditAction::Export,
                    "CN=KEYSTONE TEST b",
                    AuditResult::Success,
                ),
            ],
            ts(30),
        )
        .expect("append");
        let log = d.roots[1].join("keystone").join("audit.log");
        let text = std::fs::read_to_string(&log).expect("read");
        std::fs::write(&log, text.replacen("KEYSTONE TEST a", "KEYSTONE TEST A", 1))
            .expect("tamper");
        let data = gather(&selection(&d, &[0, 1]), false);
        let failure = data.audit[1].result.clone().expect_err("broken");
        assert_eq!(failure.first_bad_entry, Some(1));
        assert!(matches!(
            evaluate(&data, false, now()).gate,
            Gate::Blocked(_)
        ));
    }

    #[test]
    fn adr0003_one_drive_disables_signing_and_offers_drive_replacement() {
        // Covers: FR-12 AC1, SEC-11 (ADR 0003)
        let d = drives(2);
        let data = gather(&selection(&d, &[1]), false);
        assert_eq!(data.not_enough_drives, Some((0, 1)));
        let view = evaluate(&data, false, now());
        let Gate::NeedsDriveReplacement(text) = &view.gate else {
            panic!("expected drive replacement, got {:?}", view.gate);
        };
        assert!(
            text.contains("Connected: 0 primary and 1 backup drive."),
            "{text}"
        );
        assert!(
            text.contains("replace it with a new, empty drive"),
            "{text}"
        );
        let full = evaluate(&gather(&selection(&d, &[0, 1]), false), false, now());
        assert_eq!(full.gate, Gate::Continue);
    }

    #[test]
    fn unreadable_journal_blocks_and_is_named() {
        // Covers: FR-22 AC4, SEC-22 (review finding 7)
        let mut data = base();
        data.recovery = Some(Ok(RecoveryReport {
            pending: Vec::new(),
            unreadable: vec!["The journal on backup drive bbbb cannot be read.".into()],
        }));
        let view = evaluate(&data, false, now());
        let Gate::Blocked(reason) = &view.gate else {
            panic!("expected blocked, got {:?}", view.gate);
        };
        assert!(reason.contains("backup drive bbbb"), "{reason}");
        assert!(
            view.sections
                .iter()
                .any(|s| s.lines.iter().any(|l| l.status == Status::Blocked
                    && l.text.contains("until this drive is repaired or replaced")))
        );
    }

    #[test]
    fn audit_details_of_drive_replacement_and_recovery_are_shown() {
        // Covers: FR-14 AC1, SEC-11 (ADR 0003), FR-22 AC3
        use keystone_core::store::{AuditDetails, DriveId};
        let added = DriveId::random().expect("id");
        let promoted = DriveId::random().expect("id");
        let mut replaced = entry(4, "");
        replaced.action = AuditAction::DriveRepair;
        replaced.details = Some(AuditDetails {
            drive_added: Some(added),
            primary_promoted: Some(promoted),
            ..AuditDetails::default()
        });
        let text = format_entry(&replaced);
        assert!(text.contains("replace a lost drive"), "{text}");
        assert!(
            text.contains(&format!("new drive {}", added.short())),
            "{text}"
        );
        assert!(
            text.contains(&format!("drive {} promoted to primary", promoted.short())),
            "{text}"
        );
        let serial = keystone_core::model::Serial::from_bytes([7; 20]).expect("serial");
        let mut finished = entry(5, "CN=KEYSTONE TEST Main");
        finished.action = AuditAction::RecoveryFinish;
        finished.details = Some(AuditDetails {
            original_action: Some(AuditAction::SetupYubikey),
            serials: Some(vec![serial]),
            ..AuditDetails::default()
        });
        let text = format_entry(&finished);
        assert!(
            text.contains(
                "finish interrupted operation of \"set up YubiKey and main intermediate\""
            ),
            "{text}"
        );
        assert!(
            text.contains(&format!("serial {}", serial.to_hex())),
            "{text}"
        );
    }

    #[test]
    fn new_ca_needs_no_history_checks() {
        let data = StartupData {
            new_ca: true,
            ..StartupData::default()
        };
        let view = evaluate(&data, false, now());
        assert_eq!(view.gate, Gate::Continue);
        assert!(view.sections.iter().any(|s| s.title == "Drives"));
    }

    #[test]
    fn entries_are_formatted_on_one_line() {
        let text = format_entry(&entry(7, "CN=KEYSTONE TEST Root"));
        assert!(text.starts_with("#7 "), "{text}");
        assert!(
            text.contains("UTC export CN=KEYSTONE TEST Root (success)"),
            "{text}"
        );
    }
}
