//! The recovery screen (FR-22 AC4, AC5, AC7, AC8, SEC-22).
//!
//! One column per drive and one for the YubiKey, listing exactly what each holds for
//! the interrupted operation. At most two actions, each with one plain sentence saying
//! what it will do and what it will not do. Both come from the operations layer
//! (`ops::Ca::recovery_items`, read with the YubiKey connected, so an interrupted
//! YubiKey setup gets the action that fits the YubiKey's real state and a lost YubiKey
//! never blocks recovery). Nothing on this screen formats, deletes or overwrites
//! anything: the only actions are the ones `ops` offers.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use keystone_core::ops::{RecoveryAction, RecoveryItem};
use keystone_core::store::{
    DriveOperationView, FileState, OperationKind, OperationState, YubikeySetupStep,
};

use super::token::{TokenState, recovery_lines};
use super::{Line, Status};

/// Most actions the screen ever offers (FR-22 AC8).
pub const MAX_ACTIONS: usize = 2;

/// One column of the recovery screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    /// Column title (drive label, or "YubiKey").
    pub title: String,
    /// What it holds.
    pub lines: Vec<Line>,
}

/// One offered action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionView {
    /// Button label.
    pub label: String,
    /// One plain sentence: what it will and will not do.
    pub sentence: String,
    /// The action.
    pub action: RecoveryAction,
}

/// One interrupted operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationView {
    /// Heading.
    pub heading: String,
    /// One column per drive, then the YubiKey column.
    pub columns: Vec<Column>,
    /// At most [`MAX_ACTIONS`] actions.
    pub actions: Vec<ActionView>,
    /// Why nothing can be offered, when `actions` is empty.
    pub blocked: Option<String>,
}

/// The operation kind in words.
pub fn kind_name(kind: OperationKind) -> &'static str {
    match kind {
        OperationKind::CreateMaster => "create the master",
        OperationKind::SetupYubikey => "set up the YubiKey and main intermediate",
        OperationKind::CreateSubIntermediate => "create a sub-intermediate",
        OperationKind::Revoke => "revoke a certificate",
        OperationKind::RefreshCrl => "refresh a CRL",
        OperationKind::ReplaceYubikey => "replace a lost YubiKey",
    }
}

/// A YubiKey setup step in words.
pub fn step_name(step: YubikeySetupStep) -> &'static str {
    match step {
        YubikeySetupStep::PinChanged => "PIN changed",
        YubikeySetupStep::PukChanged => "PUK changed",
        YubikeySetupStep::ManagementKeySet => "management key set",
        YubikeySetupStep::KeyGenerated => "key generated on the YubiKey",
        YubikeySetupStep::CertificateWritten => "certificate written to the YubiKey",
    }
}

fn state_name(state: Option<OperationState>) -> &'static str {
    match state {
        None => "no journal for this operation",
        Some(OperationState::Pending) => "interrupted (pending)",
        Some(OperationState::Completed) => "completed",
        Some(OperationState::Cancelled) => "cancelled",
        Some(OperationState::Abandoned) => "abandoned",
    }
}

fn file_state_name(state: FileState) -> &'static str {
    match state {
        FileState::Missing => "missing",
        FileState::Verified => "present and verified",
        FileState::Differs => "present but different",
    }
}

fn drive_column(view: &DriveOperationView) -> Column {
    let mut lines = vec![Line::new(
        if view.state.is_some() {
            Status::Info
        } else {
            Status::Warning
        },
        format!("State: {}.", state_name(view.state)),
    )];
    if !view.journal_entries.is_empty() {
        lines.push(Line::new(
            Status::Info,
            format!("Journal entries: {}.", view.journal_entries.join(", ")),
        ));
    }
    if view.signed_certificates.is_empty() && view.signed_crls.is_empty() {
        lines.push(Line::new(Status::Info, "Nothing signed is recorded."));
    }
    for serial in &view.signed_certificates {
        lines.push(Line::new(
            Status::Info,
            format!("Signed certificate, serial {serial}."),
        ));
    }
    for number in &view.signed_crls {
        lines.push(Line::new(
            Status::Info,
            format!("Signed CRL number {number}."),
        ));
    }
    for (step, device) in &view.yubikey_steps {
        lines.push(Line::new(
            Status::Info,
            format!("YubiKey {device}: {}.", step_name(*step)),
        ));
    }
    for output in &view.outputs {
        let status = if output.available() {
            Status::Ok
        } else {
            Status::Warning
        };
        lines.push(Line::new(
            status,
            format!(
                "{}: staged copy {}, final copy {}.",
                output.path,
                file_state_name(output.staged),
                file_state_name(output.placed)
            ),
        ));
    }
    for (name, _) in &view.unlisted_staged_files {
        lines.push(Line::new(
            Status::Info,
            format!("Staged file not listed in the journal: {name}."),
        ));
    }
    lines.push(Line::new(
        Status::Info,
        format!("Audit entries for this operation: {}.", view.audit_entries),
    ));
    lines.push(if view.holds_verified_output {
        Line::new(Status::Ok, "Holds the complete, verified output.")
    } else {
        Line::new(Status::Info, "Does not hold a complete, verified output.")
    });
    Column {
        title: view.drive.clone(),
        lines,
    }
}

fn yubikey_column(item: &RecoveryItem, token: &TokenState) -> Column {
    let mut lines = recovery_lines(token);
    if let Some(column) = &item.yubikey
        && item.kind == OperationKind::SetupYubikey
    {
        lines.push(if column.is_this_operations_yubikey {
            Line::new(
                Status::Info,
                "This is the YubiKey this setup used (or the setup recorded no YubiKey step yet).",
            )
        } else {
            Line::new(Status::Warning, "This is not the YubiKey this setup used.")
        });
        if column.key_without_certificate {
            lines.push(Line::new(
                Status::Info,
                "The signing slot holds a key without a certificate.",
            ));
        }
    }
    let steps: BTreeSet<YubikeySetupStep> = item
        .drives
        .iter()
        .flat_map(|drive| drive.yubikey_steps.iter().map(|(step, _)| *step))
        .collect();
    if steps.is_empty() {
        lines.push(Line::new(
            Status::Info,
            "No YubiKey step is recorded for this operation.",
        ));
    } else {
        let done: Vec<&str> = steps.iter().map(|s| step_name(*s)).collect();
        lines.push(Line::new(
            Status::Info,
            format!("Recorded YubiKey steps: {}.", done.join(", ")),
        ));
    }
    Column {
        title: "YubiKey".to_string(),
        lines,
    }
}

/// The button label of an action. Never a word like format, delete or wipe.
pub fn action_label(action: &RecoveryAction) -> String {
    match action {
        RecoveryAction::FinishFrom { drive, .. } => format!("Finish from {drive}"),
        RecoveryAction::Abandon => "Mark as abandoned".to_string(),
        RecoveryAction::RebuildFromJournal { .. } => {
            "Finish from what the journal recorded".to_string()
        }
        RecoveryAction::ResumeYubikeySetup { .. } => "Continue the YubiKey setup".to_string(),
        RecoveryAction::CompleteSetupWithExistingKey => {
            "Complete the setup with the key in the YubiKey".to_string()
        }
        RecoveryAction::FinishWithoutYubikey => "Finish without the lost YubiKey".to_string(),
    }
}

/// Builds the screen for one interrupted operation.
pub fn operation_view(item: &RecoveryItem, token: &TokenState) -> OperationView {
    let mut columns: Vec<Column> = item.drives.iter().map(drive_column).collect();
    columns.push(yubikey_column(item, token));
    let actions: Vec<ActionView> = item
        .actions
        .iter()
        .take(MAX_ACTIONS)
        .map(|choice| ActionView {
            label: action_label(&choice.action),
            sentence: choice.description.clone(),
            action: choice.action.clone(),
        })
        .collect();
    let blocked = if actions.is_empty() {
        Some(item.blocked_reason.clone().unwrap_or_else(|| {
            "No safe action can be offered. Keep every drive and the YubiKey as they are."
                .to_string()
        }))
    } else {
        None
    };
    let serials: Vec<String> = item
        .planned_serials
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut heading = format!(
        "Interrupted: {} to {} ({}).",
        item.operation,
        kind_name(item.kind),
        item.subject
    );
    if !serials.is_empty() {
        heading.push_str(&format!(
            " Reserved serial number{}: {}; it stays reserved.",
            if serials.len() == 1 { "" } else { "s" },
            serials.join(", ")
        ));
    }
    OperationView {
        heading,
        columns,
        actions,
        blocked,
    }
}

/// What a resumed YubiKey setup asks for again (FR-22 AC7): nothing is stored, so a PIN
/// or PUK that was already set is asked again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeNeeds {
    /// The PIN was already changed: ask for the current PIN.
    pub current_pin: bool,
    /// The PUK step is still to do: ask for a new PUK.
    pub new_puk: bool,
    /// Nothing was signed yet: ask for the master passphrase and the main
    /// intermediate's name and validity again.
    pub unsigned: bool,
}

/// What the resume form asks for, from what the drives recorded.
pub fn resume_needs(item: &RecoveryItem, action: &RecoveryAction) -> ResumeNeeds {
    let next = match action {
        RecoveryAction::ResumeYubikeySetup { next_step } => *next_step,
        _ => None,
    };
    let steps: BTreeSet<YubikeySetupStep> = item
        .drives
        .iter()
        .flat_map(|drive| drive.yubikey_steps.iter().map(|(step, _)| *step))
        .collect();
    let pin_changed = steps.contains(&YubikeySetupStep::PinChanged)
        || item
            .yubikey
            .as_ref()
            .is_some_and(|column| !column.credentials.pin_is_default);
    let puk_pending = matches!(
        next,
        Some(YubikeySetupStep::PinChanged | YubikeySetupStep::PukChanged)
    ) || item
        .yubikey
        .as_ref()
        .is_some_and(|column| column.credentials.puk_is_default);
    let signed = item
        .drives
        .iter()
        .any(|drive| !drive.signed_certificates.is_empty());
    ResumeNeeds {
        current_pin: pin_changed,
        new_puk: puk_pending,
        unsigned: !signed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::model::{Sha256Digest, Timestamp};
    use keystone_core::ops::{Ca, RecoveryChoice};
    use keystone_core::store::{DriveSet, OperationId, OutputDir, OutputPath, OutputState};
    use std::path::Path;

    fn ts(seconds: i64) -> Timestamp {
        Timestamp::utc(keystone_core::build_info::build_date() + time::Duration::seconds(seconds))
    }

    fn drive(index: usize, holds: bool) -> DriveOperationView {
        let path = OutputPath::new(OutputDir::Certs, "x.crt").expect("path");
        DriveOperationView {
            drive_index: index,
            drive: format!("drive {index}"),
            journal_entries: vec!["001-pending.json".into(), "002-staged.json".into()],
            state: Some(OperationState::Pending),
            signed_certificates: Vec::new(),
            signed_crls: vec![1],
            yubikey_steps: vec![(YubikeySetupStep::PinChanged, 7)],
            outputs: vec![OutputState {
                path,
                sha256: Sha256Digest([1; 32]),
                staged: if holds {
                    FileState::Verified
                } else {
                    FileState::Missing
                },
                placed: FileState::Missing,
            }],
            unlisted_staged_files: Vec::new(),
            audit_entries: 0,
            holds_verified_output: holds,
        }
    }

    fn item(actions: Vec<RecoveryAction>) -> RecoveryItem {
        let operation = OperationId(3);
        RecoveryItem {
            operation,
            kind: OperationKind::SetupYubikey,
            subject: "CN=KEYSTONE TEST Main".into(),
            planned_serials: Vec::new(),
            drives: vec![drive(0, true), drive(1, false)],
            yubikey: None,
            actions: actions
                .into_iter()
                .map(|action| RecoveryChoice {
                    description: format!(
                        "Do {} for {operation}; nothing is deleted or overwritten.",
                        action_label(&action)
                    ),
                    action,
                })
                .collect(),
            blocked_reason: None,
        }
    }

    #[test]
    fn fr22_ac8_one_column_per_drive_and_one_for_the_yubikey() {
        // Covers: FR-22 AC8, FR-22 AC4
        let view = operation_view(
            &item(vec![RecoveryAction::FinishFrom {
                drive_index: 0,
                drive: "drive 0".into(),
            }]),
            &TokenState::DriverMissing,
        );
        let titles: Vec<&str> = view.columns.iter().map(|c| c.title.as_str()).collect();
        assert_eq!(titles, ["drive 0", "drive 1", "YubiKey"]);
        assert!(view.columns[0].lines.iter().any(|l| {
            l.text
                .contains("certs/x.crt: staged copy present and verified")
        }));
        assert!(
            view.columns[1]
                .lines
                .iter()
                .any(|l| l.text.contains("staged copy missing"))
        );
        assert!(
            view.columns[2]
                .lines
                .iter()
                .any(|l| l.text.contains("Recorded YubiKey steps: PIN changed"))
        );
        assert!(view.heading.contains("operation 3"));
    }

    #[test]
    fn fr22_ac8_at_most_two_actions_each_with_one_sentence_and_no_destruction() {
        // Covers: FR-22 AC8
        let many = vec![
            RecoveryAction::FinishFrom {
                drive_index: 0,
                drive: "drive 0".into(),
            },
            RecoveryAction::Abandon,
            RecoveryAction::ResumeYubikeySetup { next_step: None },
            RecoveryAction::FinishWithoutYubikey,
        ];
        let view = operation_view(&item(many), &TokenState::DriverMissing);
        assert_eq!(view.actions.len(), MAX_ACTIONS);
        for action in &view.actions {
            let sentence = &action.sentence;
            assert_eq!(
                sentence.matches(". ").count(),
                0,
                "one sentence: {sentence}"
            );
            assert!(sentence.ends_with('.'));
            let label = action.label.to_lowercase();
            for verb in ["format", "delete", "overwrite", "wipe", "erase"] {
                assert!(!label.contains(verb), "{label}");
            }
            assert!(
                sentence.contains("nothing is deleted or overwritten")
                    || sentence.contains("nothing is wiped"),
                "{sentence}"
            );
        }
        // Every action Keystone can offer has a label without a destructive verb.
        for action in [
            RecoveryAction::RebuildFromJournal {
                needs_master_passphrase: true,
            },
            RecoveryAction::CompleteSetupWithExistingKey,
            RecoveryAction::FinishWithoutYubikey,
        ] {
            let label = action_label(&action).to_lowercase();
            for verb in ["format", "delete", "overwrite", "wipe", "erase"] {
                assert!(!label.contains(verb), "{label}");
            }
        }
    }

    #[test]
    fn no_safe_action_explains_why() {
        let mut op = item(Vec::new());
        op.blocked_reason = Some("the drives hold different journals".into());
        let view = operation_view(&op, &TokenState::Unavailable("no YubiKey".into()));
        assert!(view.actions.is_empty());
        assert_eq!(
            view.blocked.as_deref(),
            Some("the drives hold different journals")
        );
    }

    #[test]
    fn fr22_ac4_real_report_offers_abandon_for_an_unsigned_operation() {
        // Covers: FR-22 AC4
        let dir = tempfile::tempdir().expect("tempdir");
        let roots: Vec<_> = ["a", "b"]
            .iter()
            .map(|n| {
                let p = dir.path().join(n);
                std::fs::create_dir(&p).expect("mkdir");
                p
            })
            .collect();
        let set = DriveSet::create(&roots[0], &[roots[1].as_path()], ts(0)).expect("create");
        drop(set);
        let set = DriveSet::open(&[roots[0].as_path(), Path::new(&roots[1])]).expect("open");
        let _op = set
            .begin_operation(
                OperationKind::CreateMaster,
                "CN=KEYSTONE TEST Root",
                &[],
                ts(5),
            )
            .expect("begin");
        let ca = Ca::open(&[roots[0].as_path(), roots[1].as_path()]).expect("open");
        let items = ca.recovery_items(None).expect("items");
        let view = operation_view(&items[0], &TokenState::DriverMissing);
        assert_eq!(view.columns.len(), 3);
        assert_eq!(view.actions.len(), 1);
        assert_eq!(view.actions[0].label, "Mark as abandoned");
        assert!(view.actions[0].sentence.contains("serial number reserved"));
    }

    #[test]
    fn fr22_ac7_resume_asks_again_only_for_what_is_still_needed() {
        // Covers: FR-22 AC7
        let resume = RecoveryAction::ResumeYubikeySetup {
            next_step: Some(YubikeySetupStep::PukChanged),
        };
        let needs = resume_needs(&item(vec![resume.clone()]), &resume);
        assert!(needs.current_pin, "the PIN was already changed");
        assert!(needs.new_puk);
        assert!(needs.unsigned);
        let mut signed = item(vec![resume.clone()]);
        signed.drives[0]
            .signed_certificates
            .push(keystone_core::model::Serial::from_bytes([3; 20]).expect("serial"));
        let later = RecoveryAction::ResumeYubikeySetup {
            next_step: Some(YubikeySetupStep::CertificateWritten),
        };
        let needs = resume_needs(&signed, &later);
        assert!(!needs.new_puk && !needs.unsigned);
    }
}
