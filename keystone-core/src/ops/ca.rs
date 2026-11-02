//! Opening an existing CA, the startup checks, the signing gate, drive repair, the clock
//! and export (FR-12 AC3, FR-13 AC3, FR-14 AC3, FR-17, FR-19, FR-22 AC2, AC4).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use crate::clock::{
    self, ClockAssessment, ClockCorrection, ClockProblem, ClockWarning, ConfirmedTime,
};
use crate::crl::{CrlFreshness, crl_freshness};
use crate::model::{Fingerprint, Serial, Sha256Digest, Timestamp};
use crate::store::{
    AuditEntry, CaDrive, DriveComparison, DriveHistory, DriveRole, DriveSet, ExportDrive,
    OperationId, OperationKind, OutputDir, OutputPath, ParseError, RepairPlan, StoreError,
};

use super::recovery::RecoveryItem;
use super::state::{CaState, StoredCert};
use super::{OpsError, Step};

/// Something that blocks every signing action until it is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocker {
    /// FR-12 AC1: writing needs the primary drive and at least one backup.
    NotEnoughDrives {
        /// Primary drives connected.
        primaries: usize,
        /// Backup drives connected.
        backups: usize,
    },
    /// FR-12 AC3: some drives are behind; the operator confirms the repair plans first.
    DrivesBehind {
        /// One plan per behind drive.
        plans: Vec<RepairPlan>,
    },
    /// FR-12 AC3: the histories diverge; both are shown side by side and nothing is
    /// chosen automatically.
    DrivesDiverged {
        /// Entries shared by every drive.
        common: usize,
        /// Every history after that point.
        histories: Vec<DriveHistory>,
    },
    /// Something on the drives cannot be verified (FR-14, FR-22 AC2).
    DrivesDamaged {
        /// One sentence per problem.
        problems: Vec<String>,
    },
    /// FR-14 AC3: a drive's audit-log chain is broken at `entry`.
    AuditLogBroken {
        /// The drive.
        drive: String,
        /// 1-based number of the first bad entry.
        entry: u64,
        /// What is wrong with it.
        problem: String,
    },
    /// FR-22 AC4: an interrupted operation must be finished or abandoned first.
    PendingOperation {
        /// The operation.
        operation: OperationId,
        /// Its kind.
        kind: OperationKind,
        /// Its subject.
        subject: String,
    },
    /// FR-17 AC2: the clock is earlier than the newest audit entry or the build date.
    ClockBlocked(Vec<ClockProblem>),
    /// The confirmed time is earlier than the newest audit entry (it was confirmed
    /// before a later entry was written); confirm the time again.
    ClockConfirmationStale {
        /// The confirmed time.
        confirmed: Timestamp,
        /// The newest audit-log time.
        baseline: Timestamp,
    },
    /// The CA state on the drives could not be read.
    StateUnreadable(String),
}

impl Blocker {
    /// One plain sentence for the operator.
    pub fn message(&self) -> String {
        match self {
            Blocker::NotEnoughDrives { primaries, backups } => format!(
                "connect the primary drive and at least one backup drive (connected: {primaries} primary, {backups} backup)"
            ),
            Blocker::DrivesBehind { plans } => format!(
                "{} drive(s) are behind; review and confirm the copy of the missing operations",
                plans.len()
            ),
            Blocker::DrivesDiverged { common, histories } => format!(
                "the drives hold {} different histories after entry {common}; compare them side by side, Keystone never chooses one",
                histories.len()
            ),
            Blocker::DrivesDamaged { problems } => problems.join("; "),
            Blocker::AuditLogBroken {
                drive,
                entry,
                problem,
            } => format!("the audit log on {drive} is broken at entry {entry}: {problem}"),
            Blocker::PendingOperation {
                operation, subject, ..
            } => {
                format!("{operation} ({subject}) was interrupted; finish it on the recovery screen")
            }
            Blocker::ClockBlocked(problems) => problems
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; "),
            Blocker::ClockConfirmationStale {
                confirmed,
                baseline,
            } => format!(
                "the confirmed time {} is earlier than the newest audit entry ({}); confirm the date and time again",
                confirmed.get(),
                baseline.get()
            ),
            Blocker::StateUnreadable(reason) => reason.clone(),
        }
    }
}

/// A CRL that needs refreshing soon (FR-13 AC3). The GUI's warning opens
/// [`Ca::plan_refresh_crl`] for `issuer_serial`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlWarning {
    /// The issuing certificate.
    pub issuer_serial: Serial,
    /// Its subject, for display.
    pub issuer: String,
    /// The current CRL's number.
    pub crl_number: u64,
    /// The current CRL's nextUpdate.
    pub next_update: OffsetDateTime,
    /// How close it is.
    pub freshness: CrlFreshness,
}

/// A warning shown at startup; it does not block signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupWarning {
    /// FR-13 AC3.
    CrlRefresh(CrlWarning),
    /// FR-17 AC2: the time needs an explicit confirmation.
    Clock(ClockWarning),
    /// FR-17 AC3: certificates signed with a future date; revoke and re-issue them.
    FutureDatedCertificates(Vec<Serial>),
    /// FR-15: sub-intermediates cut off by a revoked main intermediate, to re-issue.
    ReissueNeeded(Vec<Serial>),
    /// The CA has no master yet (only cancelled or abandoned attempts).
    NoMaster,
}

/// The audit-log check of one drive (FR-14 AC3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditLogStatus {
    /// The chain verifies.
    Verified {
        /// The drive.
        drive: String,
        /// Number of entries.
        entries: usize,
    },
    /// The chain is broken.
    Broken {
        /// The drive.
        drive: String,
        /// 1-based number of the first bad entry (0 when the file itself is unusable).
        first_bad_entry: u64,
        /// What is wrong.
        problem: String,
    },
}

/// One certificate as the startup screen lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertSummary {
    /// Serial.
    pub serial: Serial,
    /// Subject.
    pub subject: String,
    /// End of validity.
    pub not_after: OffsetDateTime,
    /// SHA-256 fingerprint (FR-20).
    pub fingerprint: Fingerprint,
}

impl CertSummary {
    fn of(cert: &StoredCert) -> Self {
        CertSummary {
            serial: cert.serial(),
            subject: cert.record.subject.display(),
            not_after: cert.info.not_after,
            fingerprint: cert.record.fingerprint,
        }
    }
}

/// What the CA holds (FR-19 AC1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HierarchySummary {
    /// The master.
    pub master: Option<CertSummary>,
    /// The main intermediate that signs new sub-intermediates.
    pub active_main: Option<CertSummary>,
    /// Number of sub-intermediates that are valid at the assessed time.
    pub valid_sub_intermediates: usize,
    /// Number of certificates in the issuance record.
    pub recorded_certificates: usize,
}

/// Everything the start screen needs (PRD section 6 preamble, FR-19).
#[derive(Debug, Clone)]
pub struct StartupReport {
    /// Drive labels, primary first.
    pub drives: Vec<String>,
    /// Audit-log check per drive (FR-14 AC3).
    pub audit: Vec<AuditLogStatus>,
    /// Drive comparison (FR-12 AC3).
    pub comparison: DriveComparison,
    /// Interrupted operations (FR-22 AC4); call [`Ca::recovery_items`] with the YubiKey
    /// connected to add its column.
    pub recovery: Vec<RecoveryItem>,
    /// Clock sanity checks for the time shown (FR-17 AC2); confirm with
    /// `clock::confirm` to get the [`ConfirmedTime`] every signing needs.
    pub clock: ClockAssessment,
    /// What the CA holds.
    pub hierarchy: HierarchySummary,
    /// Everything that blocks signing.
    pub blockers: Vec<Blocker>,
    /// Warnings.
    pub warnings: Vec<StartupWarning>,
}

impl StartupReport {
    /// True when no blocker exists. Signing still needs a confirmed time (FR-17 AC1).
    pub fn signing_allowed(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// A file written to the export drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedFile {
    /// File name inside `keystone-export/`.
    pub name: String,
    /// Full path, for messages to the operator.
    pub path: PathBuf,
    /// SHA-256 of the content.
    pub sha256: Sha256Digest,
}

/// The export part of an operation's outcome (FR-09, FR-13 AC6, FR-22 AC2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportStatus {
    /// No export drive was given; use [`Ca::export_operation`].
    NotRequested,
    /// Written and verified.
    Written(Vec<ExportedFile>),
    /// Export failed; the operation itself is complete. Retry with
    /// [`Ca::export_operation`].
    Failed(String),
}

/// FR-17 for a new CA (Flow A): the drives hold no audit log yet, so the time is checked
/// against the build date only.
pub fn assess_clock_for_new_ca(now: OffsetDateTime) -> ClockAssessment {
    clock::assess(now, None, crate::build_info::build_date())
}

/// An opened CA: its connected drives (FR-19).
#[derive(Debug)]
pub struct Ca {
    drives: DriveSet,
}

impl Ca {
    /// Opens the CA on the drives mounted at `roots` (FR-19 AC1). All must belong to the
    /// same CA. Nothing is written.
    pub fn open(roots: &[&Path]) -> Result<Ca, OpsError> {
        Ok(Ca {
            drives: DriveSet::open(roots)?,
        })
    }

    pub(crate) fn from_set(drives: DriveSet) -> Ca {
        Ca { drives }
    }

    /// The connected drives.
    pub fn drive_set(&self) -> &DriveSet {
        &self.drives
    }

    /// The drive whose audit log is longest and verifies (for display while drives are
    /// behind); the primary when they agree.
    fn most_complete_drive(&self) -> &CaDrive {
        self.drives
            .drives()
            .iter()
            .enumerate()
            .filter_map(|(index, drive)| drive.audit_log().ok().map(|log| (index, log.len())))
            .max_by_key(|(index, len)| (*len, std::cmp::Reverse(*index)))
            .map_or(&self.drives.drives()[0], |(index, _)| {
                &self.drives.drives()[index]
            })
    }

    /// The CA state (certificates, CRLs, issuance record), from the most complete drive.
    pub fn state(&self) -> Result<CaState, OpsError> {
        CaState::load(self.most_complete_drive())
    }

    /// The newest audit time any drive holds (respecting clock corrections, FR-17 AC3).
    fn clock_baseline(&self) -> Option<Timestamp> {
        self.drives
            .drives()
            .iter()
            .filter_map(|drive| drive.audit_log().ok())
            .filter_map(|log| clock::baseline(log.entries()))
            .max()
    }

    /// FR-17 AC2: sanity checks for `now` (the system time, or the time the operator
    /// entered) against the newest audit entry and the build date.
    pub fn assess_clock(&self, now: OffsetDateTime) -> ClockAssessment {
        clock::assess(now, self.clock_baseline(), crate::build_info::build_date())
    }

    /// FR-17 AC3: Correct clock baseline. Appends an audited clock-correction entry on
    /// every drive; existing entries never change.
    pub fn correct_clock_baseline(
        &self,
        confirmed: OffsetDateTime,
    ) -> Result<AuditEntry, OpsError> {
        self.drives.ensure_writable()?;
        let log = self.drives.audit_log()?;
        let correction =
            ClockCorrection::plan(log.entries(), confirmed, crate::build_info::build_date())?;
        Ok(correction.record(&self.drives)?)
    }

    /// FR-12 AC3: copies the missing operations to the behind drives after the operator
    /// confirmed `plans` (from [`Blocker::DrivesBehind`]).
    pub fn repair_drives(&self, plans: &[RepairPlan], time: ConfirmedTime) -> Result<(), OpsError> {
        Ok(self.drives.repair(plans, time.get())?)
    }

    /// The start checks (PRD section 6, FR-19 AC1): drives, audit logs, drive comparison,
    /// interrupted operations, the clock at `now`, CRL warnings and what the CA holds.
    pub fn startup_report(&self, now: OffsetDateTime) -> Result<StartupReport, OpsError> {
        let mut blockers = Vec::new();
        let mut warnings = Vec::new();
        match self.drives.ensure_writable() {
            Ok(()) => {}
            Err(StoreError::NotEnoughDrives { primaries, backups }) => {
                blockers.push(Blocker::NotEnoughDrives { primaries, backups });
            }
            Err(error) => return Err(error.into()),
        }
        let mut audit = Vec::new();
        for drive in self.drives.drives() {
            match drive.audit_log() {
                Ok(log) => audit.push(AuditLogStatus::Verified {
                    drive: drive.label(),
                    entries: log.len(),
                }),
                Err(StoreError::Parse { source, .. }) => {
                    let (entry, problem) = match source {
                        ParseError::Audit { entry, problem } => (entry, problem.to_string()),
                        other => (0, other.to_string()),
                    };
                    blockers.push(Blocker::AuditLogBroken {
                        drive: drive.label(),
                        entry,
                        problem: problem.clone(),
                    });
                    audit.push(AuditLogStatus::Broken {
                        drive: drive.label(),
                        first_bad_entry: entry,
                        problem,
                    });
                }
                Err(error) => return Err(error.into()),
            }
        }
        let comparison = self.drives.compare()?;
        match &comparison {
            DriveComparison::InSync => {}
            DriveComparison::Behind { plans } => blockers.push(Blocker::DrivesBehind {
                plans: plans.clone(),
            }),
            DriveComparison::Diverged { common, histories } => {
                blockers.push(Blocker::DrivesDiverged {
                    common: *common,
                    histories: histories.clone(),
                });
            }
            DriveComparison::Damaged { problems } => blockers.push(Blocker::DrivesDamaged {
                problems: problems.clone(),
            }),
        }
        let recovery = match self.recovery_items(None) {
            Ok(items) => items,
            Err(OpsError::Store(StoreError::Parse { path, source })) => {
                blockers.push(Blocker::StateUnreadable(format!(
                    "{}: {source}",
                    path.display()
                )));
                Vec::new()
            }
            Err(error) => return Err(error),
        };
        for item in &recovery {
            blockers.push(Blocker::PendingOperation {
                operation: item.operation,
                kind: item.kind,
                subject: item.subject.clone(),
            });
        }
        let clock = self.assess_clock(now);
        if clock.is_blocked() {
            blockers.push(Blocker::ClockBlocked(clock.blocked.clone()));
        }
        warnings.extend(clock.warnings.iter().copied().map(StartupWarning::Clock));
        let mut hierarchy = HierarchySummary::default();
        match self.state() {
            Ok(state) => {
                hierarchy = HierarchySummary {
                    master: state.master().map(CertSummary::of),
                    active_main: state.active_main(now).map(CertSummary::of),
                    valid_sub_intermediates: state
                        .sub_intermediates()
                        .iter()
                        .filter(|sub| sub.is_usable(now))
                        .count(),
                    recorded_certificates: state.record().certificates().len(),
                };
                if state.master().is_none() {
                    warnings.push(StartupWarning::NoMaster);
                }
                warnings.extend(
                    crl_warnings(&state, now)
                        .into_iter()
                        .map(StartupWarning::CrlRefresh),
                );
                let future: Vec<Serial> =
                    clock::future_dated_certificates(state.record(), Timestamp::utc(now))
                        .iter()
                        .map(|cert| cert.certificate.serial)
                        .collect();
                if !future.is_empty() {
                    warnings.push(StartupWarning::FutureDatedCertificates(future));
                }
                let reissue: Vec<Serial> = state
                    .reissue_candidates(now)
                    .iter()
                    .map(|cert| cert.serial())
                    .collect();
                if !reissue.is_empty() {
                    warnings.push(StartupWarning::ReissueNeeded(reissue));
                }
            }
            Err(error) => blockers.push(Blocker::StateUnreadable(error.to_string())),
        }
        Ok(StartupReport {
            drives: self.drives.drives().iter().map(CaDrive::label).collect(),
            audit,
            comparison,
            recovery,
            clock,
            hierarchy,
            blockers,
            warnings,
        })
    }

    /// The signing gate: drives writable and identical, no interrupted operation, the
    /// confirmed time not earlier than the newest audit entry. Returns the state.
    pub(crate) fn ready_for_signing(&self, time: ConfirmedTime) -> Result<CaState, OpsError> {
        let mut blockers = Vec::new();
        if let Err(StoreError::NotEnoughDrives { primaries, backups }) =
            self.drives.ensure_writable()
        {
            blockers.push(Blocker::NotEnoughDrives { primaries, backups });
        }
        match self.drives.compare()? {
            DriveComparison::InSync => {}
            DriveComparison::Behind { plans } => blockers.push(Blocker::DrivesBehind { plans }),
            DriveComparison::Diverged { common, histories } => {
                blockers.push(Blocker::DrivesDiverged { common, histories });
            }
            DriveComparison::Damaged { problems } => {
                blockers.push(Blocker::DrivesDamaged { problems });
            }
        }
        for pending in self.drives.recovery_report()?.pending {
            blockers.push(Blocker::PendingOperation {
                operation: pending.operation,
                kind: pending.kind,
                subject: pending.subject,
            });
        }
        if blockers.is_empty() {
            let log = self.drives.audit_log()?;
            if let Some(baseline) = clock::baseline(log.entries())
                && time.get() < baseline
            {
                blockers.push(Blocker::ClockConfirmationStale {
                    confirmed: time.get(),
                    baseline,
                });
            }
        }
        if !blockers.is_empty() {
            return Err(OpsError::Blocked(blockers));
        }
        CaState::load(&self.drives.drives()[0])
    }

    /// Writes the exportable outputs of a completed operation to the export drive at
    /// `export_root` (FR-09 AC1, FR-13 AC6), after checking that the completed entry
    /// and every output verify on at least two drives (FR-22 AC2). Files already on the
    /// export drive with the same content are kept; a different file with the same name
    /// is never overwritten. Appends an `export` audit entry.
    pub fn export_operation(
        &self,
        operation: OperationId,
        export_root: &Path,
        time: ConfirmedTime,
    ) -> Result<Vec<ExportedFile>, OpsError> {
        let export = ExportDrive::open(export_root)?;
        let (outputs, verified) = self.drives.export_ready(operation)?;
        let journal = self.drives.drives()[verified[0]]
            .operation_journal(operation)?
            .ok_or_else(|| OpsError::NotReady(format!("{operation} has no journal")))?;
        let wanted: Vec<(OutputPath, String)> = outputs
            .iter()
            .map(|output| output.path.clone())
            .filter(|path| exported(journal.kind(), path))
            .map(|path| {
                let name = path.name().to_owned();
                (path, name)
            })
            .collect();
        // The store keeps identical files already on the export drive (a retried
        // export), never overwrites a different one, never exports the master's key, and
        // appends the `export` audit entry (review finding 15).
        Ok(self
            .drives
            .export_outputs(operation, &export, &wanted, time.get())?
            .into_iter()
            .map(|(name, sha256)| ExportedFile {
                path: export.path_of(&name),
                name,
                sha256,
            })
            .collect())
    }

    /// Export right after an operation completed; failures are reported, not raised.
    pub(crate) fn export_after(
        &self,
        operation: OperationId,
        export_root: Option<&Path>,
        time: ConfirmedTime,
        progress: &dyn super::ProgressSink,
    ) -> ExportStatus {
        let Some(root) = export_root else {
            return ExportStatus::NotRequested;
        };
        if let Err(error) = super::seam::fault(super::seam::FaultPoint::BeforeExport) {
            return ExportStatus::Failed(error.to_string());
        }
        progress.report(super::Progress::Step {
            step: Step::Exporting,
            cancel_available: false,
        });
        match self.export_operation(operation, root, time) {
            Ok(files) => ExportStatus::Written(files),
            Err(error) => ExportStatus::Failed(error.to_string()),
        }
    }

    /// Which drives are primary and backups, for display.
    pub fn drive_roles(&self) -> Vec<(String, DriveRole)> {
        self.drives
            .drives()
            .iter()
            .map(|drive| (drive.label(), drive.identity().role))
            .collect()
    }
}

/// Which outputs of an operation go to the export drive: the sub-intermediate's
/// certificate, encrypted key and chain (FR-09 AC1), and every CRL (FR-13 AC4, AC6).
fn exported(kind: OperationKind, path: &OutputPath) -> bool {
    match kind {
        OperationKind::CreateSubIntermediate => {
            matches!(path.dir(), OutputDir::Certs | OutputDir::Keys)
        }
        _ => path.dir() == OutputDir::Crls,
    }
}

/// FR-13 AC3: CRLs of usable issuers whose nextUpdate is 30 days away or past.
pub(crate) fn crl_warnings(state: &CaState, now: OffsetDateTime) -> Vec<CrlWarning> {
    let mut issuers: Vec<&StoredCert> = state.master().into_iter().collect();
    issuers.extend(
        state
            .main_intermediates()
            .into_iter()
            .filter(|main| main.is_usable(now)),
    );
    issuers
        .into_iter()
        .filter_map(|issuer| {
            let crl = state.current_crl(issuer.serial())?;
            let freshness = crl_freshness(crl.info.next_update, now);
            (freshness != CrlFreshness::Fresh).then(|| CrlWarning {
                issuer_serial: issuer.serial(),
                issuer: issuer.record.subject.display(),
                crl_number: crl.info.crl_number,
                next_update: crl.info.next_update,
                freshness,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{DriveHistory, RepairPlan};

    #[test]
    fn every_blocker_has_one_plain_sentence() {
        // Covers: FR-12 AC3, FR-14 AC3, FR-17 AC2, FR-22 AC4
        let now = crate::build_info::build_date();
        let time = Timestamp::utc(now);
        let blockers = [
            Blocker::NotEnoughDrives {
                primaries: 1,
                backups: 0,
            },
            Blocker::DrivesBehind {
                plans: vec![RepairPlan {
                    source: 0,
                    target: 1,
                    source_label: "primary".into(),
                    target_label: "backup".into(),
                    steps: Vec::new(),
                }],
            },
            Blocker::DrivesDiverged {
                common: 3,
                histories: vec![
                    DriveHistory {
                        drives: vec!["a".into()],
                        entries: Vec::new(),
                    },
                    DriveHistory {
                        drives: vec!["b".into()],
                        entries: Vec::new(),
                    },
                ],
            },
            Blocker::DrivesDamaged {
                problems: vec!["x is missing".into()],
            },
            Blocker::AuditLogBroken {
                drive: "backup".into(),
                entry: 4,
                problem: "changed".into(),
            },
            Blocker::PendingOperation {
                operation: OperationId(2),
                kind: OperationKind::Revoke,
                subject: "CN=KEYSTONE TEST".into(),
            },
            Blocker::ClockBlocked(vec![ClockProblem::EarlierThanBuildDate {
                now,
                build_date: now,
            }]),
            Blocker::ClockConfirmationStale {
                confirmed: time,
                baseline: time,
            },
            Blocker::StateUnreadable("unreadable".into()),
        ];
        let expected = [
            "connect the primary drive",
            "1 drive(s) are behind",
            "2 different histories after entry 3",
            "x is missing",
            "broken at entry 4",
            "operation 2",
            "build date",
            "confirm the date and time again",
            "unreadable",
        ];
        for (blocker, text) in blockers.iter().zip(expected) {
            assert!(blocker.message().contains(text), "{}", blocker.message());
        }
    }
}
