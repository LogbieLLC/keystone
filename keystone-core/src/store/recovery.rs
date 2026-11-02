//! Recovery after an interrupted operation (FR-22 AC4, AC5, AC7, AC8 data layer, SEC-22).
//! Sensitive code (GOVERNANCE.md section 3: operation journal).
//!
//! [`DriveSet::recovery_report`] lists every operation that is pending (no final entry)
//! on at least one drive, with exactly what each drive holds for it: journal entries,
//! signed objects, YubiKey steps, and every output file in staging and in place with its
//! hash status. It offers at most two actions, each with one plain sentence:
//! - [`RecoveryAction::FinishFrom`]: a drive already holds the operation's final entry
//!   (an interrupted finish, cancel or abandon): bring its audit entries to every drive,
//!   then copy that final entry, so every drive records the same end. Nothing else is
//!   offered then, and Abandon is refused: a second final entry would make the journal
//!   unreadable;
//! - [`RecoveryAction::FinishFrom`]: a drive holds the verified output (every file listed
//!   by its `staged` or `completed` entry, with the right SHA-256): copy what is missing
//!   to the other drives, write the audit entry and the `completed` entry last;
//! - [`RecoveryAction::Abandon`]: offered only when nothing irreversible was journaled on
//!   any drive (no signature, no YubiKey step, nothing staged) and no drive holds a final
//!   entry: mark it abandoned; its serial stays reserved. An audit entry that an earlier,
//!   interrupted cancel or abandon wrote to some drives only is first copied to every
//!   drive (an earlier abandon entry is reused, not written twice);
//! - for YubiKey setup with recorded steps and nothing staged,
//!   [`RecoveryAction::ResumeYubikeySetup`] tells the operations layer to read the
//!   YubiKey's real state and continue from the first incomplete step (FR-22 AC5, AC7).
//!
//! Recovery never formats, deletes or overwrites anything.
#![forbid(unsafe_code)]

use super::StoreError;
use super::audit::{AuditAction, AuditDetails, AuditDraft, AuditResult};
use super::compare::{copy_journal_entries, copy_output, extend_log};
use super::drive::{CaDrive, DriveSet, to_json_file};
use super::fsio::WriteMode;
use super::ids::OperationId;
use super::journal::{
    JOURNAL_FORMAT, JournalEntry, JournalEvent, OperationJournal, OperationKind, OperationState,
    OutputFile, SignedObject, YubikeySetupStep,
};
use super::paths::{JOURNAL_DIR, OutputDir, OutputPath, STAGING_DIR};
use super::record::{RecordChange, parse_record};
use crate::crypto::hash::sha256;
use crate::limits::MAX_OUTPUT_FILE_BYTES;
use crate::model::{Serial, Sha256Digest, Timestamp};

/// A file compared with the SHA-256 its journal lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    /// Not there.
    Missing,
    /// There, with the listed SHA-256.
    Verified,
    /// There, but different.
    Differs,
}

/// One output file on one drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputState {
    /// The output.
    pub path: OutputPath,
    /// Its SHA-256 as listed in the journal.
    pub sha256: Sha256Digest,
    /// The copy in `staging/op-N/`.
    pub staged: FileState,
    /// The copy in place.
    pub placed: FileState,
}

impl OutputState {
    /// True when a verified copy exists (staged or in place).
    pub fn available(&self) -> bool {
        self.staged == FileState::Verified || self.placed == FileState::Verified
    }
}

/// What one drive holds for an interrupted operation (one column of the recovery screen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveOperationView {
    /// Index into [`DriveSet::drives`].
    pub drive_index: usize,
    /// Drive label.
    pub drive: String,
    /// Journal entry file names, in order (empty: no journal for this operation).
    pub journal_entries: Vec<String>,
    /// State on this drive (`None`: no journal).
    pub state: Option<OperationState>,
    /// Serials of certificates journaled as signed.
    pub signed_certificates: Vec<Serial>,
    /// CRL numbers journaled as signed.
    pub signed_crls: Vec<u64>,
    /// YubiKey steps journaled, with the device serial.
    pub yubikey_steps: Vec<(YubikeySetupStep, u32)>,
    /// Outputs listed by this drive's `staged` (or `completed`) entry.
    pub outputs: Vec<OutputState>,
    /// Files in `staging/op-N/` that no journal entry lists, with their SHA-256.
    pub unlisted_staged_files: Vec<(String, Sha256Digest)>,
    /// Number of audit entries this drive holds for the operation.
    pub audit_entries: usize,
    /// True when every listed output has a verified copy on this drive.
    pub holds_verified_output: bool,
}

/// A safe recovery action (FR-22 AC4, AC8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Finish the writes from a drive that holds the verified output.
    FinishFrom {
        /// Index into [`DriveSet::drives`].
        drive_index: usize,
        /// Drive label.
        drive: String,
    },
    /// Mark the operation abandoned (no signed output exists anywhere).
    Abandon,
    /// YubiKey setup: read the YubiKey's real state and continue from the first
    /// incomplete step (the operations layer does this; FR-22 AC5, AC7).
    ResumeYubikeySetup {
        /// The first step not yet journaled.
        next_step: Option<YubikeySetupStep>,
    },
}

impl RecoveryAction {
    /// One plain sentence: what it will do and what it will not do (FR-22 AC8).
    pub fn description(&self, operation: OperationId) -> String {
        match self {
            RecoveryAction::FinishFrom { drive, .. } => format!(
                "Copy the finished files of {operation} from {drive} to every other drive and mark it completed; nothing is deleted or overwritten."
            ),
            RecoveryAction::Abandon => format!(
                "Mark {operation} as abandoned and keep its serial number reserved; nothing is deleted or overwritten."
            ),
            RecoveryAction::ResumeYubikeySetup { next_step } => match next_step {
                Some(step) => format!(
                    "Check the YubiKey and continue {operation} from the step \"{step:?}\"; no finished step is repeated and nothing is wiped."
                ),
                None => format!(
                    "Check the YubiKey and continue {operation}; no finished step is repeated and nothing is wiped."
                ),
            },
        }
    }
}

/// One interrupted operation and what can be done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingOperation {
    /// The operation.
    pub operation: OperationId,
    /// Its kind (from the pending entry).
    pub kind: OperationKind,
    /// Its subject.
    pub subject: String,
    /// Its reserved serials.
    pub planned_serials: Vec<Serial>,
    /// One column per drive.
    pub drives: Vec<DriveOperationView>,
    /// True when a signature, YubiKey step or staged output was journaled on any drive.
    pub signed_output_exists: bool,
    /// At most two safe actions.
    pub actions: Vec<RecoveryAction>,
    /// Why no action can be offered, when `actions` is empty.
    pub blocked_reason: Option<String>,
}

/// Every interrupted operation (FR-22 AC4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoveryReport {
    /// Interrupted operations, oldest first.
    pub pending: Vec<PendingOperation>,
}

impl RecoveryReport {
    /// True when nothing needs recovery.
    pub fn is_clean(&self) -> bool {
        self.pending.is_empty()
    }
}

fn file_state(data: Option<Vec<u8>>, expected: Sha256Digest) -> FileState {
    match data {
        None => FileState::Missing,
        Some(data) if sha256(&data) == expected => FileState::Verified,
        Some(_) => FileState::Differs,
    }
}

fn staging_rel(operation: OperationId, dir: OutputDir) -> String {
    format!("{STAGING_DIR}/{}/{}", operation.stem(), dir.name())
}

fn listed_outputs(journal: &OperationJournal) -> Option<&[OutputFile]> {
    journal.completed_outputs().or(journal.staged_outputs())
}

fn view(
    drive_index: usize,
    drive: &CaDrive,
    operation: OperationId,
    journal: Option<&OperationJournal>,
) -> Result<DriveOperationView, StoreError> {
    let mut outputs = Vec::new();
    let listed = journal.and_then(listed_outputs).unwrap_or_default();
    for output in listed {
        let (dir, name) = (output.path.dir(), output.path.name());
        outputs.push(OutputState {
            path: output.path.clone(),
            sha256: output.sha256,
            staged: file_state(
                drive.read_at(&staging_rel(operation, dir), name, MAX_OUTPUT_FILE_BYTES)?,
                output.sha256,
            ),
            placed: file_state(
                drive.read_at(dir.name(), name, MAX_OUTPUT_FILE_BYTES)?,
                output.sha256,
            ),
        });
    }
    let mut unlisted = Vec::new();
    for dir in OutputDir::ALL {
        let Some(folder) = drive.dir_at(&staging_rel(operation, dir), false)? else {
            continue;
        };
        for (name, _) in folder.entries()? {
            if name.starts_with('.')
                || listed
                    .iter()
                    .any(|o| o.path.dir() == dir && o.path.name() == name)
            {
                continue;
            }
            let data = folder.read(&name, MAX_OUTPUT_FILE_BYTES)?;
            unlisted.push((format!("{}/{name}", dir.name()), sha256(&data)));
        }
    }
    let mut signed_certificates = Vec::new();
    let mut signed_crls = Vec::new();
    for object in journal.into_iter().flat_map(OperationJournal::signed) {
        match object {
            SignedObject::Certificate { record, .. } => signed_certificates.push(record.serial),
            SignedObject::Crl(crl) => signed_crls.push(crl.crl_number),
        }
    }
    let audit_entries = drive
        .audit_log()?
        .entries()
        .iter()
        .filter(|entry| entry.operation == Some(operation))
        .count();
    Ok(DriveOperationView {
        drive_index,
        drive: drive.label(),
        journal_entries: journal
            .map(|j| j.entries().iter().map(JournalEntry::file_name).collect())
            .unwrap_or_default(),
        state: journal.map(OperationJournal::state),
        signed_certificates,
        signed_crls,
        yubikey_steps: journal
            .map(OperationJournal::yubikey_steps)
            .unwrap_or_default(),
        holds_verified_output: journal.and_then(listed_outputs).is_some()
            && outputs.iter().all(OutputState::available),
        outputs,
        unlisted_staged_files: unlisted,
        audit_entries,
    })
}

/// True when `shorter`'s entries are the first entries of `longer`, byte for byte.
fn journal_prefix(shorter: &OperationJournal, longer: &OperationJournal) -> bool {
    shorter.raw_entries().len() <= longer.raw_entries().len()
        && shorter
            .raw_entries()
            .iter()
            .zip(longer.raw_entries())
            .all(|(a, b)| a == b)
}

impl DriveSet {
    /// FR-22 AC4: every operation that is pending on at least one drive, with what each
    /// drive holds and the safe actions.
    pub fn recovery_report(&self) -> Result<RecoveryReport, StoreError> {
        let journals: Vec<_> = self
            .drives()
            .iter()
            .map(CaDrive::journal)
            .collect::<Result<_, _>>()?;
        let mut operations: Vec<OperationId> = journals
            .iter()
            .flat_map(|journal| {
                journal
                    .iter()
                    .filter(|(_, j)| j.state() == OperationState::Pending)
                    .map(|(op, _)| *op)
            })
            .collect();
        operations.sort();
        operations.dedup();
        let mut report = RecoveryReport::default();
        for operation in operations {
            let per_drive: Vec<Option<&OperationJournal>> = journals
                .iter()
                .map(|journal| journal.get(&operation))
                .collect();
            report.pending.push(self.analyse(operation, &per_drive)?);
        }
        Ok(report)
    }

    fn analyse(
        &self,
        operation: OperationId,
        per_drive: &[Option<&OperationJournal>],
    ) -> Result<PendingOperation, StoreError> {
        let mut drives = Vec::new();
        for (index, (drive, journal)) in self.drives().iter().zip(per_drive).enumerate() {
            drives.push(view(index, drive, operation, *journal)?);
        }
        let any = per_drive
            .iter()
            .flatten()
            .next()
            .copied()
            .ok_or_else(|| StoreError::Unsafe(format!("{operation} has no journal")))?;
        let signed_output_exists = per_drive
            .iter()
            .flatten()
            .any(|journal| journal.has_persistent_change());
        let longest = per_drive
            .iter()
            .flatten()
            .max_by_key(|journal| journal.entries().len())
            .copied()
            .unwrap_or(any);
        let consistent = per_drive
            .iter()
            .flatten()
            .all(|journal| journal_prefix(journal, longest));
        let terminal_source = per_drive
            .iter()
            .position(|journal| journal.is_some_and(|j| j.terminal().is_some()));
        let signed_or_staged = per_drive
            .iter()
            .flatten()
            .any(|journal| journal.signed().next().is_some() || journal.staged_outputs().is_some());
        let next_step = {
            let done = longest.yubikey_steps();
            YubikeySetupStep::ALL
                .into_iter()
                .find(|step| !done.iter().any(|(d, _)| d == step))
        };
        let mut actions = Vec::new();
        let mut blocked_reason = None;
        if !consistent {
            blocked_reason = Some(
                "the drives hold different journals for this operation; no automatic action is safe"
                    .to_string(),
            );
        } else if let Some(source) = terminal_source {
            // A drive already holds the final entry (an interrupted finish, cancel or
            // abandon): the only safe action is to make every drive agree with it.
            if longest.state() == OperationState::Completed && !drives[source].holds_verified_output
            {
                blocked_reason = Some(format!(
                    "{} marks this operation completed, but files its completed entry lists are missing or changed there",
                    drives[source].drive
                ));
            } else {
                actions.push(RecoveryAction::FinishFrom {
                    drive_index: source,
                    drive: drives[source].drive.clone(),
                });
            }
        } else if let Some(source) = best_source(&drives, per_drive) {
            actions.push(RecoveryAction::FinishFrom {
                drive_index: source,
                drive: drives[source].drive.clone(),
            });
        } else if !signed_output_exists && !signed_or_staged {
            actions.push(RecoveryAction::Abandon);
        } else if longest.kind() == OperationKind::SetupYubikey
            && longest.staged_outputs().is_none()
        {
            actions.push(RecoveryAction::ResumeYubikeySetup { next_step });
        } else {
            blocked_reason = Some(
                "something was signed, but no drive holds the complete verified output".to_string(),
            );
        }
        Ok(PendingOperation {
            operation,
            kind: any.kind(),
            subject: any.subject().to_string(),
            planned_serials: any.planned_serials().to_vec(),
            drives,
            signed_output_exists,
            actions,
            blocked_reason,
        })
    }

    /// Copies missing journal entries of `operation` (all but a final entry) from the drive
    /// with the longest journal to the others. The journals must agree byte for byte.
    pub fn sync_operation_journal(&self, operation: OperationId) -> Result<(), StoreError> {
        self.ensure_writable()?;
        let journals: Vec<Option<OperationJournal>> = self
            .drives()
            .iter()
            .map(|drive| drive.operation_journal(operation))
            .collect::<Result<_, _>>()?;
        let (source, longest) = journals
            .iter()
            .enumerate()
            .filter_map(|(index, journal)| journal.as_ref().map(|j| (index, j)))
            .max_by_key(|(_, journal)| journal.entries().len())
            .ok_or_else(|| StoreError::Unsafe(format!("{operation} has no journal")))?;
        if journals
            .iter()
            .flatten()
            .any(|journal| !journal_prefix(journal, longest))
        {
            return Err(StoreError::Unsafe(format!(
                "the drives hold different journals for {operation}"
            )));
        }
        for (index, drive) in self.drives().iter().enumerate() {
            if index != source {
                copy_journal_entries(&self.drives()[source], drive, longest, false)?;
            }
        }
        Ok(())
    }

    /// FR-22 AC4: finishes an interrupted operation from a drive holding its verified
    /// output. Re-checks that the action is still offered, then on every drive: copies
    /// missing journal entries, moves or copies outputs into place (create-only, verified),
    /// brings the operation's audit entries up to date (or writes a `recovery_finish`
    /// entry), and writes the `completed` entry last.
    pub fn finish_operation(
        &self,
        operation: OperationId,
        source: usize,
        time: Timestamp,
    ) -> Result<(), StoreError> {
        self.ensure_writable()?;
        let report = self.recovery_report()?;
        let pending = report
            .pending
            .iter()
            .find(|p| p.operation == operation)
            .ok_or_else(|| StoreError::Unsafe(format!("{operation} is not pending")))?;
        if !pending
            .actions
            .iter()
            .any(|a| matches!(a, RecoveryAction::FinishFrom { drive_index, .. } if *drive_index == source))
        {
            return Err(StoreError::Unsafe(format!(
                "finishing {operation} from that drive is not a safe action"
            )));
        }
        self.sync_operation_journal(operation)?;
        let src = &self.drives()[source];
        let journal = src
            .operation_journal(operation)?
            .ok_or_else(|| StoreError::Unsafe(format!("{operation} disappeared")))?;
        let outputs = listed_outputs(&journal).unwrap_or_default().to_vec();
        for drive in self.drives() {
            for output in &outputs {
                place_output(src, drive, operation, output)?;
            }
        }
        let audited = self.sync_operation_audit(operation)?;
        if let Some(head) = journal.audit_head() {
            // The final entry exists on `src`: every drive must now hold the audit entry
            // it records before the final entry is copied (FR-12 AC3 order).
            for drive in self.drives() {
                if drive.audit_log()?.entry_hash(head.seq) != Some(head.sha256) {
                    return Err(StoreError::Unsafe(format!(
                        "{} does not hold audit entry {} that the final entry of {operation} records; compare the drives first",
                        drive.label(),
                        head.seq
                    )));
                }
            }
            for drive in self.drives() {
                copy_journal_entries(src, drive, &journal, true)?;
            }
            return Ok(());
        }
        if !audited {
            let draft = recovery_finish_draft(src, &journal, &outputs)?;
            self.append_audit(&[draft], time)?;
        }
        let entry = JournalEntry {
            format: JOURNAL_FORMAT,
            operation,
            step: journal.entries().len() as u32 + 1,
            time: whole(time)?,
            event: JournalEvent::Completed {
                outputs,
                // The operation's own last audit entry, not the log head (finding 6).
                audit: self
                    .audit_log()?
                    .operation_head(operation)
                    .ok_or_else(|| StoreError::Unsafe(format!("{operation} has no audit entry")))?,
            },
        };
        self.write_verified(
            &format!("{JOURNAL_DIR}/{}", operation.stem()),
            &entry.file_name(),
            &to_json_file(&entry),
            WriteMode::CreateOnly,
        )?;
        Ok(())
    }

    /// FR-22 AC4: marks an operation abandoned when no signed output exists anywhere.
    /// Its pending entry stays, so its serial stays reserved. Nothing is deleted.
    pub fn abandon_operation(
        &self,
        operation: OperationId,
        time: Timestamp,
    ) -> Result<(), StoreError> {
        self.ensure_writable()?;
        let report = self.recovery_report()?;
        let pending = report
            .pending
            .iter()
            .find(|p| p.operation == operation)
            .ok_or_else(|| StoreError::Unsafe(format!("{operation} is not pending")))?;
        if !pending.actions.contains(&RecoveryAction::Abandon) {
            return Err(StoreError::Unsafe(format!(
                "{operation} cannot be abandoned: something irreversible was recorded"
            )));
        }
        // Re-checked on the raw journals: never a second final entry (review finding 1),
        // never after a signature or staging (FR-22 AC4).
        for drive in self.drives() {
            if let Some(journal) = drive.operation_journal(operation)? {
                if journal.terminal().is_some() {
                    return Err(StoreError::Unsafe(format!(
                        "{operation} already has a final entry on {}; finish it from that drive",
                        drive.label()
                    )));
                }
                if journal.signed().next().is_some() || journal.staged_outputs().is_some() {
                    return Err(StoreError::Unsafe(format!(
                        "{operation} cannot be abandoned: something was signed or staged"
                    )));
                }
            }
        }
        self.sync_operation_journal(operation)?;
        // An earlier attempt may have written the audit entry to some drives only
        // (review finding 2): bring it to every drive first.
        self.sync_operation_audit(operation)?;
        let journal = self
            .drives()
            .iter()
            .map(|drive| drive.operation_journal(operation))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .max_by_key(|journal| journal.entries().len())
            .ok_or_else(|| StoreError::Unsafe(format!("{operation} disappeared")))?;
        let log = self.audit_log()?;
        let previous = log
            .entries()
            .iter()
            .rev()
            .find(|entry| entry.operation == Some(operation))
            .filter(|entry| {
                entry.action == AuditAction::RecoveryAbandon
                    && entry.result == AuditResult::Abandoned
            });
        if previous.is_none() {
            let mut draft = AuditDraft::new(
                AuditAction::RecoveryAbandon,
                journal.subject(),
                AuditResult::Abandoned,
            );
            draft.operation = Some(operation);
            draft.serial = journal.planned_serials().first().copied();
            self.append_audit(&[draft], time)?;
        }
        let audit = self
            .audit_log()?
            .operation_head(operation)
            .ok_or_else(|| StoreError::Unsafe(format!("{operation} has no audit entry")))?;
        let entry = JournalEntry {
            format: JOURNAL_FORMAT,
            operation,
            step: journal.entries().len() as u32 + 1,
            time: whole(time)?,
            event: JournalEvent::Abandoned { audit },
        };
        self.write_verified(
            &format!("{JOURNAL_DIR}/{}", operation.stem()),
            &entry.file_name(),
            &to_json_file(&entry),
            WriteMode::CreateOnly,
        )?;
        Ok(())
    }

    /// Makes every drive hold this operation's audit entries when some drive already has
    /// them (an interruption between drives). Returns true when the entries exist.
    fn sync_operation_audit(&self, operation: OperationId) -> Result<bool, StoreError> {
        let logs: Vec<_> = self
            .drives()
            .iter()
            .map(CaDrive::audit_log)
            .collect::<Result<_, _>>()?;
        let longest = (0..logs.len()).max_by_key(|i| logs[*i].len()).unwrap_or(0);
        if logs.iter().any(|log| !log.is_prefix_of(&logs[longest])) {
            return Err(StoreError::OutOfSync(
                "the audit logs differ; compare the drives first".to_string(),
            ));
        }
        let source = &logs[longest];
        let has_entries = source
            .entries()
            .iter()
            .any(|e| e.operation == Some(operation));
        for (drive, log) in self.drives().iter().zip(&logs) {
            if log.len() < source.len() {
                if source.entries()[log.len()..]
                    .iter()
                    .any(|entry| entry.operation != Some(operation))
                {
                    return Err(StoreError::OutOfSync(format!(
                        "{} is missing more than this operation's audit entries; compare the drives first",
                        drive.label()
                    )));
                }
                extend_log(drive, source, source.len() as u64)?;
            }
        }
        Ok(has_entries)
    }
}

/// The `recovery_finish` audit entry of an operation finished from `src` (FR-14 AC1,
/// FR-21 AC6, review finding 8): the original action, the subject, the first serial and
/// fingerprint, the issuer, the permitted names, the revocation reason, the CRL number and
/// every serial the operation signed or changed in the issuance record.
fn recovery_finish_draft(
    src: &CaDrive,
    journal: &OperationJournal,
    outputs: &[OutputFile],
) -> Result<AuditDraft, StoreError> {
    let operation = journal.operation();
    let mut draft = AuditDraft::new(
        AuditAction::RecoveryFinish,
        journal.subject(),
        AuditResult::Success,
    );
    draft.operation = Some(operation);
    let mut details = AuditDetails {
        original_action: Some(journal.kind().into()),
        note: Some(format!(
            "finished from {} after an interruption",
            src.label()
        )),
        ..AuditDetails::default()
    };
    let mut serials: Vec<Serial> = Vec::new();
    let add = |serial: Serial, serials: &mut Vec<Serial>| {
        if !serials.contains(&serial) {
            serials.push(serial);
        }
    };
    for object in journal.signed() {
        match object {
            SignedObject::Certificate { record, .. } => {
                add(record.serial, &mut serials);
                if draft.fingerprint.is_none() {
                    draft.fingerprint = Some(record.fingerprint);
                    details.issuer_serial = Some(record.issuer_serial);
                    if record.level == crate::model::CaLevel::SubIntermediate {
                        details.name_constraints = Some(record.name_constraints);
                        details.permitted_dns = Some(record.permitted_dns.clone());
                        details.permitted_ip = Some(record.permitted_ip.clone());
                    }
                }
            }
            SignedObject::Crl(crl) => {
                details.crl_number = Some(crl.crl_number);
                details.issuer_serial.get_or_insert(crl.issuer_serial);
            }
        }
    }
    // The issuance-record update lists every revocation (and every sub-intermediate cut
    // off by it); it is one of the verified outputs on `src`.
    for output in outputs.iter().filter(|o| o.path.dir() == OutputDir::Record) {
        let (dir, name) = (output.path.dir(), output.path.name());
        let data = match src.read_at(dir.name(), name, MAX_OUTPUT_FILE_BYTES)? {
            Some(data) if sha256(&data) == output.sha256 => Some(data),
            _ => src
                .read_at(&staging_rel(operation, dir), name, MAX_OUTPUT_FILE_BYTES)?
                .filter(|data| sha256(data) == output.sha256),
        };
        let Some(data) = data else { continue };
        let update = parse_record(&data).map_err(|source| StoreError::Parse {
            path: src.keystone().child(&output.path.to_string()),
            source,
        })?;
        for change in &update.changes {
            match change {
                RecordChange::Issued { certificate } => add(certificate.serial, &mut serials),
                RecordChange::Revoked { serial, reason, .. } => {
                    add(*serial, &mut serials);
                    details.revocation_reason.get_or_insert(*reason);
                }
                RecordChange::RevokedByAncestor { serial, .. } => add(*serial, &mut serials),
            }
        }
    }
    draft.serial = serials
        .first()
        .copied()
        .or_else(|| journal.planned_serials().first().copied());
    if !serials.is_empty() {
        serials.truncate(super::audit::MAX_AUDIT_SERIALS);
        details.serials = Some(serials);
    }
    draft.details = Some(details);
    Ok(draft)
}

/// Puts one output in place on `drive`: already there and verified, moved from this
/// drive's verified staged copy, or copied from `src`. Never overwrites.
fn place_output(
    src: &CaDrive,
    drive: &CaDrive,
    operation: OperationId,
    output: &OutputFile,
) -> Result<(), StoreError> {
    let (dir, name) = (output.path.dir(), output.path.name());
    match file_state(
        drive.read_at(dir.name(), name, MAX_OUTPUT_FILE_BYTES)?,
        output.sha256,
    ) {
        FileState::Verified => return Ok(()),
        FileState::Differs => {
            return Err(StoreError::Unsafe(format!(
                "{} holds a different {}; it is never overwritten",
                drive.label(),
                output.path
            )));
        }
        FileState::Missing => {}
    }
    let staging = staging_rel(operation, dir);
    let staged = drive.read_at(&staging, name, MAX_OUTPUT_FILE_BYTES)?;
    if file_state(staged, output.sha256) == FileState::Verified {
        let from = drive
            .dir_at(&staging, false)?
            .ok_or_else(|| StoreError::Unsafe(format!("{staging} disappeared")))?;
        let to = drive
            .dir_at(dir.name(), true)?
            .ok_or_else(|| StoreError::Unsafe(format!("cannot open {}", dir.name())))?;
        from.move_to(name, &to, name)?;
        let back = sha256(&to.read_back(name, MAX_OUTPUT_FILE_BYTES)?);
        if back != output.sha256 {
            return Err(StoreError::ReadBackMismatch {
                drive: drive.label(),
                path: to.child(name),
                expected: output.sha256,
                actual: back,
            });
        }
        return Ok(());
    }
    // Copy from the source drive (its placed or staged verified copy).
    if file_state(
        src.read_at(dir.name(), name, MAX_OUTPUT_FILE_BYTES)?,
        output.sha256,
    ) == FileState::Verified
    {
        return copy_output(src, drive, output);
    }
    let data = src
        .read_at(&staging, name, MAX_OUTPUT_FILE_BYTES)?
        .filter(|data| sha256(data) == output.sha256)
        .ok_or_else(|| {
            StoreError::Unsafe(format!("{} is missing on {}", output.path, src.label()))
        })?;
    drive.write_one_verified(dir.name(), name, &data, WriteMode::CreateOnly)
}

fn whole(time: Timestamp) -> Result<Timestamp, StoreError> {
    time.get()
        .replace_nanosecond(0)
        .map(Timestamp::utc)
        .map_err(|e| StoreError::Unsafe(e.to_string()))
}

/// Which drive to finish from: one that holds the verified output, preferring a drive
/// with a `completed` entry, then the primary.
fn best_source(
    views: &[DriveOperationView],
    per_drive: &[Option<&OperationJournal>],
) -> Option<usize> {
    views
        .iter()
        .zip(per_drive)
        .filter(|(view, _)| view.holds_verified_output)
        .min_by_key(|(view, journal)| {
            let completed = journal.is_some_and(|j| j.state() == OperationState::Completed);
            (!completed, view.drive_index)
        })
        .map(|(view, _)| view.drive_index)
}

#[cfg(test)]
mod tests;
