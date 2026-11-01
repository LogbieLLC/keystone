//! Writing one journaled operation (FR-12, FR-16 data layer, FR-22 AC1-AC3, AC7, SEC-04,
//! SEC-11, SEC-20). Sensitive code (GOVERNANCE.md section 3: operation journal).
//!
//! ```text
//! begin_operation ─▶ record_signed / record_yubikey_step ─▶ stage … ─▶ seal_staging
//!   (pending)          (irreversible steps, journaled)        (staging/)   (staged entry)
//!   ─▶ commit ─▶ append_audit ─▶ complete
//!   (move into place)  (audit.log)   (completed entry, last)
//! ```
//! Every step writes to every drive and verifies every copy by read-back SHA-256. An
//! interruption at any point leaves a state the recovery analysis understands.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use super::audit::{AuditDraft, AuditResult};
use super::drive::{DriveSet, to_json_file};
use super::fsio::WriteMode;
use super::ids::{MAX_OPERATION_ID, OperationId};
use super::journal::{
    AuditHead, JOURNAL_FORMAT, JournalEntry, JournalEvent, MAX_OUTPUTS, MAX_STEP, OperationKind,
    OperationState, OutputFile, SignedObject, YubikeySetupStep,
};
use super::paths::{JOURNAL_DIR, OutputDir, OutputPath, RECORD_DIR, STAGING_DIR};
use super::{ExportDrive, StoreError};
use crate::crypto::hash::sha256;
use crate::limits::MAX_OUTPUT_FILE_BYTES;
use crate::model::{Serial, Sha256Digest, Timestamp};

/// PEM label of the only private-key format Keystone stores (SEC-04).
const ENCRYPTED_KEY_LABEL: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
/// Key types of unencrypted private-key PEM labels, `-----BEGIN <type>PRIVATE KEY-----`,
/// that must never reach a drive (SEC-04). The labels are built at run time so neither
/// this source file nor the binary contains one for the plaintext-key scanner to find.
const PLAINTEXT_KEY_TYPES: [&str; 5] = ["", "RSA ", "EC ", "DSA ", "OPENSSH "];

/// SEC-04 at the storage boundary: no output may contain a plaintext private key, and a
/// file in `keys/` must be an encrypted PKCS#8 PEM.
fn check_no_plaintext_key(path: &OutputPath, data: &[u8]) -> Result<(), StoreError> {
    let contains = |marker: &str| data.windows(marker.len()).any(|w| w == marker.as_bytes());
    if PLAINTEXT_KEY_TYPES
        .iter()
        .any(|kind| contains(&format!("-----BEGIN {kind}PRIVATE KEY-----")))
    {
        return Err(StoreError::Unsafe(format!(
            "{path} contains an unencrypted private key; Keystone never stores one (SEC-04)"
        )));
    }
    if path.dir() == OutputDir::Keys && !data.starts_with(ENCRYPTED_KEY_LABEL.as_bytes()) {
        return Err(StoreError::Unsafe(format!(
            "{path} is not an encrypted PKCS#8 key; only encrypted keys are stored (SEC-04)"
        )));
    }
    Ok(())
}

fn whole_seconds(time: Timestamp) -> Result<Timestamp, StoreError> {
    time.get()
        .replace_nanosecond(0)
        .map(Timestamp::utc)
        .map_err(|e| StoreError::Unsafe(e.to_string()))
}

/// Every journal of one drive as raw entry bytes, by operation.
type RawJournals = Vec<(OperationId, Vec<Vec<u8>>)>;

impl DriveSet {
    /// Checks that every drive holds the same audit log and the same journals, and that
    /// no operation is pending. Returns the shared audit-log head.
    pub(crate) fn ensure_in_sync(&self) -> Result<AuditHead, StoreError> {
        let head = self.audit_log()?.head();
        let mut first: Option<(String, RawJournals)> = None;
        for drive in self.drives() {
            let journal = drive.journal()?;
            if let Some((operation, _)) = journal
                .iter()
                .find(|(_, j)| j.state() == OperationState::Pending)
            {
                return Err(StoreError::PendingOperation(*operation));
            }
            let raw: RawJournals = journal
                .into_iter()
                .map(|(op, j)| (op, j.raw_entries().to_vec()))
                .collect();
            match &first {
                None => first = Some((drive.label(), raw)),
                Some((label, existing)) if *existing != raw => {
                    return Err(StoreError::OutOfSync(format!(
                        "{label} and {} have different operation journals",
                        drive.label()
                    )));
                }
                Some(_) => {}
            }
        }
        Ok(head)
    }

    /// The next operation number: one more than any number used on any drive (journal,
    /// staging and record folders).
    pub fn next_operation_id(&self) -> Result<OperationId, StoreError> {
        let mut highest = 0u64;
        for drive in self.drives() {
            for rel in [JOURNAL_DIR, STAGING_DIR, RECORD_DIR] {
                if let Some(dir) = drive.dir_at(rel, false)? {
                    for (name, _) in dir.entries()? {
                        let stem = name.strip_suffix(".json").unwrap_or(&name);
                        if let Some(op) = OperationId::from_stem(stem) {
                            highest = highest.max(op.0);
                        }
                    }
                }
            }
        }
        if highest >= MAX_OPERATION_ID {
            return Err(StoreError::Unsafe("no operation numbers left".to_string()));
        }
        Ok(OperationId(highest + 1))
    }

    /// FR-22 AC1: starts an operation by writing its `pending` entry, with the planned
    /// serial(s), to every drive before the first irreversible step.
    ///
    /// Refuses when the drives differ, an operation is pending, or a planned serial was
    /// ever seen in any record or journal on any connected drive (FR-10 AC2).
    pub fn begin_operation(
        &self,
        kind: OperationKind,
        subject: &str,
        planned_serials: &[Serial],
        time: Timestamp,
    ) -> Result<OperationHandle<'_>, StoreError> {
        self.ensure_writable()?;
        self.ensure_in_sync()?;
        let known = self.known_serials()?;
        let mut unique = BTreeSet::new();
        for serial in planned_serials {
            if known.contains(serial) || !unique.insert(*serial) {
                return Err(StoreError::SerialAlreadyUsed(*serial));
            }
        }
        let id = self.next_operation_id()?;
        let mut handle = OperationHandle {
            set: self,
            id,
            kind,
            subject: subject.to_string(),
            planned: planned_serials.to_vec(),
            next_step: 1,
            outputs: Vec::new(),
            sealed: false,
            committed: false,
            persistent: false,
            audited: false,
        };
        handle.write_entry(
            JournalEvent::Pending {
                kind,
                subject: subject.to_string(),
                planned_serials: planned_serials.to_vec(),
            },
            time,
        )?;
        Ok(handle)
    }

    /// Continues a pending operation whose journal is identical on every drive (for
    /// example YubiKey setup after an interruption, FR-22 AC7). The handle knows what
    /// was already journaled.
    pub fn resume_operation(&self, id: OperationId) -> Result<OperationHandle<'_>, StoreError> {
        self.ensure_writable()?;
        let mut journal = None;
        for drive in self.drives() {
            let this = drive.operation_journal(id)?.ok_or_else(|| {
                StoreError::OutOfSync(format!("{} has no journal for {id}", drive.label()))
            })?;
            match &journal {
                None => journal = Some(this),
                Some(existing) if *existing != this => {
                    return Err(StoreError::OutOfSync(format!(
                        "the drives hold different journals for {id}; use the recovery screen"
                    )));
                }
                Some(_) => {}
            }
        }
        let journal = journal.ok_or(StoreError::NotEnoughDrives {
            primaries: 0,
            backups: 0,
        })?;
        if journal.state() != OperationState::Pending {
            return Err(StoreError::OperationState {
                operation: id,
                message: "the operation is already finished".to_string(),
            });
        }
        let outputs = journal.staged_outputs().map(<[OutputFile]>::to_vec);
        let audited = self
            .audit_log()?
            .entries()
            .iter()
            .any(|entry| entry.operation == Some(id));
        let mut handle = OperationHandle {
            set: self,
            id,
            kind: journal.kind(),
            subject: journal.subject().to_string(),
            planned: journal.planned_serials().to_vec(),
            next_step: journal.entries().len() as u32 + 1,
            sealed: outputs.is_some(),
            outputs: outputs.unwrap_or_default(),
            committed: false,
            persistent: journal.has_persistent_change(),
            audited,
        };
        if handle.sealed && handle.all_placed()? {
            handle.committed = true;
        }
        Ok(handle)
    }

    /// FR-22 AC2: the outputs of a completed operation, if the completed entry and the
    /// complete, hash-verified output set exist on at least two drives. Returns the
    /// outputs and the drives (indexes into [`DriveSet::drives`]) that hold them verified.
    pub fn export_ready(
        &self,
        id: OperationId,
    ) -> Result<(Vec<OutputFile>, Vec<usize>), StoreError> {
        let mut verified = Vec::new();
        let mut outputs: Option<Vec<OutputFile>> = None;
        for (index, drive) in self.drives().iter().enumerate() {
            let Some(journal) = drive.operation_journal(id)? else {
                continue;
            };
            let Some(listed) = journal.completed_outputs() else {
                continue;
            };
            if outputs.as_deref().is_some_and(|o| o != listed) {
                return Err(StoreError::OutOfSync(format!(
                    "the drives disagree about the outputs of {id}"
                )));
            }
            let mut complete = true;
            for output in listed {
                let data = drive.read_at(
                    output.path.dir().name(),
                    output.path.name(),
                    MAX_OUTPUT_FILE_BYTES,
                )?;
                if data.is_none_or(|data| sha256(&data) != output.sha256) {
                    complete = false;
                }
            }
            if complete {
                verified.push(index);
            }
            outputs = Some(listed.to_vec());
        }
        if verified.len() < 2 {
            return Err(StoreError::Unsafe(format!(
                "{id} cannot be exported: its completed entry and every verified output must exist on at least two drives (found {})",
                verified.len()
            )));
        }
        Ok((outputs.unwrap_or_default(), verified))
    }

    /// Copies outputs of a completed operation to the export drive (create-only,
    /// read-back verified), but only after [`DriveSet::export_ready`] passed (FR-22 AC2).
    /// `files` pairs each output with its name on the export drive.
    pub fn export_outputs(
        &self,
        id: OperationId,
        export: &ExportDrive,
        files: &[(OutputPath, String)],
    ) -> Result<Vec<(String, Sha256Digest)>, StoreError> {
        let (outputs, verified) = self.export_ready(id)?;
        let source = &self.drives()[verified[0]];
        let mut written = Vec::new();
        for (path, export_name) in files {
            let output = outputs
                .iter()
                .find(|o| o.path == *path)
                .ok_or_else(|| StoreError::Unsafe(format!("{path} is not an output of {id}")))?;
            let data = source
                .read_at(path.dir().name(), path.name(), MAX_OUTPUT_FILE_BYTES)?
                .filter(|data| sha256(data) == output.sha256)
                .ok_or_else(|| {
                    StoreError::Unsafe(format!("{path} changed on {}", source.label()))
                })?;
            check_no_plaintext_key(path, &data)?;
            written.push((export_name.clone(), export.write_file(export_name, &data)?));
        }
        Ok(written)
    }
}

/// An operation in progress. Created by [`DriveSet::begin_operation`] or
/// [`DriveSet::resume_operation`].
#[derive(Debug)]
pub struct OperationHandle<'a> {
    set: &'a DriveSet,
    id: OperationId,
    kind: OperationKind,
    subject: String,
    planned: Vec<Serial>,
    next_step: u32,
    outputs: Vec<OutputFile>,
    sealed: bool,
    committed: bool,
    persistent: bool,
    audited: bool,
}

impl OperationHandle<'_> {
    /// The operation number.
    pub fn id(&self) -> OperationId {
        self.id
    }

    /// The operation kind.
    pub fn kind(&self) -> OperationKind {
        self.kind
    }

    /// The serials reserved by the pending entry.
    pub fn planned_serials(&self) -> &[Serial] {
        &self.planned
    }

    /// Outputs staged so far.
    pub fn outputs(&self) -> &[OutputFile] {
        &self.outputs
    }

    /// True once a persistent change was made; then the operation can no longer be
    /// cancelled (FR-16).
    pub fn has_persistent_change(&self) -> bool {
        self.persistent
    }

    fn state_error(&self, message: &str) -> StoreError {
        StoreError::OperationState {
            operation: self.id,
            message: message.to_string(),
        }
    }

    fn write_entry(&mut self, event: JournalEvent, time: Timestamp) -> Result<(), StoreError> {
        if self.next_step > MAX_STEP {
            return Err(self.state_error("too many journal entries"));
        }
        let entry = JournalEntry {
            format: JOURNAL_FORMAT,
            operation: self.id,
            step: self.next_step,
            time: whole_seconds(time)?,
            event,
        };
        let rel = format!("{JOURNAL_DIR}/{}", self.id.stem());
        self.set.write_verified(
            &rel,
            &entry.file_name(),
            &to_json_file(&entry),
            WriteMode::CreateOnly,
        )?;
        self.next_step += 1;
        Ok(())
    }

    /// FR-22 AC3: journals a signed certificate or CRL on every drive right after
    /// signing. A certificate whose serial was not planned is still journaled (it must
    /// never be dropped), and then an error stops the operation.
    pub fn record_signed(
        &mut self,
        object: SignedObject,
        time: Timestamp,
    ) -> Result<(), StoreError> {
        if self.sealed {
            return Err(self.state_error("nothing can be signed after staging"));
        }
        let unplanned = match &object {
            SignedObject::Certificate { record, .. } => {
                (!self.planned.contains(&record.serial)).then_some(record.serial)
            }
            SignedObject::Crl(_) => None,
        };
        self.persistent = true;
        self.write_entry(JournalEvent::Signed { object }, time)?;
        match unplanned {
            Some(serial) => Err(self.state_error(&format!(
                "certificate {serial} was signed with a serial the pending entry did not reserve"
            ))),
            None => Ok(()),
        }
    }

    /// FR-22 AC7: journals one finished YubiKey setup step (never a PIN or PUK). Steps
    /// must be recorded in order, each once.
    pub fn record_yubikey_step(
        &mut self,
        step: YubikeySetupStep,
        device_serial: u32,
        time: Timestamp,
    ) -> Result<(), StoreError> {
        if self.kind != OperationKind::SetupYubikey {
            return Err(self.state_error("YubiKey steps belong to YubiKey setup only"));
        }
        if self.sealed {
            return Err(self.state_error("YubiKey steps must come before staging"));
        }
        let done = self.completed_yubikey_steps()?;
        if done.last().is_some_and(|(last, _)| *last >= step) {
            return Err(self.state_error("YubiKey steps must be recorded in order, once each"));
        }
        if done
            .first()
            .is_some_and(|(_, serial)| *serial != device_serial)
        {
            return Err(self.state_error("a different YubiKey was used for this setup"));
        }
        self.persistent = true;
        self.write_entry(
            JournalEvent::YubikeyStep {
                step,
                device_serial,
            },
            time,
        )
    }

    /// The YubiKey steps already journaled (from the primary drive).
    pub fn completed_yubikey_steps(&self) -> Result<Vec<(YubikeySetupStep, u32)>, StoreError> {
        Ok(self.set.drives()[0]
            .operation_journal(self.id)?
            .map(|journal| journal.yubikey_steps())
            .unwrap_or_default())
    }

    /// FR-22 AC2: writes one output to `staging/op-N/` on every drive and verifies every
    /// copy. Refuses plaintext private keys (SEC-04). If an identical staged copy already
    /// exists (an interrupted earlier attempt) it is accepted; a different one is an error.
    pub fn stage(&mut self, path: OutputPath, data: &[u8]) -> Result<OutputFile, StoreError> {
        if self.sealed {
            return Err(self.state_error("staging is already sealed"));
        }
        if self.outputs.iter().any(|o| o.path == path) || self.outputs.len() >= MAX_OUTPUTS {
            return Err(self.state_error(&format!("{path} cannot be staged twice")));
        }
        if data.len() > MAX_OUTPUT_FILE_BYTES {
            return Err(self.state_error(&format!("{path} is too large")));
        }
        check_no_plaintext_key(&path, data)?;
        let rel = format!("{STAGING_DIR}/{}/{}", self.id.stem(), path.dir().name());
        let expected = sha256(data);
        let mut missing = false;
        for drive in self.set.drives() {
            match drive.read_at(&rel, path.name(), MAX_OUTPUT_FILE_BYTES)? {
                Some(existing) if sha256(&existing) == expected => {}
                Some(_) => {
                    return Err(StoreError::AlreadyExists {
                        path: drive.keystone().child(&format!("{rel}/{}", path.name())),
                    });
                }
                None => missing = true,
            }
        }
        if missing {
            // Drives that already hold the identical copy are skipped by the per-drive
            // create-only write below; every copy is then verified.
            for drive in self.set.drives() {
                let dir = drive
                    .dir_at(&rel, true)?
                    .ok_or_else(|| StoreError::Unsafe(format!("cannot create {rel}")))?;
                if dir.kind(path.name())?.is_none() {
                    dir.write_atomic(path.name(), data, WriteMode::CreateOnly)?;
                }
            }
        }
        for drive in self.set.drives() {
            let dir = drive
                .dir_at(&rel, false)?
                .ok_or_else(|| StoreError::Unsafe(format!("{rel} disappeared")))?;
            let actual = sha256(&dir.read_back(path.name(), MAX_OUTPUT_FILE_BYTES)?);
            if actual != expected {
                return Err(StoreError::ReadBackMismatch {
                    drive: drive.label(),
                    path: dir.child(path.name()),
                    expected,
                    actual,
                });
            }
        }
        let output = OutputFile {
            path,
            sha256: expected,
            size: data.len() as u64,
        };
        self.outputs.push(output.clone());
        Ok(output)
    }

    /// Writes the `staged` entry listing every output and its SHA-256 on every drive.
    pub fn seal_staging(&mut self, time: Timestamp) -> Result<(), StoreError> {
        if self.sealed {
            return Err(self.state_error("staging is already sealed"));
        }
        self.write_entry(
            JournalEvent::Staged {
                outputs: self.outputs.clone(),
            },
            time,
        )?;
        self.sealed = true;
        self.persistent = true;
        Ok(())
    }

    fn all_placed(&self) -> Result<bool, StoreError> {
        for drive in self.set.drives() {
            for output in &self.outputs {
                let placed = drive.read_at(
                    output.path.dir().name(),
                    output.path.name(),
                    MAX_OUTPUT_FILE_BYTES,
                )?;
                if placed.is_none_or(|data| sha256(&data) != output.sha256) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Moves every staged output into place on every drive (create-only: an existing file
    /// is never replaced, SEC-20), then verifies every placed copy (FR-12 AC2).
    pub fn commit(&mut self) -> Result<(), StoreError> {
        if !self.sealed {
            return Err(self.state_error("seal staging before moving outputs into place"));
        }
        self.persistent = true;
        let staging = format!("{STAGING_DIR}/{}", self.id.stem());
        for drive in self.set.drives() {
            for output in &self.outputs {
                let dir_name = output.path.dir().name();
                let target = drive
                    .dir_at(dir_name, true)?
                    .ok_or_else(|| StoreError::Unsafe(format!("cannot open {dir_name}")))?;
                match target.read_if_exists(output.path.name(), MAX_OUTPUT_FILE_BYTES)? {
                    Some(data) if sha256(&data) == output.sha256 => continue,
                    Some(_) => {
                        return Err(StoreError::AlreadyExists {
                            path: target.child(output.path.name()),
                        });
                    }
                    None => {}
                }
                let source = drive
                    .dir_at(&format!("{staging}/{dir_name}"), false)?
                    .ok_or_else(|| {
                        StoreError::Unsafe(format!(
                            "the staged copy of {} is missing on {}",
                            output.path,
                            drive.label()
                        ))
                    })?;
                source.move_to(output.path.name(), &target, output.path.name())?;
            }
        }
        for drive in self.set.drives() {
            for output in &self.outputs {
                let dir = drive
                    .dir_at(output.path.dir().name(), false)?
                    .ok_or_else(|| StoreError::Unsafe(format!("{} disappeared", output.path)))?;
                let actual = sha256(&dir.read_back(output.path.name(), MAX_OUTPUT_FILE_BYTES)?);
                if actual != output.sha256 {
                    return Err(StoreError::ReadBackMismatch {
                        drive: drive.label(),
                        path: dir.child(output.path.name()),
                        expected: output.sha256,
                        actual,
                    });
                }
            }
            remove_empty_staging(drive, &staging)?;
        }
        self.committed = true;
        Ok(())
    }

    /// FR-14 AC1: appends this operation's audit entries on every drive. The drafts'
    /// `operation` is set to this operation.
    pub fn append_audit(
        &mut self,
        drafts: &[AuditDraft],
        time: Timestamp,
    ) -> Result<(), StoreError> {
        if drafts.is_empty() {
            return Err(self.state_error("an operation needs at least one audit entry"));
        }
        let drafts: Vec<AuditDraft> = drafts
            .iter()
            .cloned()
            .map(|mut draft| {
                draft.operation = Some(self.id);
                draft
            })
            .collect();
        self.set.append_audit(&drafts, time)?;
        self.audited = true;
        Ok(())
    }

    /// FR-22 AC2: writes the `completed` entry, last, on every drive: every output's
    /// SHA-256 and the audit-log head. Requires the outputs to be in place and the audit
    /// entries written.
    pub fn complete(mut self, time: Timestamp) -> Result<Vec<OutputFile>, StoreError> {
        if !self.sealed {
            return Err(self.state_error("seal staging before completing"));
        }
        if !self.committed {
            if !self.all_placed()? {
                return Err(self.state_error("move the outputs into place before completing"));
            }
            self.committed = true;
        }
        if !self.audited {
            return Err(self.state_error("write the audit entry before completing"));
        }
        let audit = self.set.audit_log()?.head();
        let outputs = self.outputs.clone();
        self.write_entry(
            JournalEvent::Completed {
                outputs: outputs.clone(),
                audit,
            },
            time,
        )?;
        Ok(outputs)
    }

    /// FR-16: cancels before the first persistent change. Deletes this operation's staged
    /// files, appends a cancelled audit entry and writes the `cancelled` entry. The
    /// pending entry stays, so the planned serial stays reserved.
    pub fn cancel(mut self, time: Timestamp) -> Result<(), StoreError> {
        if self.persistent || self.sealed || self.committed {
            return Err(self.state_error(
                "the operation made a persistent change and can no longer be cancelled",
            ));
        }
        let staging = format!("{STAGING_DIR}/{}", self.id.stem());
        for drive in self.set.drives() {
            for output in &self.outputs {
                if let Some(dir) =
                    drive.dir_at(&format!("{staging}/{}", output.path.dir().name()), false)?
                    && dir.kind(output.path.name())?.is_some()
                {
                    dir.remove_file(output.path.name())?;
                }
            }
            remove_empty_staging(drive, &staging)?;
        }
        let mut draft = AuditDraft::new(
            self.kind.into(),
            self.subject.clone(),
            AuditResult::Cancelled,
        );
        draft.serial = self.planned.first().copied();
        self.append_audit(&[draft], time)?;
        let audit = self.set.audit_log()?.head();
        self.write_entry(JournalEvent::Cancelled { audit }, time)
    }
}

/// Removes empty folders under `staging/op-N` (never files).
fn remove_empty_staging(drive: &super::CaDrive, staging: &str) -> Result<(), StoreError> {
    if let Some(dir) = drive.dir_at(staging, false)? {
        for name in OutputDir::ALL.map(OutputDir::name) {
            dir.remove_empty_dir(name)?;
        }
    }
    if let Some(parent) = drive.dir_at(STAGING_DIR, false)?
        && let Some((_, op)) = staging.split_once('/')
    {
        parent.remove_empty_dir(op)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
