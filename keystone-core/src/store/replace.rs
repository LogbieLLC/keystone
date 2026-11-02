//! Replace a lost drive (SEC-11, T-11; maintainer-approved feature, ADR 0003).
//!
//! When a CA drive is lost or fails, a new **empty** drive receives a complete, verified
//! copy of the CA from the healthy drives that are connected, and the change is audited:
//!
//! 1. [`DriveSet::plan_add_drive`] checks, writing nothing: the connected drives hold the
//!    same verified history (no drive behind, diverged or damaged), no operation is
//!    interrupted, and the new drive is empty (or holds an interrupted copy of this CA,
//!    which is then continued). It works with a single healthy drive, and with a CA that
//!    has no primary or no backup left: that is the emergency it exists for. Everything
//!    else that writes still needs a primary and at least one backup (FR-12 AC1).
//! 2. [`DriveSet::add_drive`] copies every journal entry, every output file listed by a
//!    completed entry, the audit log and the binary-hash record to the new drive, each
//!    create-only (the audit log only grows) and verified by read-back SHA-256 against
//!    the completed entries and the source; then it verifies the whole copy again and
//!    **writes the new drive's identity last**, so an interrupted copy never looks like a
//!    CA drive. It then appends, on every drive, a `drive_repair` audit entry naming the
//!    added drive and, when no primary was connected (the primary was lost), one naming
//!    the backup promoted to primary. Both are written together, on each drive at once.
//!
//! Nothing is signed, nothing is overwritten (except the replace-type `audit.log`, which
//! only grows, and `binary.sha256` on the new drive) and nothing is deleted. A drive's
//! `drive.json` is create-only, so a promotion is recorded in the audit log, and
//! [`DriveSet::open`] gives drives their role from the latest promotion there.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use super::StoreError;
use super::audit::{AuditAction, AuditDetails, AuditDraft, AuditResult};
use super::compare::{
    DriveComparison, copy_journal_entries, copy_output, drive_problems, extend_log,
};
use super::drive::{
    CaDrive, DriveClass, DriveIdentity, DriveRole, DriveSet, IDENTITY_FORMAT, classify_drive,
    layout_folders, same_device, write_identity,
};
use super::fsio::{Dir, EntryKind, WriteMode};
use super::ids::DriveId;
use super::paths::{AUDIT_LOG_FILE, BINARY_HASH_FILE, IDENTITY_FILE, KEYSTONE_DIR, STAGING_DIR};
use crate::crypto::hash::sha256;
use crate::limits::{MAX_AUDIT_LOG_BYTES, MAX_METADATA_BYTES};
use crate::model::Timestamp;

/// What the new drive holds before the copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewDriveState {
    /// Nothing (an empty drive).
    Empty,
    /// Part of a copy of this CA, from an interrupted earlier attempt (no identity yet):
    /// every file on it equals the source's. The copy continues.
    PartialCopy,
    /// A complete copy of this CA with its identity, from an attempt interrupted before
    /// the audit entries: only the entries are written.
    CopiedNotRecorded(DriveId),
}

/// What [`DriveSet::add_drive`] will do. Nothing was written to make it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddDrivePlan {
    /// The new drive's mount point.
    pub target: PathBuf,
    /// What the new drive holds now.
    pub state: NewDriveState,
    /// Index (into [`DriveSet::drives`]) of the drive copied from.
    pub source: usize,
    /// Label of the drive copied from.
    pub source_label: String,
    /// The backup drive that becomes the primary, when no primary is connected.
    pub promote: Option<DriveId>,
    /// Its label.
    pub promote_label: Option<String>,
    /// Number of journaled operations copied.
    pub operations: usize,
    /// Number of output files copied (certificates, encrypted keys, CRLs, records).
    pub files: usize,
    /// Number of audit entries copied.
    pub audit_entries: usize,
}

/// Device and inode of a folder.
fn folder_identity(path: &Path) -> Result<(u64, u64), StoreError> {
    Dir::open(path)?.identity()
}

impl DriveSet {
    /// Plans copying this CA to a new drive at `target` (see the module documentation).
    /// Refuses while the connected drives are not in sync, while an operation is
    /// interrupted, and for a target that is not empty (except an interrupted copy of
    /// this CA), is one of the connected drives, or is on the same device as one of them
    /// (SEC-11). The target need not be a mount point: a folder on the new drive is fine.
    pub fn plan_add_drive(&self, target: &Path) -> Result<AddDrivePlan, StoreError> {
        match self.compare()? {
            DriveComparison::InSync => {}
            DriveComparison::Damaged { problems } => return Err(StoreError::Damaged(problems)),
            DriveComparison::Behind { .. } => {
                return Err(StoreError::OutOfSync(
                    "some connected drives are behind; repair them before adding a drive".into(),
                ));
            }
            DriveComparison::Diverged { .. } => {
                return Err(StoreError::OutOfSync(
                    "the connected drives hold different histories; nothing is copied while they diverge".into(),
                ));
            }
        }
        let report = self.recovery_report()?;
        if let Some(pending) = report.pending.first() {
            return Err(StoreError::PendingOperation(pending.operation));
        }
        if let Some(problem) = report.unreadable.first() {
            return Err(StoreError::Damaged(vec![problem.clone()]));
        }
        let target_folder = folder_identity(target)?;
        for drive in self.drives() {
            if folder_identity(drive.root())? == target_folder
                || drive.keystone().identity()? == target_folder
            {
                return Err(StoreError::DriveSet(format!(
                    "{} is {}; choose a new, empty drive",
                    target.display(),
                    drive.label()
                )));
            }
            // SEC-11: the new drive must be a separate device (a folder on it is fine).
            if same_device(target, drive.root())? {
                return Err(StoreError::DriveSet(format!(
                    "this folder ({}) is on the same device as the {}; choose a folder on a new, separate USB drive",
                    target.display(),
                    drive.label()
                )));
            }
        }
        let source = &self.drives()[0];
        let log = source.audit_log()?;
        let state = match classify_drive(target)? {
            DriveClass::Empty => NewDriveState::Empty,
            DriveClass::DamagedKeystone(_) if is_partial_copy(target, source, &log)? => {
                NewDriveState::PartialCopy
            }
            DriveClass::KeystoneCa(identity)
                if identity.ca_id == self.ca_id()
                    && identity.role == DriveRole::Backup
                    && !log.entries().iter().any(|entry| {
                        entry
                            .details
                            .as_ref()
                            .is_some_and(|d| d.drive_added == Some(identity.drive_id))
                    }) =>
            {
                let copy = CaDrive::open(target)?;
                verify_copy(&copy, source)?;
                NewDriveState::CopiedNotRecorded(identity.drive_id)
            }
            DriveClass::KeystoneCa(_) | DriveClass::DamagedKeystone(_) => {
                return Err(StoreError::DriveHoldsCa {
                    root: target.to_path_buf(),
                });
            }
            DriveClass::KeystoneExport | DriveClass::Other => {
                return Err(StoreError::DriveNotEmpty {
                    root: target.to_path_buf(),
                });
            }
        };
        let promote = (source.role() != DriveRole::Primary).then_some(source);
        let journals = source.journal()?;
        Ok(AddDrivePlan {
            target: target.to_path_buf(),
            state,
            source: 0,
            source_label: source.label(),
            promote: promote.map(|drive| drive.identity().drive_id),
            promote_label: promote.map(CaDrive::label),
            operations: journals.len(),
            files: journals
                .values()
                .map(|journal| journal.completed_outputs().unwrap_or_default().len())
                .sum(),
            audit_entries: log.len(),
        })
    }

    /// Carries out a plan the operator reviewed ([`DriveSet::plan_add_drive`], recomputed
    /// first and required to be unchanged) and returns the drive set with the new drive.
    /// `time` is the confirmed time: the new identity's creation time and the audit
    /// entries' time.
    pub fn add_drive(&self, plan: &AddDrivePlan, time: Timestamp) -> Result<DriveSet, StoreError> {
        if self.plan_add_drive(&plan.target)? != *plan {
            return Err(StoreError::Unsafe(
                "the drives changed since the copy was shown; check them again".into(),
            ));
        }
        let source = &self.drives()[plan.source];
        let drive_id = match plan.state {
            NewDriveState::CopiedNotRecorded(drive_id) => drive_id,
            NewDriveState::Empty | NewDriveState::PartialCopy => {
                let identity = DriveIdentity {
                    format: IDENTITY_FORMAT,
                    ca_id: self.ca_id(),
                    drive_id: DriveId::random()?,
                    role: DriveRole::Backup,
                    created: whole(time)?,
                };
                let keystone = Dir::open(&plan.target)?.ensure_dir(KEYSTONE_DIR)?;
                for name in layout_folders() {
                    keystone.ensure_dir(name)?;
                }
                let copy = CaDrive::provisional(&plan.target, keystone, identity.clone());
                copy_everything(source, &copy)?;
                verify_copy(&copy, source)?;
                // Last: from now on the new drive is a drive of this CA.
                write_identity(&plan.target, copy.keystone(), &identity)?;
                identity.drive_id
            }
        };
        let mut roots: Vec<&Path> = self.drives().iter().map(CaDrive::root).collect();
        roots.push(&plan.target);
        let set = DriveSet::open(&roots)?;
        let mut drafts = Vec::new();
        let mut added = AuditDraft::new(AuditAction::DriveRepair, "", AuditResult::Success);
        added.details = Some(AuditDetails {
            drive_added: Some(drive_id),
            note: Some(format!(
                "new backup drive {} added to replace a lost drive: {} operations, {} files and {} audit entries copied from {} and verified",
                drive_id.short(),
                plan.operations,
                plan.files,
                plan.audit_entries,
                plan.source_label
            )),
            ..AuditDetails::default()
        });
        drafts.push(added);
        if let Some(promoted) = plan.promote {
            let mut draft = AuditDraft::new(AuditAction::DriveRepair, "", AuditResult::Success);
            draft.details = Some(AuditDetails {
                primary_promoted: Some(promoted),
                note: Some(format!(
                    "no primary drive was connected (the primary was lost): backup drive {} is now the primary",
                    promoted.short()
                )),
                ..AuditDetails::default()
            });
            drafts.push(draft);
        }
        set.append_audit_unchecked(&drafts, time)?;
        DriveSet::open(&roots)
    }

    /// [`DriveSet::append_audit`] without the primary-and-backup rule: only for the
    /// entries that record a replacement drive (and a promotion), which is how a CA with
    /// a lost primary or a lost only backup gets them back.
    fn append_audit_unchecked(
        &self,
        drafts: &[AuditDraft],
        time: Timestamp,
    ) -> Result<(), StoreError> {
        let log = self.audit_log()?;
        let (bytes, _) = log
            .with_appended(drafts, time)
            .map_err(|source| StoreError::Parse {
                path: self.drives()[0].keystone().child(AUDIT_LOG_FILE),
                source,
            })?;
        for drive in self.drives() {
            drive.write_one_verified("", AUDIT_LOG_FILE, &bytes, WriteMode::Replace)?;
        }
        Ok(())
    }
}

fn whole(time: Timestamp) -> Result<Timestamp, StoreError> {
    time.get()
        .replace_nanosecond(0)
        .map(Timestamp::utc)
        .map_err(|e| StoreError::Unsafe(e.to_string()))
}

/// Copies every operation (journal entries, completed outputs, final entry), the audit
/// log and the binary-hash record from `source` to the new drive. Every write is
/// create-only (the audit log only grows) and verified by read-back.
fn copy_everything(source: &CaDrive, copy: &CaDrive) -> Result<(), StoreError> {
    for journal in source.journal()?.values() {
        copy_journal_entries(source, copy, journal, false)?;
        for output in journal.completed_outputs().unwrap_or_default() {
            copy_output(source, copy, output)?;
        }
        copy_journal_entries(source, copy, journal, true)?;
    }
    let log = source.audit_log()?;
    extend_log(copy, &log, log.len() as u64)?;
    if let Some(record) = source
        .keystone()
        .read_if_exists(BINARY_HASH_FILE, MAX_METADATA_BYTES)?
        && copy
            .keystone()
            .read_if_exists(BINARY_HASH_FILE, MAX_METADATA_BYTES)?
            .as_ref()
            != Some(&record)
    {
        copy.write_one_verified("", BINARY_HASH_FILE, &record, WriteMode::Replace)?;
    }
    Ok(())
}

/// The new drive holds exactly what `source` holds: every journal byte for byte, every
/// completed output with its SHA-256, the same verified audit log with every journal's
/// audit head in it, and the same binary-hash record.
fn verify_copy(copy: &CaDrive, source: &CaDrive) -> Result<(), StoreError> {
    let differs = |what: String| {
        StoreError::Unsafe(format!(
            "the copy on {} is not complete: {what}",
            copy.root().display()
        ))
    };
    let ours = copy.journal()?;
    let theirs = source.journal()?;
    if ours.keys().ne(theirs.keys()) {
        return Err(differs("the operation journals differ".into()));
    }
    for (operation, journal) in &theirs {
        if ours[operation].raw_entries() != journal.raw_entries() {
            return Err(differs(format!("the journal of {operation} differs")));
        }
    }
    let log = source.audit_log()?;
    if copy.audit_log()? != log {
        return Err(differs("the audit log differs".into()));
    }
    let problems = drive_problems(copy, &log)?;
    if let Some(problem) = problems.first() {
        return Err(differs(problem.clone()));
    }
    let record = |drive: &CaDrive| {
        drive
            .keystone()
            .read_if_exists(BINARY_HASH_FILE, MAX_METADATA_BYTES)
    };
    if record(copy)? != record(source)? {
        return Err(differs("the binary hash record differs".into()));
    }
    Ok(())
}

/// True when every file under `target`'s `keystone/` folder is part of a copy of
/// `source`: the same bytes at the same place (the audit log a byte prefix of the
/// source's; the binary-hash record may be older), no drive identity, no staging
/// content, nothing else. Temporary files of cut-off writes are ignored.
fn is_partial_copy(
    target: &Path,
    source: &CaDrive,
    log: &super::audit::AuditLog,
) -> Result<bool, StoreError> {
    let top = Dir::open(target)?;
    let entries: Vec<(String, EntryKind)> = top
        .entries()?
        .into_iter()
        .filter(|(name, kind)| !(name == "lost+found" && *kind == EntryKind::Dir))
        .collect();
    if entries != [(KEYSTONE_DIR.to_string(), EntryKind::Dir)] {
        return Ok(false);
    }
    let mut pending = vec![String::new()];
    while let Some(rel) = pending.pop() {
        let dir = top.open_dir(KEYSTONE_DIR)?;
        let dir = if rel.is_empty() {
            dir
        } else {
            dir.open_dir(&rel)?
        };
        for (name, kind) in dir.entries()? {
            let path = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            match kind {
                EntryKind::File if name.starts_with('.') => {}
                EntryKind::Dir if rel.is_empty() && name == STAGING_DIR => {
                    if !dir.open_dir(&name)?.entries()?.is_empty() {
                        return Ok(false);
                    }
                }
                EntryKind::Dir => {
                    if source.dir_at(&path, false)?.is_none()
                        && !(rel.is_empty() && layout_folders().any(|folder| folder == name))
                    {
                        return Ok(false);
                    }
                    pending.push(path);
                }
                EntryKind::File if rel.is_empty() && name == IDENTITY_FILE => return Ok(false),
                EntryKind::File if rel.is_empty() && name == AUDIT_LOG_FILE => {
                    let ours = dir.read(&name, MAX_AUDIT_LOG_BYTES)?;
                    if !log.as_bytes().starts_with(&ours) {
                        return Ok(false);
                    }
                }
                EntryKind::File if rel.is_empty() && name == BINARY_HASH_FILE => {}
                EntryKind::File => {
                    let ours = dir.read(&name, MAX_AUDIT_LOG_BYTES)?;
                    let theirs = source.read_at(&rel, &name, MAX_AUDIT_LOG_BYTES)?;
                    if theirs.is_none_or(|theirs| sha256(&theirs) != sha256(&ours)) {
                        return Ok(false);
                    }
                }
                EntryKind::Other => return Ok(false),
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
