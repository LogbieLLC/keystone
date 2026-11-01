//! Drive comparison and repair (FR-12 AC3, FR-19 AC1, SEC-09, SEC-22).
//!
//! At start the drives are compared by their audit logs:
//! - all logs equal: [`DriveComparison::InSync`];
//! - every log is an exact prefix of the longest (same entries and hashes, only fewer):
//!   [`DriveComparison::Behind`] with a [`RepairPlan`] per behind drive. After the operator
//!   confirms, [`DriveSet::repair`] copies each missing operation *whole*: its journal
//!   entries, every output file its completed entry lists (each verified against that
//!   SHA-256), its audit entries, and **last** its final journal entry, so copying a log
//!   entry can never make an incomplete drive look repaired;
//! - logs differ after a common point: [`DriveComparison::Diverged`], with every history
//!   side by side. Signing is blocked. Keystone never chooses a history, by length or
//!   otherwise;
//! - a log that does not verify, a journal whose recorded audit head is not in the log,
//!   or a completed operation's output that is missing or changed:
//!   [`DriveComparison::Damaged`]. Signing is blocked.
#![forbid(unsafe_code)]

use super::StoreError;
use super::audit::{AuditAction, AuditDetails, AuditDraft, AuditEntry, AuditLog, AuditResult};
use super::drive::{CaDrive, DriveSet};
use super::fsio::WriteMode;
use super::ids::OperationId;
use super::journal::{OperationJournal, OutputFile};
use super::paths::{AUDIT_LOG_FILE, JOURNAL_DIR};
use crate::crypto::hash::sha256;
use crate::limits::MAX_OUTPUT_FILE_BYTES;
use crate::model::Timestamp;

/// One history as shown side by side when logs diverge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveHistory {
    /// Labels of the drives holding this history.
    pub drives: Vec<String>,
    /// Entries after the common point.
    pub entries: Vec<AuditEntry>,
}

/// One step of a repair: copy one operation whole, or audit entries that belong to no
/// operation (for example a clock correction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairStep {
    /// Copy an operation whole; its final journal entry is written last.
    Operation {
        /// The operation.
        operation: OperationId,
        /// Its audit entries (shown to the operator).
        entries: Vec<AuditEntry>,
        /// Output files its completed entry lists (empty for cancelled or abandoned).
        outputs: Vec<OutputFile>,
        /// Number of journal entry files copied (including the final one).
        journal_entries: usize,
    },
    /// Copy audit entries that belong to no operation.
    AuditOnly {
        /// The entries.
        entries: Vec<AuditEntry>,
    },
}

impl RepairStep {
    fn last_seq(&self) -> u64 {
        let entries = match self {
            RepairStep::Operation { entries, .. } | RepairStep::AuditOnly { entries } => entries,
        };
        entries.last().map_or(0, |entry| entry.seq)
    }
}

/// How to bring one behind drive up to date (FR-12 AC3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPlan {
    /// Index (into [`DriveSet::drives`]) of the drive copied from.
    pub source: usize,
    /// Index of the behind drive.
    pub target: usize,
    /// Label of the source drive.
    pub source_label: String,
    /// Label of the behind drive.
    pub target_label: String,
    /// The missing operations, oldest first.
    pub steps: Vec<RepairStep>,
}

/// Result of comparing the drives (FR-12 AC3, FR-19 AC1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveComparison {
    /// Every drive holds the same audit log.
    InSync,
    /// Some drives are behind; each plan needs the operator's confirmation.
    Behind {
        /// One plan per behind drive.
        plans: Vec<RepairPlan>,
    },
    /// The logs differ after a common point. Signing is blocked.
    Diverged {
        /// Number of leading entries every drive shares.
        common: usize,
        /// Every distinct history after that point, side by side.
        histories: Vec<DriveHistory>,
    },
    /// Something cannot be verified. Signing is blocked.
    Damaged {
        /// One plain sentence per problem.
        problems: Vec<String>,
    },
}

impl DriveComparison {
    /// Signing is allowed only when every drive holds the same verified history.
    pub fn signing_allowed(&self) -> bool {
        matches!(self, DriveComparison::InSync)
    }
}

/// Integrity problems of one drive: journal heads missing from the log (FR-14) and
/// completed outputs that are missing or changed (FR-22 AC2).
fn drive_problems(drive: &CaDrive, log: &AuditLog) -> Result<Vec<String>, StoreError> {
    let mut problems = Vec::new();
    for (operation, journal) in drive.journal()? {
        if let Some(head) = journal.audit_head()
            && log.entry_hash(head.seq) != Some(head.sha256)
        {
            problems.push(format!(
                "{}: the journal of {operation} records audit entry {} which is missing or changed in the audit log",
                drive.label(),
                head.seq
            ));
        }
        for output in journal.completed_outputs().unwrap_or_default() {
            let data = drive.read_at(
                output.path.dir().name(),
                output.path.name(),
                MAX_OUTPUT_FILE_BYTES,
            )?;
            match data {
                None => problems.push(format!(
                    "{}: {} of {operation} is missing",
                    drive.label(),
                    output.path
                )),
                Some(data) if sha256(&data) != output.sha256 => problems.push(format!(
                    "{}: {} of {operation} was changed (SHA-256 differs from its completed entry)",
                    drive.label(),
                    output.path
                )),
                Some(_) => {}
            }
        }
    }
    Ok(problems)
}

impl DriveSet {
    /// Compares the drives (FR-12 AC3, FR-19 AC1, SEC-09). Run at every start.
    pub fn compare(&self) -> Result<DriveComparison, StoreError> {
        let mut logs = Vec::new();
        let mut problems = Vec::new();
        for drive in self.drives() {
            match drive.audit_log() {
                Ok(log) => {
                    problems.extend(drive_problems(drive, &log)?);
                    logs.push(log);
                }
                Err(StoreError::Parse { source, .. }) => {
                    problems.push(format!("{}: {source}", drive.label()));
                    logs.push(AuditLog::empty());
                }
                Err(error) => return Err(error),
            }
        }
        if !problems.is_empty() {
            return Ok(DriveComparison::Damaged { problems });
        }
        let longest = (0..logs.len())
            .max_by_key(|index| (logs[*index].len(), std::cmp::Reverse(*index)))
            .unwrap_or(0);
        if logs.iter().all(|log| log.is_prefix_of(&logs[longest])) {
            let mut plans = Vec::new();
            for (target, log) in logs.iter().enumerate() {
                if log.len() < logs[longest].len() {
                    plans.push(self.plan_repair(longest, target)?);
                }
            }
            return Ok(if plans.is_empty() {
                DriveComparison::InSync
            } else {
                DriveComparison::Behind { plans }
            });
        }
        let common = logs
            .iter()
            .map(|log| log.common_prefix_len(&logs[0]))
            .min()
            .unwrap_or(0);
        let mut histories: Vec<(AuditLog, DriveHistory)> = Vec::new();
        for (drive, log) in self.drives().iter().zip(&logs) {
            if let Some((_, history)) = histories.iter_mut().find(|(known, _)| known == log) {
                history.drives.push(drive.label());
            } else {
                histories.push((
                    log.clone(),
                    DriveHistory {
                        drives: vec![drive.label()],
                        entries: log.entries()[common..].to_vec(),
                    },
                ));
            }
        }
        Ok(DriveComparison::Diverged {
            common,
            histories: histories.into_iter().map(|(_, history)| history).collect(),
        })
    }

    /// Plans copying everything `target` misses from `source` (whose log `target`'s log
    /// must be an exact prefix of).
    pub(crate) fn plan_repair(
        &self,
        source: usize,
        target: usize,
    ) -> Result<RepairPlan, StoreError> {
        let (src, dst) = (&self.drives()[source], &self.drives()[target]);
        let (src_log, dst_log) = (src.audit_log()?, dst.audit_log()?);
        if !dst_log.is_prefix_of(&src_log) {
            return Err(StoreError::Unsafe(format!(
                "{} is not an exact prefix of {}; it cannot be repaired automatically",
                dst.label(),
                src.label()
            )));
        }
        let missing = &src_log.entries()[dst_log.len()..];
        let mut steps: Vec<RepairStep> = Vec::new();
        let mut index = 0;
        while index < missing.len() {
            let operation = missing[index].operation;
            let run = missing[index..]
                .iter()
                .take_while(|entry| entry.operation == operation)
                .count();
            let entries = missing[index..index + run].to_vec();
            index += run;
            let Some(operation) = operation else {
                steps.push(RepairStep::AuditOnly { entries });
                continue;
            };
            let seen_before = steps.iter().any(|step| {
                matches!(step, RepairStep::Operation { operation: op, .. } if *op == operation)
            }) || dst_log.entries().iter().any(|e| e.operation == Some(operation));
            if seen_before {
                return Err(StoreError::Unsafe(format!(
                    "the audit entries of {operation} are not in one block; it cannot be repaired automatically"
                )));
            }
            let journal = src.operation_journal(operation)?.ok_or_else(|| {
                StoreError::Unsafe(format!("{} has no journal for {operation}", src.label()))
            })?;
            let last = entries.last().map_or(0, |entry| entry.seq);
            if journal.audit_head().map(|head| head.seq) != Some(last) {
                return Err(StoreError::Unsafe(format!(
                    "{operation} is not finished on {}; open the recovery screen first",
                    src.label()
                )));
            }
            check_target_journal(dst, operation, &journal)?;
            let outputs = journal.completed_outputs().unwrap_or_default().to_vec();
            for output in &outputs {
                let data = src.read_at(
                    output.path.dir().name(),
                    output.path.name(),
                    MAX_OUTPUT_FILE_BYTES,
                )?;
                if data.is_none_or(|data| sha256(&data) != output.sha256) {
                    return Err(StoreError::Unsafe(format!(
                        "{} of {operation} is missing or changed on {}; it cannot be copied",
                        output.path,
                        src.label()
                    )));
                }
                let existing = dst.read_at(
                    output.path.dir().name(),
                    output.path.name(),
                    MAX_OUTPUT_FILE_BYTES,
                )?;
                if existing.is_some_and(|data| sha256(&data) != output.sha256) {
                    return Err(StoreError::Unsafe(format!(
                        "{} already holds a different {}; it is never overwritten",
                        dst.label(),
                        output.path
                    )));
                }
            }
            steps.push(RepairStep::Operation {
                operation,
                entries,
                outputs,
                journal_entries: journal.entries().len(),
            });
        }
        Ok(RepairPlan {
            source,
            target,
            source_label: src.label(),
            target_label: dst.label(),
            steps,
        })
    }

    /// FR-12 AC3: carries out the plans the operator confirmed (from
    /// [`DriveComparison::Behind`]). Each plan is recomputed first and must be unchanged.
    /// Each operation is copied whole and verified, with its final journal entry written
    /// last. When every drive holds the same log again, one `drive_repair` entry is
    /// appended on every drive. Nothing is deleted or overwritten.
    pub fn repair(&self, plans: &[RepairPlan], time: Timestamp) -> Result<(), StoreError> {
        self.ensure_writable()?;
        let mut notes = Vec::new();
        for plan in plans {
            if self.plan_repair(plan.source, plan.target)? != *plan {
                return Err(StoreError::Unsafe(
                    "the drives changed since the repair was shown; compare them again".to_string(),
                ));
            }
            let copied = self.repair_one(plan)?;
            let entries: usize =
                plan.steps
                    .iter()
                    .map(|step| match step {
                        RepairStep::Operation { entries, .. }
                        | RepairStep::AuditOnly { entries } => entries.len(),
                    })
                    .sum();
            notes.push(format!(
                "copied {copied} operation(s) and {entries} audit entries from {} to {}",
                plan.source_label, plan.target_label
            ));
        }
        let mut draft = AuditDraft::new(AuditAction::DriveRepair, "", AuditResult::Success);
        draft.details = Some(AuditDetails {
            note: Some(notes.join("; ")),
            ..AuditDetails::default()
        });
        self.append_audit(&[draft], time)?;
        Ok(())
    }

    fn repair_one(&self, plan: &RepairPlan) -> Result<usize, StoreError> {
        let (src, dst) = (&self.drives()[plan.source], &self.drives()[plan.target]);
        let src_log = src.audit_log()?;
        let mut copied = 0usize;
        for step in &plan.steps {
            let journal = match step {
                RepairStep::Operation { operation, .. } => Some(
                    src.operation_journal(*operation)?
                        .ok_or_else(|| StoreError::Unsafe(format!("{operation} disappeared")))?,
                ),
                RepairStep::AuditOnly { .. } => None,
            };
            if let (Some(journal), RepairStep::Operation { outputs, .. }) = (&journal, step) {
                copy_journal_entries(src, dst, journal, false)?;
                for output in outputs {
                    copy_output(src, dst, output)?;
                }
            }
            extend_log(dst, &src_log, step.last_seq())?;
            if let Some(journal) = &journal {
                copy_journal_entries(src, dst, journal, true)?;
                copied += 1;
            }
        }
        Ok(copied)
    }
}

/// The target's journal for `operation` must be a byte-identical prefix of the source's,
/// without its final entry.
fn check_target_journal(
    dst: &CaDrive,
    operation: OperationId,
    source: &OperationJournal,
) -> Result<(), StoreError> {
    if let Some(existing) = dst.operation_journal(operation)? {
        let ours = existing.raw_entries();
        let theirs = source.raw_entries();
        if existing.terminal().is_some()
            || ours.len() > theirs.len()
            || ours.iter().zip(theirs).any(|(a, b)| a != b)
        {
            return Err(StoreError::Unsafe(format!(
                "{} holds a different journal for {operation}; it cannot be repaired automatically",
                dst.label()
            )));
        }
    }
    Ok(())
}

/// Copies journal entries missing on `dst` (create-only, verified). With `terminal` false
/// the final entry is skipped; with `terminal` true only the final entry is copied.
pub(crate) fn copy_journal_entries(
    src: &CaDrive,
    dst: &CaDrive,
    journal: &OperationJournal,
    terminal: bool,
) -> Result<(), StoreError> {
    let rel = format!("{JOURNAL_DIR}/{}", journal.operation().stem());
    let has_terminal = journal.terminal().is_some();
    let count = journal.entries().len();
    for (index, (entry, raw)) in journal
        .entries()
        .iter()
        .zip(journal.raw_entries())
        .enumerate()
    {
        let is_terminal = has_terminal && index + 1 == count;
        if is_terminal != terminal {
            continue;
        }
        let name = entry.file_name();
        match dst.read_at(&rel, &name, raw.len().max(1))? {
            Some(existing) if existing == *raw => {}
            Some(_) => {
                return Err(StoreError::Unsafe(format!(
                    "{} holds a different {rel}/{name} than {}",
                    dst.label(),
                    src.label()
                )));
            }
            None => dst.write_one_verified(&rel, &name, raw, WriteMode::CreateOnly)?,
        }
    }
    Ok(())
}

/// Copies one output file from `src` to `dst` (create-only), verified against `output`.
pub(crate) fn copy_output(
    src: &CaDrive,
    dst: &CaDrive,
    output: &OutputFile,
) -> Result<(), StoreError> {
    let (dir, name) = (output.path.dir().name(), output.path.name());
    if let Some(existing) = dst.read_at(dir, name, MAX_OUTPUT_FILE_BYTES)? {
        if sha256(&existing) == output.sha256 {
            return Ok(());
        }
        return Err(StoreError::Unsafe(format!(
            "{} already holds a different {}; it is never overwritten",
            dst.label(),
            output.path
        )));
    }
    let data = src
        .read_at(dir, name, MAX_OUTPUT_FILE_BYTES)?
        .filter(|data| sha256(data) == output.sha256)
        .ok_or_else(|| {
            StoreError::Unsafe(format!(
                "{} is missing or changed on {}",
                output.path,
                src.label()
            ))
        })?;
    dst.write_one_verified(dir, name, &data, WriteMode::CreateOnly)
}

/// Extends `dst`'s audit log to the first `seq` entries of `source` (whose prefix it must
/// already be). Atomic replace; verified by read-back.
pub(crate) fn extend_log(dst: &CaDrive, source: &AuditLog, seq: u64) -> Result<(), StoreError> {
    let current = dst.audit_log()?;
    let count = usize::try_from(seq).unwrap_or(usize::MAX);
    if current.len() >= count {
        return Ok(());
    }
    let bytes = source.prefix_bytes(count);
    if !bytes.starts_with(current.as_bytes()) {
        return Err(StoreError::Unsafe(format!(
            "{} no longer holds a prefix of the source log",
            dst.label()
        )));
    }
    dst.write_one_verified("", AUDIT_LOG_FILE, bytes, WriteMode::Replace)
}

#[cfg(test)]
mod tests;
