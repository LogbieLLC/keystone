//! Operation journal (FR-22 AC1-AC3, AC7 data layer, SEC-22). Sensitive code
//! (GOVERNANCE.md section 3).
//!
//! Each operation that changes CA state has a folder `keystone/journal/op-NNNNNN/` on
//! every CA drive. Each entry is its own immutable, create-only file
//! `<step:03>-<kind>.json` holding one [`JournalEntry`]:
//!
//! | kind           | when it is written                                                    |
//! |----------------|-----------------------------------------------------------------------|
//! | `pending`      | step 1, before the first irreversible step; records planned serials   |
//! | `yubikey-step` | after each YubiKey setup step (PIN, PUK, management key, key, cert)   |
//! | `signed`       | right after a certificate or CRL is signed (FR-22 AC3)                |
//! | `staged`       | after every output is staged and verified: paths, SHA-256, sizes      |
//! | `completed`    | last: SHA-256 of every output file and its own last audit entry       |
//! | `cancelled`    | FR-16 cancel before any persistent change; the serial stays reserved  |
//! | `abandoned`    | FR-22 AC4: no signed output exists anywhere; the serial stays reserved|
//!
//! The journal never stores a PIN, PUK, management key or passphrase: a YubiKey step
//! records only which step finished and the device serial number.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::audit::MAX_AUDIT_TEXT;
use super::drive::{CaDrive, check_len, check_timestamp};
use super::ids::OperationId;
use super::paths::{JOURNAL_DIR, OutputPath};
use super::record::CertificateRecord;
use super::{ParseError, StoreError};
use crate::limits::{MAX_JOURNAL_ENTRY_BYTES, MAX_OUTPUT_FILE_BYTES, MAX_PEM_BYTES};
use crate::model::{Serial, Sha256Digest, Timestamp};

/// Current version of the journal entry format.
pub const JOURNAL_FORMAT: u32 = 1;
/// Highest step number (three-digit file prefix).
pub const MAX_STEP: u32 = 999;
/// Most planned serials in one operation.
pub const MAX_PLANNED_SERIALS: usize = 64;
/// Most output files in one operation.
pub const MAX_OUTPUTS: usize = 256;

/// Kinds of operations that change CA state (FR-22 AC1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// Flow A.
    CreateMaster,
    /// Flow B: YubiKey hardening, on-device key, main intermediate, first CRL.
    SetupYubikey,
    /// Flow C.
    CreateSubIntermediate,
    /// Flow D.
    Revoke,
    /// FR-13 AC4.
    RefreshCrl,
    /// Flow E steps 1, 2 and 4 (revoke the old main intermediate, mark its children).
    ReplaceYubikey,
}

/// YubiKey setup steps, in order (FR-22 AC7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum YubikeySetupStep {
    /// The PIN was changed from the default.
    PinChanged,
    /// The PUK was changed from the default.
    PukChanged,
    /// A random PIN-protected AES-256 management key was set.
    ManagementKeySet,
    /// The RSA 4,096 key was generated on the YubiKey.
    KeyGenerated,
    /// The signed main-intermediate certificate was written to the slot.
    CertificateWritten,
}

impl YubikeySetupStep {
    /// Every step, in order.
    pub const ALL: [YubikeySetupStep; 5] = [
        YubikeySetupStep::PinChanged,
        YubikeySetupStep::PukChanged,
        YubikeySetupStep::ManagementKeySet,
        YubikeySetupStep::KeyGenerated,
        YubikeySetupStep::CertificateWritten,
    ];
}

/// An output file and its SHA-256 (FR-22 AC2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputFile {
    /// Where it is placed inside `keystone/`.
    pub path: OutputPath,
    /// SHA-256 of its content.
    pub sha256: Sha256Digest,
    /// Size in bytes.
    pub size: u64,
}

/// An operation's own last audit entry, recorded by its final journal entry. Entries of
/// no operation appended later never change it (a behind drive stays repairable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditHead {
    /// Number of entries (the newest entry's `seq`).
    pub seq: u64,
    /// SHA-256 of the newest entry's canonical form.
    pub sha256: Sha256Digest,
}

/// A signed CRL, journaled right after signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCrl {
    /// Serial of the issuing certificate.
    pub issuer_serial: Serial,
    /// CRL number.
    pub crl_number: u64,
    /// thisUpdate.
    pub this_update: Timestamp,
    /// nextUpdate.
    pub next_update: Timestamp,
    /// SHA-256 of the DER CRL.
    pub sha256: Sha256Digest,
    /// The CRL (PEM).
    pub pem: String,
}

/// Something that was signed (FR-22 AC3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SignedObject {
    /// A certificate with everything the issuance record needs.
    Certificate {
        /// The record entry.
        record: Box<CertificateRecord>,
        /// The certificate (PEM).
        pem: String,
    },
    /// A CRL.
    Crl(Box<SignedCrl>),
}

/// What a journal entry records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum JournalEvent {
    /// Step 1: the operation began.
    Pending {
        /// Which operation.
        kind: OperationKind,
        /// Subject shown to the operator.
        subject: String,
        /// Serial numbers reserved by this operation (FR-22 AC1, FR-10 AC2).
        planned_serials: Vec<Serial>,
    },
    /// A YubiKey setup step finished (FR-22 AC7). No secret is stored.
    YubikeyStep {
        /// The step.
        step: YubikeySetupStep,
        /// The YubiKey's serial number.
        device_serial: u32,
    },
    /// Something was signed (FR-22 AC3).
    Signed {
        /// What.
        object: SignedObject,
    },
    /// Every output was staged and verified (FR-22 AC2).
    Staged {
        /// The outputs.
        outputs: Vec<OutputFile>,
    },
    /// Written last (FR-22 AC2).
    Completed {
        /// The outputs (the same list as `staged`).
        outputs: Vec<OutputFile>,
        /// This operation's own last audit entry.
        audit: AuditHead,
    },
    /// Cancelled before any persistent change (FR-16).
    Cancelled {
        /// This operation's own last audit entry (the cancel entry).
        audit: AuditHead,
    },
    /// Abandoned on the recovery screen (FR-22 AC4).
    Abandoned {
        /// This operation's own last audit entry (the abandon entry).
        audit: AuditHead,
    },
}

impl JournalEvent {
    /// The kind used in the file name.
    pub fn tag(&self) -> &'static str {
        match self {
            JournalEvent::Pending { .. } => "pending",
            JournalEvent::YubikeyStep { .. } => "yubikey-step",
            JournalEvent::Signed { .. } => "signed",
            JournalEvent::Staged { .. } => "staged",
            JournalEvent::Completed { .. } => "completed",
            JournalEvent::Cancelled { .. } => "cancelled",
            JournalEvent::Abandoned { .. } => "abandoned",
        }
    }

    /// True for `completed`, `cancelled` and `abandoned`.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            JournalEvent::Completed { .. }
                | JournalEvent::Cancelled { .. }
                | JournalEvent::Abandoned { .. }
        )
    }

    fn validate(&self, step: u32) -> Result<(), String> {
        if matches!(self, JournalEvent::Pending { .. }) != (step == 1) {
            return Err("the pending entry must be step 1, and only step 1".to_string());
        }
        match self {
            JournalEvent::Pending {
                subject,
                planned_serials,
                ..
            } => {
                if subject.len() > MAX_AUDIT_TEXT {
                    return Err("subject is too long".to_string());
                }
                let unique: BTreeSet<_> = planned_serials.iter().collect();
                if planned_serials.len() > MAX_PLANNED_SERIALS
                    || unique.len() != planned_serials.len()
                {
                    return Err("invalid planned serials".to_string());
                }
            }
            JournalEvent::YubikeyStep { .. } => {}
            JournalEvent::Signed { object } => match object {
                SignedObject::Certificate { record, pem } => {
                    record.validate()?;
                    check_pem(pem)?;
                }
                SignedObject::Crl(crl) => {
                    check_timestamp(crl.this_update, "this_update").map_err(|e| e.to_string())?;
                    check_timestamp(crl.next_update, "next_update").map_err(|e| e.to_string())?;
                    if crl.next_update <= crl.this_update {
                        return Err("nextUpdate must be after thisUpdate".to_string());
                    }
                    check_pem(&crl.pem)?;
                }
            },
            JournalEvent::Staged { outputs } | JournalEvent::Completed { outputs, .. } => {
                validate_outputs(outputs)?;
            }
            JournalEvent::Cancelled { .. } | JournalEvent::Abandoned { .. } => {}
        }
        Ok(())
    }
}

fn check_pem(pem: &str) -> Result<(), String> {
    if pem.is_empty() || pem.len() > MAX_PEM_BYTES {
        return Err("invalid PEM text".to_string());
    }
    Ok(())
}

fn validate_outputs(outputs: &[OutputFile]) -> Result<(), String> {
    let paths: BTreeSet<_> = outputs.iter().map(|output| &output.path).collect();
    if outputs.len() > MAX_OUTPUTS || paths.len() != outputs.len() {
        return Err("invalid output list".to_string());
    }
    if outputs
        .iter()
        .any(|output| output.size > MAX_OUTPUT_FILE_BYTES as u64)
    {
        return Err("output file is too large".to_string());
    }
    Ok(())
}

/// One journal entry file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEntry {
    /// Always [`JOURNAL_FORMAT`].
    pub format: u32,
    /// The operation.
    pub operation: OperationId,
    /// 1-based position in the operation's journal.
    pub step: u32,
    /// When it was written (UTC, whole seconds).
    pub time: Timestamp,
    /// What it records.
    pub event: JournalEvent,
}

impl JournalEntry {
    /// The file name: `<step:03>-<kind>.json`.
    pub fn file_name(&self) -> String {
        format!("{:03}-{}.json", self.step, self.event.tag())
    }
}

/// Parses one journal entry file (SEC-08). Never panics on any input.
pub fn parse_journal_entry(bytes: &[u8]) -> Result<JournalEntry, ParseError> {
    check_len(bytes, MAX_JOURNAL_ENTRY_BYTES)?;
    let entry: JournalEntry = serde_json::from_slice(bytes)
        .map_err(|e| ParseError::invalid(format!("journal entry: {e}")))?;
    if entry.format != JOURNAL_FORMAT {
        return Err(ParseError::invalid("unsupported journal format"));
    }
    if !entry.operation.is_valid() || !(1..=MAX_STEP).contains(&entry.step) {
        return Err(ParseError::invalid("invalid operation or step number"));
    }
    check_timestamp(entry.time, "time")?;
    entry
        .event
        .validate(entry.step)
        .map_err(ParseError::Invalid)?;
    Ok(entry)
}

/// State of an operation on one drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationState {
    /// No terminal entry yet: interrupted or still running.
    Pending,
    /// Completed.
    Completed,
    /// Cancelled (FR-16).
    Cancelled,
    /// Abandoned (FR-22 AC4).
    Abandoned,
}

/// The journal of one operation on one drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationJournal {
    operation: OperationId,
    entries: Vec<JournalEntry>,
    raw: Vec<Vec<u8>>,
}

impl OperationJournal {
    /// Checks the order rules and builds the journal from `(entry, raw bytes)` in step order.
    pub(crate) fn from_entries(
        operation: OperationId,
        files: Vec<(JournalEntry, Vec<u8>)>,
    ) -> Result<Self, String> {
        let mut staged: Option<&Vec<OutputFile>> = None;
        for (index, (entry, _)) in files.iter().enumerate() {
            if entry.operation != operation || entry.step as usize != index + 1 {
                return Err(format!("entry {} is out of place", index + 1));
            }
            if entry.event.is_terminal() && index + 1 != files.len() {
                return Err("an entry follows the operation's final entry".to_string());
            }
            match &entry.event {
                JournalEvent::Staged { outputs } => {
                    if staged.is_some() {
                        return Err("the operation was staged twice".to_string());
                    }
                    staged = Some(outputs);
                }
                JournalEvent::Signed { .. } | JournalEvent::YubikeyStep { .. }
                    if staged.is_some() =>
                {
                    return Err("nothing may be signed after staging".to_string());
                }
                JournalEvent::Completed { outputs, .. } if staged.is_some_and(|s| s != outputs) => {
                    return Err("completed outputs differ from staged outputs".to_string());
                }
                JournalEvent::Completed { outputs, .. }
                    if staged.is_none() && !outputs.is_empty() =>
                {
                    return Err("completed outputs were never staged".to_string());
                }
                _ => {}
            }
        }
        if files.is_empty() {
            return Err("the operation has no pending entry".to_string());
        }
        let mut steps = Vec::new();
        for (entry, _) in &files {
            if let JournalEvent::YubikeyStep { step, .. } = entry.event {
                if steps.last().is_some_and(|last| *last >= step) {
                    return Err("YubiKey steps are out of order".to_string());
                }
                steps.push(step);
            }
        }
        let (entries, raw) = files.into_iter().unzip();
        Ok(OperationJournal {
            operation,
            entries,
            raw,
        })
    }

    /// The operation.
    pub fn operation(&self) -> OperationId {
        self.operation
    }

    /// Every entry, in step order.
    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    /// The exact bytes of each entry file, in step order.
    pub(crate) fn raw_entries(&self) -> &[Vec<u8>] {
        &self.raw
    }

    fn pending(&self) -> (OperationKind, &str, &[Serial]) {
        match &self.entries[0].event {
            JournalEvent::Pending {
                kind,
                subject,
                planned_serials,
            } => (*kind, subject, planned_serials),
            _ => unreachable!("from_entries guarantees a pending first entry"),
        }
    }

    /// The operation kind.
    pub fn kind(&self) -> OperationKind {
        self.pending().0
    }

    /// The subject.
    pub fn subject(&self) -> &str {
        self.pending().1
    }

    /// Serials reserved by this operation (they stay reserved whatever happens).
    pub fn planned_serials(&self) -> &[Serial] {
        self.pending().2
    }

    /// The final entry, if any.
    pub fn terminal(&self) -> Option<&JournalEntry> {
        self.entries
            .last()
            .filter(|entry| entry.event.is_terminal())
    }

    /// Pending, completed, cancelled or abandoned.
    pub fn state(&self) -> OperationState {
        match self.terminal().map(|entry| &entry.event) {
            Some(JournalEvent::Completed { .. }) => OperationState::Completed,
            Some(JournalEvent::Cancelled { .. }) => OperationState::Cancelled,
            Some(JournalEvent::Abandoned { .. }) => OperationState::Abandoned,
            _ => OperationState::Pending,
        }
    }

    /// Everything journaled as signed.
    pub fn signed(&self) -> impl Iterator<Item = &SignedObject> {
        self.entries.iter().filter_map(|entry| match &entry.event {
            JournalEvent::Signed { object } => Some(object),
            _ => None,
        })
    }

    /// YubiKey steps recorded, in order, with the device serial.
    pub fn yubikey_steps(&self) -> Vec<(YubikeySetupStep, u32)> {
        self.entries
            .iter()
            .filter_map(|entry| match entry.event {
                JournalEvent::YubikeyStep {
                    step,
                    device_serial,
                } => Some((step, device_serial)),
                _ => None,
            })
            .collect()
    }

    /// Outputs listed by the `staged` entry.
    pub fn staged_outputs(&self) -> Option<&[OutputFile]> {
        self.entries.iter().find_map(|entry| match &entry.event {
            JournalEvent::Staged { outputs } => Some(outputs.as_slice()),
            _ => None,
        })
    }

    /// Outputs listed by the `completed` entry.
    pub fn completed_outputs(&self) -> Option<&[OutputFile]> {
        match self.terminal().map(|entry| &entry.event) {
            Some(JournalEvent::Completed { outputs, .. }) => Some(outputs),
            _ => None,
        }
    }

    /// Audit-log head recorded by the final entry.
    pub fn audit_head(&self) -> Option<AuditHead> {
        match self.terminal().map(|entry| &entry.event) {
            Some(
                JournalEvent::Completed { audit, .. }
                | JournalEvent::Cancelled { audit }
                | JournalEvent::Abandoned { audit },
            ) => Some(*audit),
            _ => None,
        }
    }

    /// True once anything irreversible was journaled: a signature, a YubiKey step, or
    /// staging sealed (after which outputs may have been moved into place).
    pub fn has_persistent_change(&self) -> bool {
        self.entries.iter().any(|entry| {
            matches!(
                entry.event,
                JournalEvent::Signed { .. }
                    | JournalEvent::YubikeyStep { .. }
                    | JournalEvent::Staged { .. }
            )
        })
    }
}

/// Parses an entry file name `<step:03>-<kind>.json`.
fn parse_entry_name(name: &str) -> Option<(u32, &str)> {
    let stem = name.strip_suffix(".json")?;
    let (digits, tag) = stem.split_once('-')?;
    if digits.len() != 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((digits.parse().ok()?, tag))
}

impl CaDrive {
    /// Reads and checks every operation journal on this drive (SEC-08).
    pub fn journal(&self) -> Result<BTreeMap<OperationId, OperationJournal>, StoreError> {
        let mut out = BTreeMap::new();
        let Some(dir) = self.dir_at(JOURNAL_DIR, false)? else {
            return Ok(out);
        };
        for (name, _) in dir.entries()? {
            if name.starts_with('.') {
                continue;
            }
            let operation = OperationId::from_stem(&name).ok_or_else(|| StoreError::Parse {
                path: dir.child(&name),
                source: ParseError::invalid("unexpected entry in the journal folder"),
            })?;
            if let Some(journal) = self.operation_journal(operation)? {
                out.insert(operation, journal);
            }
        }
        Ok(out)
    }

    /// Reads one operation's journal, or `None` if this drive has no folder for it.
    pub fn operation_journal(
        &self,
        operation: OperationId,
    ) -> Result<Option<OperationJournal>, StoreError> {
        let rel = format!("{JOURNAL_DIR}/{}", operation.stem());
        let Some(dir) = self.dir_at(&rel, false)? else {
            return Ok(None);
        };
        let mut files = Vec::new();
        for (name, _) in dir.entries()? {
            if name.starts_with('.') {
                continue;
            }
            let path = dir.child(&name);
            let bad = |message: &str| StoreError::Parse {
                path: path.clone(),
                source: ParseError::invalid(message),
            };
            let (step, tag) =
                parse_entry_name(&name).ok_or_else(|| bad("unexpected journal file name"))?;
            let raw = dir.read(&name, MAX_JOURNAL_ENTRY_BYTES)?;
            let entry = parse_journal_entry(&raw).map_err(|source| StoreError::Parse {
                path: path.clone(),
                source,
            })?;
            if entry.step != step || entry.event.tag() != tag || entry.operation != operation {
                return Err(bad("file name and content differ"));
            }
            files.push((entry, raw));
        }
        if files.is_empty() {
            return Ok(None);
        }
        files.sort_by_key(|(entry, _)| entry.step);
        OperationJournal::from_entries(operation, files)
            .map(Some)
            .map_err(|message| StoreError::Parse {
                path: dir.path().to_path_buf(),
                source: ParseError::Invalid(message),
            })
    }
}

#[cfg(test)]
mod tests;
