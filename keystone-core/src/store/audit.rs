//! Tamper-evident audit log (FR-14, SEC-09). Sensitive code (GOVERNANCE.md section 3).
//!
//! # File format
//! `keystone/audit.log` is JSON Lines: one entry per line, each line ending in `\n`,
//! nothing else in the file. The file only ever grows; it is replaced atomically with
//! the old bytes plus new lines, and existing entries are never changed.
//!
//! # Canonical form (what is hashed)
//! An entry's *canonical form* is the compact JSON object written by `serde_json` for
//! [`AuditEntry`]: exactly the keys `seq, time, operation, action, subject, serial,
//! fingerprint, result, details, prev`, in that order, with no whitespace. Absent
//! optional values are `null`; inside `details`, absent fields are omitted and an empty
//! `details` is written as `null`. Strings use serde_json's escaping (only `"`, `\` and
//! control characters are escaped; other characters are raw UTF-8). Timestamps are
//! RFC 3339 in UTC with whole seconds (`2026-11-01T10:00:00Z`); serials, fingerprints and
//! hashes are lowercase hex. Each line of the file must be byte-for-byte the canonical form
//! of the entry it contains; any other spelling is rejected.
//!
//! # Hash chain
//! `seq` numbers entries 1, 2, 3 ... in file order. `prev` of entry 1 is 64 zeros; `prev`
//! of entry *n* is the SHA-256 of the canonical form (without the newline) of entry *n-1*.
//!
//! # Verification (FR-14 AC3)
//! [`parse_audit_log`] checks every line and names the **first bad entry**: the first
//! entry that is cut off, malformed, not canonical, out of sequence, or whose SHA-256
//! does not match the hash stored in the entry after it. A change to the *last* entry is
//! not visible in the chain of one drive; it is caught by the cross-drive comparison
//! (FR-12 AC3) and by the audit-log head recorded in each finished journal entry.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use super::drive::{CaDrive, DriveSet, check_len, check_timestamp};
use super::fsio::WriteMode;
use super::ids::OperationId;
use super::journal::{AuditHead, OperationKind};
use super::paths::AUDIT_LOG_FILE;
use super::{ParseError, StoreError};
use crate::crypto::hash::sha256;
use crate::limits::{MAX_AUDIT_ENTRY_BYTES, MAX_AUDIT_LOG_BYTES};
use crate::model::{Fingerprint, RevocationReason, Serial, Sha256Digest, Timestamp};

/// `prev` of the first entry.
pub const GENESIS_PREV: Sha256Digest = Sha256Digest([0; 32]);

/// Longest subject or note text accepted in an audit entry.
pub const MAX_AUDIT_TEXT: usize = 4096;

/// What was done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Flow A: master key, certificate and first CRL.
    CreateMaster,
    /// Flow B: YubiKey hardening, main intermediate and its first CRL.
    SetupYubikey,
    /// Flow C: a sub-intermediate.
    CreateSubIntermediate,
    /// Flow D: revocation and a new CRL.
    Revoke,
    /// FR-13 AC4: re-signed CRL without new revocations.
    RefreshCrl,
    /// Flow E: revoke the old main intermediate and mark its children.
    ReplaceYubikey,
    /// FR-17 AC3: clock-correction baseline.
    ClockCorrection,
    /// FR-12 AC3: a behind drive was repaired from another drive.
    DriveRepair,
    /// FR-22 AC4: an interrupted operation was finished from a drive holding its output.
    RecoveryFinish,
    /// FR-22 AC4: an interrupted operation was marked abandoned.
    RecoveryAbandon,
    /// Files were written to the export drive.
    Export,
    /// SEC-19: the binary's SHA-256 was recorded at install.
    BinaryHashRecorded,
}

impl From<OperationKind> for AuditAction {
    fn from(kind: OperationKind) -> Self {
        match kind {
            OperationKind::CreateMaster => AuditAction::CreateMaster,
            OperationKind::SetupYubikey => AuditAction::SetupYubikey,
            OperationKind::CreateSubIntermediate => AuditAction::CreateSubIntermediate,
            OperationKind::Revoke => AuditAction::Revoke,
            OperationKind::RefreshCrl => AuditAction::RefreshCrl,
            OperationKind::ReplaceYubikey => AuditAction::ReplaceYubikey,
        }
    }
}

/// How it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    /// Done.
    Success,
    /// Failed (details say why).
    Failure,
    /// Cancelled before any persistent change (FR-16).
    Cancelled,
    /// Marked abandoned on the recovery screen (FR-22 AC4).
    Abandoned,
}

/// FR-17 AC3: the values a clock-correction entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockCorrectionDetails {
    /// The newest timestamp in the log before the correction (the wrong, future one).
    pub previous_newest: Timestamp,
    /// The current time the operator confirmed.
    pub confirmed: Timestamp,
}

/// Optional details of an entry. Absent fields are omitted from the canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditDetails {
    /// Serial of the issuing certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_serial: Option<Serial>,
    /// Name constraints switched on (FR-21 AC1, AC6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_constraints: Option<bool>,
    /// Permitted DNS names (FR-21 AC6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permitted_dns: Option<Vec<String>>,
    /// Permitted IP ranges (FR-21 AC3, AC6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permitted_ip: Option<Vec<String>>,
    /// Revocation reason (Flow D).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<RevocationReason>,
    /// CRL number of a signed CRL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_number: Option<u64>,
    /// Clock correction (FR-17 AC3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_correction: Option<ClockCorrectionDetails>,
    /// Free text (for example which drive was repaired from which).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One audit-log entry (FR-14 AC1, AC2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    /// 1-based position in the log.
    pub seq: u64,
    /// When (UTC, whole seconds).
    pub time: Timestamp,
    /// The journaled operation this entry belongs to, if any.
    pub operation: Option<OperationId>,
    /// What was done.
    pub action: AuditAction,
    /// Subject (for example the certificate's distinguished name); may be empty.
    pub subject: String,
    /// Certificate serial, if any.
    pub serial: Option<Serial>,
    /// Certificate SHA-256 fingerprint, if any.
    pub fingerprint: Option<Fingerprint>,
    /// How it ended.
    pub result: AuditResult,
    /// Optional details.
    pub details: Option<AuditDetails>,
    /// SHA-256 of the previous entry's canonical form (FR-14 AC2).
    pub prev: Sha256Digest,
}

impl AuditEntry {
    /// The canonical form (see the module documentation), without the newline.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("in-memory JSON serialization")
    }

    fn validate(&self) -> Result<(), String> {
        check_timestamp(self.time, "time").map_err(|e| e.to_string())?;
        if self.operation.is_some_and(|op| !op.is_valid()) {
            return Err("invalid operation number".to_string());
        }
        if self.subject.len() > MAX_AUDIT_TEXT {
            return Err("subject is too long".to_string());
        }
        if let Some(details) = &self.details {
            validate_details(details)?;
        }
        Ok(())
    }
}

fn validate_details(details: &AuditDetails) -> Result<(), String> {
    if *details == AuditDetails::default() {
        return Err("empty details must be null".to_string());
    }
    if details
        .note
        .as_ref()
        .is_some_and(|n| n.len() > MAX_AUDIT_TEXT)
    {
        return Err("note is too long".to_string());
    }
    if let Some(correction) = &details.clock_correction {
        check_timestamp(correction.previous_newest, "previous_newest")
            .map_err(|e| e.to_string())?;
        check_timestamp(correction.confirmed, "confirmed").map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// What a caller asks to record; the store adds `seq`, `time` and `prev`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditDraft {
    /// The journaled operation, if any.
    pub operation: Option<OperationId>,
    /// What was done.
    pub action: AuditAction,
    /// Subject; may be empty.
    pub subject: String,
    /// Certificate serial, if any.
    pub serial: Option<Serial>,
    /// Certificate fingerprint, if any.
    pub fingerprint: Option<Fingerprint>,
    /// How it ended.
    pub result: AuditResult,
    /// Optional details.
    pub details: Option<AuditDetails>,
}

impl AuditDraft {
    /// A draft with no operation, serial, fingerprint or details.
    pub fn new(action: AuditAction, subject: impl Into<String>, result: AuditResult) -> Self {
        AuditDraft {
            operation: None,
            action,
            subject: subject.into(),
            serial: None,
            fingerprint: None,
            result,
            details: None,
        }
    }
}

/// Why an audit-log entry is bad (FR-14 AC3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditProblem {
    /// The last line has no line end: the file was cut off.
    #[error("the entry is cut off (the file was truncated)")]
    Truncated,
    /// An empty line.
    #[error("the entry is empty")]
    Empty,
    /// A line over the per-entry limit.
    #[error("the entry is longer than {limit} bytes")]
    TooLong {
        /// `limits::MAX_AUDIT_ENTRY_BYTES`.
        limit: usize,
    },
    /// Not a valid entry (JSON, unknown field, bad value).
    #[error("the entry is not a valid audit entry: {0}")]
    Invalid(String),
    /// Valid JSON but not the canonical spelling.
    #[error("the entry is not written in canonical form (it was edited)")]
    NotCanonical,
    /// Entries were removed, added or reordered.
    #[error(
        "the entry has sequence number {found} where {expected} was expected (entries were removed, added or reordered)"
    )]
    WrongSequence {
        /// The position in the file.
        expected: u64,
        /// The number stored in the entry.
        found: u64,
    },
    /// The first entry links to a previous entry.
    #[error(
        "the first entry must not link to a previous entry (entries were removed from the start)"
    )]
    WrongGenesis,
    /// This entry's hash does not match the link stored in the next entry.
    #[error(
        "its SHA-256 does not match the hash stored in entry {next_entry}, so this entry (or that link) was changed"
    )]
    HashMismatch {
        /// The entry holding the link.
        next_entry: u64,
    },
    /// This entry's link to the previous entry was changed: the previous entry still
    /// verifies, and the next entry's link no longer matches this one.
    #[error(
        "its link to the previous entry was changed (the previous entry still verifies and the next entry no longer links to this one)"
    )]
    LinkChanged,
}

/// A parsed and verified audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLog {
    bytes: Vec<u8>,
    entries: Vec<AuditEntry>,
    /// Byte offset just after each entry's newline.
    ends: Vec<usize>,
    /// SHA-256 of each entry's canonical form.
    hashes: Vec<Sha256Digest>,
}

fn audit_err(entry: u64, problem: AuditProblem) -> ParseError {
    ParseError::Audit { entry, problem }
}

/// Parses and verifies a whole audit log (FR-14 AC3, SEC-08). The error names the first
/// bad entry. Never panics on any input.
pub fn parse_audit_log(bytes: &[u8]) -> Result<AuditLog, ParseError> {
    check_len(bytes, MAX_AUDIT_LOG_BYTES)?;
    let mut log = AuditLog {
        bytes: bytes.to_vec(),
        entries: Vec::new(),
        ends: Vec::new(),
        hashes: Vec::new(),
    };
    let mut start = 0usize;
    let mut number = 0u64;
    while start < bytes.len() {
        number += 1;
        let rest = &bytes[start..];
        let Some(newline) = rest.iter().position(|b| *b == b'\n') else {
            return Err(audit_err(number, AuditProblem::Truncated));
        };
        let line = &rest[..newline];
        if line.len() > MAX_AUDIT_ENTRY_BYTES {
            return Err(audit_err(
                number,
                AuditProblem::TooLong {
                    limit: MAX_AUDIT_ENTRY_BYTES,
                },
            ));
        }
        if line.is_empty() {
            return Err(audit_err(number, AuditProblem::Empty));
        }
        let entry: AuditEntry = serde_json::from_slice(line)
            .map_err(|e| audit_err(number, AuditProblem::Invalid(e.to_string())))?;
        if entry.canonical_bytes() != line {
            return Err(audit_err(number, AuditProblem::NotCanonical));
        }
        entry
            .validate()
            .map_err(|message| audit_err(number, AuditProblem::Invalid(message)))?;
        if entry.seq != number {
            return Err(audit_err(
                number,
                AuditProblem::WrongSequence {
                    expected: number,
                    found: entry.seq,
                },
            ));
        }
        match log.hashes.last() {
            None if entry.prev != GENESIS_PREV => {
                return Err(audit_err(number, AuditProblem::WrongGenesis));
            }
            Some(previous) if entry.prev != *previous => {
                // Entry n-1 verified against its own predecessor. If entry n+1 still
                // links to entry n, entry n is unchanged and n-1 was edited; if it does
                // not, entry n itself (its link) was edited (FR-14 AC3).
                let next_links_here = rest[newline + 1..]
                    .split(|b| *b == b'\n')
                    .next()
                    .and_then(|next| serde_json::from_slice::<AuditEntry>(next).ok())
                    .map(|next| next.prev == sha256(line));
                return Err(match next_links_here {
                    Some(false) => audit_err(number, AuditProblem::LinkChanged),
                    _ => audit_err(
                        number - 1,
                        AuditProblem::HashMismatch { next_entry: number },
                    ),
                });
            }
            _ => {}
        }
        log.hashes.push(sha256(line));
        start += newline + 1;
        log.ends.push(start);
        log.entries.push(entry);
    }
    Ok(log)
}

impl AuditLog {
    /// An empty log.
    pub fn empty() -> Self {
        AuditLog {
            bytes: Vec::new(),
            entries: Vec::new(),
            ends: Vec::new(),
            hashes: Vec::new(),
        }
    }

    /// Every entry, oldest first.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The file bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes of the first `count` entries (a valid log on its own).
    pub fn prefix_bytes(&self, count: usize) -> &[u8] {
        match count.min(self.ends.len()).checked_sub(1) {
            None => &[],
            Some(last) => &self.bytes[..self.ends[last]],
        }
    }

    /// SHA-256 of entry `seq` (1-based).
    pub fn entry_hash(&self, seq: u64) -> Option<Sha256Digest> {
        let index = usize::try_from(seq.checked_sub(1)?).ok()?;
        self.hashes.get(index).copied()
    }

    /// The newest entry's number and SHA-256 (`seq` 0 and zeros for an empty log).
    pub fn head(&self) -> AuditHead {
        AuditHead {
            seq: self.entries.len() as u64,
            sha256: self.hashes.last().copied().unwrap_or(GENESIS_PREV),
        }
    }

    /// The newest entry that belongs to `operation` (its number and SHA-256): what an
    /// operation's final journal entry records, so later entries that belong to no
    /// operation never change it.
    pub fn operation_head(&self, operation: OperationId) -> Option<AuditHead> {
        let index = self
            .entries
            .iter()
            .rposition(|entry| entry.operation == Some(operation))?;
        Some(AuditHead {
            seq: self.entries[index].seq,
            sha256: self.hashes[index],
        })
    }

    /// True when this log's entries are the first entries of `other` (same entries and
    /// hashes, possibly fewer) (FR-12 AC3).
    pub fn is_prefix_of(&self, other: &AuditLog) -> bool {
        self.len() <= other.len() && other.bytes.starts_with(&self.bytes)
    }

    /// Number of leading entries both logs share.
    pub fn common_prefix_len(&self, other: &AuditLog) -> usize {
        self.hashes
            .iter()
            .zip(&other.hashes)
            .take_while(|(left, right)| left == right)
            .count()
    }

    /// The log after appending `drafts` at `time`: new file bytes and the new entries.
    pub(crate) fn with_appended(
        &self,
        drafts: &[AuditDraft],
        time: Timestamp,
    ) -> Result<(Vec<u8>, Vec<AuditEntry>), ParseError> {
        let time = Timestamp::utc(
            time.get()
                .replace_nanosecond(0)
                .map_err(|e| ParseError::invalid(e.to_string()))?,
        );
        let mut bytes = self.bytes.clone();
        let mut prev = self.head().sha256;
        let mut added = Vec::new();
        let first_seq = self.entries.len() as u64 + 1;
        for (seq, draft) in (first_seq..).zip(drafts) {
            let entry = AuditEntry {
                seq,
                time,
                operation: draft.operation,
                action: draft.action,
                subject: draft.subject.clone(),
                serial: draft.serial,
                fingerprint: draft.fingerprint,
                result: draft.result,
                details: draft
                    .details
                    .clone()
                    .filter(|details| *details != AuditDetails::default()),
                prev,
            };
            entry.validate().map_err(ParseError::Invalid)?;
            let line = entry.canonical_bytes();
            if line.len() > MAX_AUDIT_ENTRY_BYTES {
                return Err(ParseError::TooLarge {
                    len: line.len(),
                    limit: MAX_AUDIT_ENTRY_BYTES,
                });
            }
            prev = sha256(&line);
            bytes.extend_from_slice(&line);
            bytes.push(b'\n');
            added.push(entry);
        }
        check_len(&bytes, MAX_AUDIT_LOG_BYTES)?;
        Ok((bytes, added))
    }

    /// Newest timestamp among all entries.
    pub fn newest_time(&self) -> Option<Timestamp> {
        self.entries.iter().map(|entry| entry.time).max()
    }
}

impl CaDrive {
    /// Reads and verifies this drive's audit log (FR-14 AC3).
    pub fn audit_log(&self) -> Result<AuditLog, StoreError> {
        let bytes = self.keystone().read(AUDIT_LOG_FILE, MAX_AUDIT_LOG_BYTES)?;
        parse_audit_log(&bytes).map_err(|source| StoreError::Parse {
            path: self.keystone().child(AUDIT_LOG_FILE),
            source,
        })
    }
}

impl DriveSet {
    /// Verifies the audit log on every drive (FR-14 AC3) and returns it when every drive
    /// holds exactly the same log; otherwise the drives must be compared first.
    pub fn audit_log(&self) -> Result<AuditLog, StoreError> {
        let mut logs = Vec::new();
        for drive in self.drives() {
            logs.push((drive, drive.audit_log()?));
        }
        let (first_drive, first) = logs.remove(0);
        for (drive, log) in logs {
            if log != first {
                return Err(StoreError::OutOfSync(format!(
                    "{} and {} have different audit logs",
                    first_drive.label(),
                    drive.label()
                )));
            }
        }
        Ok(first)
    }

    /// Appends entries to the audit log on every drive (FR-14 AC1), atomically, and verifies
    /// every copy by read-back (FR-12 AC2). The drives must hold the same log beforehand.
    pub fn append_audit(
        &self,
        drafts: &[AuditDraft],
        time: Timestamp,
    ) -> Result<Vec<AuditEntry>, StoreError> {
        self.ensure_writable()?;
        let log = self.audit_log()?;
        let (bytes, added) =
            log.with_appended(drafts, time)
                .map_err(|source| StoreError::Parse {
                    path: self.drives()[0].keystone().child(AUDIT_LOG_FILE),
                    source,
                })?;
        self.write_verified("", AUDIT_LOG_FILE, &bytes, WriteMode::Replace)?;
        Ok(added)
    }
}

#[cfg(test)]
mod tests;
