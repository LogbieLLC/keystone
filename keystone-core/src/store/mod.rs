//! CA drives: atomic multi-drive writes, issuance record, audit log, operation journal,
//! drive comparison, repair and recovery (FR-11, FR-12, FR-14, FR-19, FR-22, SEC-08,
//! SEC-09, SEC-11, SEC-20, SEC-22).
//!
//! The audit-log hash chain ([`audit`]) and the operation journal ([`journal`],
//! [`operation`], [`recovery`]) are sensitive code (GOVERNANCE.md section 3).
//!
//! # Drive layout
//!
//! All CA state lives on two or more USB drives (PRD section 11). Each CA drive holds
//! one folder, `keystone/`, next to whatever else the file system needs:
//!
//! ```text
//! <drive root>/
//!   keystone/
//!     drive.json                 drive identity (DriveIdentity): CA id, drive id, role
//!     audit.log                  hash-chained audit log, JSON Lines (audit module)
//!     binary.sha256              SEC-19 record: "<64 hex>  keystone\n"
//!     journal/
//!       op-000001/               one folder per operation (FR-22)
//!         001-pending.json       first entry: kind, subject, planned serials
//!         002-signed.json        a certificate or CRL was signed (FR-22 AC3)
//!         003-staged.json        every output file and its SHA-256, after staging
//!         004-completed.json     written last: output hashes + its own last audit entry
//!       op-000002/
//!         001-pending.json
//!         002-yubikey-step.json  YubiKey setup, one entry per step (FR-22 AC7)
//!         ...
//!     record/
//!       op-000001.json           issuance-record update written by operation 1 (FR-11)
//!     certs/                     certificates and chain files  (create-only)
//!     keys/                      encrypted PKCS#8 keys only    (create-only, SEC-04/SEC-20)
//!     crls/                      CRLs                          (create-only)
//!     staging/
//!       op-000003/<dir>/<file>   outputs of operation 3 before they are moved into place
//! <export drive root>/
//!   keystone-export/             files carried by hand to issuing systems (create-only)
//! ```
//!
//! Rules every writer follows:
//! - **Atomic writes** (FR-12 AC4): write a temporary file (`.<name>.tmp-<random>`) in the
//!   same folder, write everything, fsync it, rename it into place, fsync the folder.
//! - **Never overwrite** (SEC-20): certificates, keys, CRLs, record updates, journal
//!   entries and drive identities are *create-only*; the final rename uses
//!   `RENAME_NOREPLACE`, so an existing file is never replaced. Only `audit.log` (which
//!   only ever grows, checked against the parsed chain) and `binary.sha256` are replaced.
//! - **Every drive, verified** (FR-12 AC1, AC2, SEC-11): every change goes to every
//!   connected CA drive (the primary and at least one backup); each copy is then read
//!   back from the medium (page cache dropped first) and compared by SHA-256. Any
//!   mismatch is an error and the action is not reported as successful.
//! - **Strict reading** (SEC-08): every file is opened without following symbolic links
//!   (`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`), must be a regular file,
//!   is size-checked against [`crate::limits`] before parsing, and is parsed with
//!   `deny_unknown_fields` into typed errors. Names that do not follow the layout are
//!   errors, not silently skipped. Names starting with `.` (temporary files) are ignored.
//!
//! # Order of writes for one operation (FR-22)
//! 1. `pending` journal entry on every drive, recording the planned serial(s), before the
//!    first irreversible step;
//! 2. irreversible steps, each journaled on every drive right after it happens
//!    (`signed`, `yubikey-step`);
//! 3. outputs written to `staging/op-N/` on every drive and verified, then a `staged`
//!    entry listing every output file with its SHA-256;
//! 4. outputs moved into place (create-only) and verified;
//! 5. the operation's audit entries appended on every drive;
//! 6. the `completed` entry, written last, listing every output file's SHA-256 and the
//!    operation's own last audit entry (entries of no operation written later, such as a
//!    clock correction, never change it).
#![forbid(unsafe_code)]

pub mod audit;
pub mod binhash;
pub mod compare;
mod drive;
#[cfg(any(test, not(feature = "production")))]
pub(crate) mod fault;
mod fsio;
mod ids;
pub mod journal;
pub mod operation;
mod paths;
pub mod record;
pub mod recovery;
pub mod replace;
#[cfg(test)]
pub(crate) mod testutil;

use std::path::PathBuf;

pub use audit::{
    AuditAction, AuditDetails, AuditDraft, AuditEntry, AuditLog, AuditProblem, AuditResult,
    ClockCorrectionDetails, parse_audit_log,
};
pub use binhash::parse_binary_hash_record;
pub use compare::{DriveComparison, DriveHistory, RepairPlan, RepairStep};
pub use drive::{
    CaDrive, DriveClass, DriveIdentity, DriveRole, DriveSet, ExportDrive, SetupProgress,
    UnfinishedSetup, classify_drive, parse_drive_identity, unfinished_setup,
};
pub use ids::{CaId, DriveId, OperationId};
pub use journal::{
    AuditHead, JournalEntry, JournalEvent, OperationJournal, OperationKind, OperationState,
    OutputFile, SignedCrl, SignedObject, YubikeySetupStep, parse_journal_entry,
};
pub use operation::OperationHandle;
pub use paths::{
    AUDIT_LOG_FILE, BINARY_HASH_FILE, EXPORT_DIR, IDENTITY_FILE, JOURNAL_DIR, KEYSTONE_DIR,
    OutputDir, OutputPath, RECORD_DIR, STAGING_DIR,
};
pub use record::{
    CertStatus, CertificateRecord, IssuanceRecord, RecordChange, RecordSource, RecordUpdate,
    RecordedCertificate, StatusFilter, SubjectName, parse_record,
};
pub use recovery::{
    DriveOperationView, FileState, OutputState, PendingOperation, RecoveryAction, RecoveryReport,
};
pub use replace::{AddDrivePlan, NewDriveState};

use crate::crypto::CryptoError;
use crate::model::{Serial, Sha256Digest};

/// A file whose content could not be accepted (SEC-08). Never contains secret material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Larger than the limit for its kind of file; nothing was parsed.
    #[error("the file is {len} bytes; the limit is {limit} bytes")]
    TooLarge {
        /// Size found.
        len: usize,
        /// The limit from `crate::limits`.
        limit: usize,
    },
    /// Not valid for its format (bad JSON, unknown field, wrong value, wrong name).
    #[error("invalid content: {0}")]
    Invalid(String),
    /// The audit log is broken. `entry` is the 1-based number of the first bad entry
    /// (FR-14 AC3).
    #[error("audit log entry {entry} is the first bad entry: {problem}")]
    Audit {
        /// 1-based number (line) of the first bad entry.
        entry: u64,
        /// What is wrong with it.
        problem: AuditProblem,
    },
}

impl ParseError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        ParseError::Invalid(message.into())
    }
}

/// Any failure while reading or writing CA drives.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A file-system call failed.
    #[error("could not {action} {path}: {source}")]
    Io {
        /// What was being done ("read", "write", "rename" ...).
        action: &'static str,
        /// The file or folder.
        path: PathBuf,
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// A file was rejected by its parser.
    #[error("{path}: {source}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// Why it was rejected.
        #[source]
        source: ParseError,
    },
    /// The path is a symbolic link, folder, device or pipe where a regular file was expected.
    #[error("{path} is not a regular file; Keystone never follows links on a drive")]
    NotAFile {
        /// The path.
        path: PathBuf,
    },
    /// A create-only file already exists; it is never overwritten (SEC-20).
    #[error("{path} already exists; Keystone never overwrites it")]
    AlreadyExists {
        /// The existing file.
        path: PathBuf,
    },
    /// SEC-20: refuse to create a new CA on a drive that already holds one.
    #[error("the drive at {root} already holds a Keystone CA; a new CA is never created over it")]
    DriveHoldsCa {
        /// Drive root.
        root: PathBuf,
    },
    /// A new CA can only be created on an empty drive.
    #[error("the drive at {root} is not empty; use an empty drive for a new CA")]
    DriveNotEmpty {
        /// Drive root.
        root: PathBuf,
    },
    /// The drive holds no readable Keystone CA.
    #[error("the drive at {root} does not hold a readable Keystone CA: {reason}")]
    NotACaDrive {
        /// Drive root.
        root: PathBuf,
        /// Why.
        reason: String,
    },
    /// The drives cannot be used together.
    #[error("these drives cannot be used together: {0}")]
    DriveSet(String),
    /// FR-12 AC1: every change needs the primary drive and at least one backup.
    #[error(
        "connect the primary drive and at least one backup drive (connected: {primaries} primary, {backups} backup)"
    )]
    NotEnoughDrives {
        /// Primary drives connected.
        primaries: usize,
        /// Backup drives connected.
        backups: usize,
    },
    /// FR-12 AC2: a copy read back from a drive does not match what was written.
    #[error(
        "read-back check failed on {drive}: {path} has SHA-256 {actual}, expected {expected}; the action did not succeed"
    )]
    ReadBackMismatch {
        /// The drive.
        drive: String,
        /// The file.
        path: PathBuf,
        /// SHA-256 of what was written.
        expected: Sha256Digest,
        /// SHA-256 read back.
        actual: Sha256Digest,
    },
    /// The drives differ; they must be compared and repaired first (FR-12 AC3).
    #[error("the CA drives do not hold the same history; compare and repair them first ({0})")]
    OutOfSync(String),
    /// Something on the drives cannot be verified (a completed output missing or changed,
    /// or a journal's audit head missing from the log): the same problems
    /// [`DriveComparison::Damaged`] lists. Nothing can be signed until it is resolved.
    #[error("the CA drives cannot be verified, so nothing can be signed: {}", .0.join("; "))]
    Damaged(Vec<String>),
    /// An operation is pending; recovery must run first (FR-22 AC4).
    #[error("operation {0} was interrupted; finish or abandon it on the recovery screen first")]
    PendingOperation(OperationId),
    /// FR-10 AC2: the planned serial has been seen before in some history.
    #[error("serial number {0} was already used or reserved; a serial is never reused")]
    SerialAlreadyUsed(Serial),
    /// An operation step was called in the wrong state.
    #[error("{operation}: {message}")]
    OperationState {
        /// The operation.
        operation: OperationId,
        /// What is not allowed.
        message: String,
    },
    /// A repair or recovery action cannot be carried out safely.
    #[error("{0}")]
    Unsafe(String),
    /// The secure random source failed (random file names and ids).
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}
