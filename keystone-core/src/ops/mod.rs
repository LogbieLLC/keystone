//! The operations layer: the PRD's user flows A to E, journaled, cancellable and
//! recoverable, on top of the building blocks (FR-02 to FR-22, PRD sections 6 and 10).
//!
//! The GUI is a thin layer over this module. Every type an operation needs is `Send`, so
//! the GUI runs operations on a worker thread and forwards [`Progress`] reports to its
//! main loop (FR-16 AC1, NFR-03).
//!
//! # Shape of the API
//!
//! ```text
//! Ca::open(drives) ──▶ Ca::startup_report(now) ──▶ blockers / warnings / recovery items
//!                         │
//!                         ├─ Ca::repair_drives(plans)          (FR-12 AC3, after the operator confirms)
//!                         ├─ Ca::recovery_items(token) ─▶ Ca::run_recovery(...)   (FR-22 AC4-AC8)
//!                         └─ clock::confirm(assessment) ─▶ ConfirmedTime          (FR-17)
//!
//! plan_*(request, ConfirmedTime) ──▶ Plan::review() (shown to the operator, nothing written)
//!                                ──▶ Plan::execute(secrets, progress, cancel) ──▶ Outcome
//! ```
//!
//! | Flow | Plan | Executes |
//! |------|------|----------|
//! | A create master | [`plan_create_master`] | [`CreateMasterPlan::execute`] |
//! | B YubiKey + main intermediate | [`Ca::plan_yubikey_setup`] | [`YubikeySetupPlan::execute`]; [`Ca::resume_yubikey_setup`]; [`Ca::wipe_yubikey_slot`] |
//! | C sub-intermediate | [`Ca::plan_sub_intermediate`] | [`SubIntermediatePlan::execute`] |
//! | D revoke + CRL | [`Ca::plan_revoke`] | [`CrlPlan::execute`] |
//! | Refresh CRL (FR-13 AC4) | [`Ca::plan_refresh_crl`] | [`CrlPlan::execute`] |
//! | E replace lost YubiKey | [`Ca::plan_replace_yubikey`] | [`CrlPlan::execute`], then Flow B, then Flow C per [`CaState::reissue_candidates`] |
//! | Replace a lost drive (SEC-11) | [`Ca::plan_replace_drive`] | [`ReplaceDrivePlan::execute`] (signs nothing; the one writing action a CA with a single healthy drive can run) |
//!
//! # Rules every signing operation follows
//! - It needs a [`ConfirmedTime`] (FR-17 AC1), which only `clock::confirm` creates, and
//!   which must not be earlier than the newest audit entry when the operation starts.
//! - The drives must be writable (primary + backup), hold the same verified history, and
//!   have no interrupted operation (FR-12 AC3, FR-14 AC3, FR-22 AC4); otherwise
//!   [`OpsError::Blocked`].
//! - Serials are drawn until one is unknown in every record and journal on every
//!   connected drive (FR-10 AC2); a child never outlives its issuer (FR-10 AC1).
//! - The pending journal entry (with the planned serial) is written before the first
//!   irreversible step (FR-22 AC1); every signed certificate or CRL is journaled right
//!   after signing (FR-22 AC3); outputs are staged, verified, moved into place, audited,
//!   and the completed entry is written last (FR-22 AC2, FR-12 AC2).
//! - The SHA-256 fingerprint of every new certificate is returned for display (FR-20).
//! - Export (FR-09, FR-13 AC6) happens only after the completed entry exists and the
//!   outputs verify on at least two drives (FR-22 AC2). An export failure does not undo
//!   the operation; [`Ca::export_operation`] retries it.
//!
//! # Failures and cancel (FR-16 AC2, FR-22)
//! - Cancel is honoured only before the first persistent change; the operation is then
//!   marked cancelled, its staged files are deleted and its serial stays reserved
//!   ([`OpsError::Cancelled`]).
//! - Any other failure before the first persistent change (wrong PIN, touch timeout,
//!   wrong passphrase, YubiKey removed) cancels the operation the same way and returns
//!   [`OpsError::Stopped`] with the cause.
//! - A failure after a persistent change leaves the operation pending and returns
//!   [`OpsError::Interrupted`]; the recovery screen finishes it.
//!
//! # Decisions on points the PRD leaves open (most conservative reading)
//! - **Flow A on reused drives.** A drive set whose journal holds only cancelled or
//!   abandoned attempts and no certificate at all holds no CA, so Flow A may run on it
//!   again (SEC-20 still refuses any drive set holding a certificate, and any drive that
//!   is neither empty nor such a set). Reserved serials stay reserved.
//! - **Order in Flow A and C.** The pending entry is written first, then the key is
//!   generated (cancellable), encrypted and staged, and only then signed, so a cancel
//!   during key generation is journaled and a signed certificate always has its
//!   encrypted key staged on every drive.
//! - **Order in Flow B.** The master passphrase is checked (and the key wiped again)
//!   before any change to the YubiKey, so a wrong passphrase changes nothing; the master
//!   key is unlocked a second time only to sign, and wiped right after.
//! - **CRL addresses (FR-18).** An issuer's address is asked for its first child and is
//!   then the one written in that child; later children reuse it (a differing address is
//!   refused). The first operation that sets it says so in its audit entry.
//! - **One main intermediate at a time.** Flow B is refused while a main intermediate
//!   is valid and unexpired; Flow E (or Flow D) must revoke it first.
//! - **Revoking a main intermediate (Flow D or E)** also marks every sub-intermediate
//!   under it "revoked by ancestor" in the same operation (FR-15 AC1), so the record
//!   always says which sub-intermediates are cut off.
//! - **File names (FR-09 AC1).** `<name>` is the Common Name in lower case with every
//!   other character run replaced by `-`, plus the first 16 hex digits of the serial, so
//!   a re-issued sub-intermediate never clashes with the old files. CRLs are DER files
//!   named `<issuer>-crl-<number>.crl` (RFC 5280 section 4.2.1.13).
//! - **Wipe (FR-07 AC4)** is refused when the slot holds a main intermediate that is
//!   still valid in the issuance record.
#![forbid(unsafe_code)]

mod ca;
mod crl_ops;
mod master;
mod pipeline;
mod progress;
mod recovery;
mod replace;
mod seam;
mod state;
mod sub;
#[cfg(not(feature = "production"))]
pub mod testing;
mod yubikey;

use crate::cert::CertError;
use crate::clock::ClockError;
use crate::crl::CrlError;
use crate::crypto::CryptoError;
use crate::model::Serial;
use crate::passphrase::PassphraseError;
use crate::profile::ProfileError;
use crate::store::{OperationId, StoreError};
use crate::token::TokenError;

pub use crate::clock::ConfirmedTime;
pub use crate::crypto::CancelFlag;
pub use ca::{
    AuditLogStatus, Blocker, Ca, CertSummary, CrlWarning, ExportStatus, ExportedFile,
    HierarchySummary, StartupReport, StartupWarning, assess_clock_for_new_ca,
};
pub use crl_ops::{CrlOutcome, CrlPlan, CrlPlanKind, IssuerUnlock};
pub use master::{
    CreateMasterOutcome, CreateMasterPlan, CreateMasterRequest, DriveSetup, plan_create_master,
};
pub use progress::{NoProgress, Progress, ProgressSink, Step};
pub use recovery::{RecoveryAction, RecoveryChoice, RecoveryItem, RecoverySecrets, TokenColumn};
pub use replace::{ReplaceDriveOutcome, ReplaceDrivePlan};
pub use state::{CaState, StoredCert, StoredCrl};
pub use sub::{SubIntermediateOutcome, SubIntermediatePlan, SubIntermediateRequest};
pub use yubikey::{
    MainIntermediateOutcome, MainIntermediateRequest, PinEntry, TokenInspection, UPLOAD_CRL_NOTE,
    YubikeySecrets, YubikeySetupPlan, inspect_yubikey,
};

/// True when this build contains the test seams of [`testing`] (never in a `production`
/// build).
pub const TEST_SEAMS_COMPILED: bool = cfg!(not(feature = "production"));

/// What the GUI shows on the review step before anything is written (FR-16, FR-21 AC6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    /// Heading.
    pub title: String,
    /// Label and value pairs, in display order.
    pub lines: Vec<(String, String)>,
    /// Warnings the operator must see (for example no CRL address, FR-18 AC1).
    pub warnings: Vec<String>,
}

impl Review {
    fn new(title: impl Into<String>) -> Self {
        Review {
            title: title.into(),
            lines: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn line(&mut self, label: impl Into<String>, value: impl Into<String>) {
        self.lines.push((label.into(), value.into()));
    }

    /// The value shown for `label`, if any.
    pub fn value(&self, label: &str) -> Option<&str> {
        self.lines
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, v)| v.as_str())
    }
}

fn serial_list(serials: &[Serial]) -> String {
    if serials.is_empty() {
        "none".to_owned()
    } else {
        serials
            .iter()
            .map(Serial::to_hex)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Errors from the operations layer. No variant ever contains a passphrase, PIN, PUK or
/// key; every message is written for the operator.
#[derive(Debug, thiserror::Error)]
pub enum OpsError {
    /// Reading or writing the CA drives failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A certificate could not be built or read.
    #[error(transparent)]
    Cert(#[from] CertError),
    /// A CRL could not be built or read.
    #[error(transparent)]
    Crl(#[from] CrlError),
    /// The YubiKey failed or refused.
    #[error(transparent)]
    Token(#[from] TokenError),
    /// A crypto operation failed (for example a wrong passphrase, FR-04 AC3).
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// An entry breaks a profile rule (names, validity, CRL address, name constraints).
    #[error(transparent)]
    Profile(#[from] ProfileError),
    /// A passphrase problem.
    #[error(transparent)]
    Passphrase(#[from] PassphraseError),
    /// The clock check failed.
    #[error(transparent)]
    Clock(#[from] ClockError),
    /// Signing is blocked until every blocker is resolved (FR-12 AC3, FR-14 AC3, FR-17,
    /// FR-22 AC4).
    #[error("signing is blocked: {}", .0.iter().map(Blocker::message).collect::<Vec<_>>().join("; "))]
    Blocked(Vec<Blocker>),
    /// A step the flow needs first is missing (for example no master yet).
    #[error("{0}")]
    NotReady(String),
    /// The CA data on the drives cannot be used as it is.
    #[error("the CA data on the drives is damaged: {0}")]
    Damaged(String),
    /// FR-07 AC4: the signing slot already holds something; only the explicit wipe can
    /// empty it.
    #[error(
        "the YubiKey's signing slot is not empty: it holds {description}. Keystone never overwrites it; wipe it explicitly by typing the YubiKey's serial number"
    )]
    SlotOccupied {
        /// What the slot holds.
        description: String,
    },
    /// The operator pressed Cancel before anything was written.
    #[error("cancelled; nothing was written")]
    CancelledBeforeStart,
    /// The operator pressed Cancel; it was honoured (FR-16 AC2).
    #[error(
        "{operation} was cancelled: its staged files were deleted, nothing was signed, and serial(s) {} stay reserved",
        serial_list(.reserved_serials)
    )]
    Cancelled {
        /// The cancelled operation.
        operation: OperationId,
        /// Serials that stay reserved.
        reserved_serials: Vec<Serial>,
    },
    /// Cancel was requested (internal; operations turn it into [`OpsError::Cancelled`]).
    #[error("cancel requested")]
    CancelRequested,
    /// A failure before the first persistent change: the operation was cancelled and
    /// nothing was signed or changed (FR-16 AC2).
    #[error(
        "{operation} stopped before anything was signed or changed and was cancelled ({cause}); serial(s) {} stay reserved",
        serial_list(.reserved_serials)
    )]
    Stopped {
        /// The operation.
        operation: OperationId,
        /// Serials that stay reserved.
        reserved_serials: Vec<Serial>,
        /// What went wrong.
        cause: Box<OpsError>,
    },
    /// A failure after a persistent change: the operation stays pending and the recovery
    /// screen finishes it (FR-22 AC4).
    #[error(
        "{operation} was interrupted after an irreversible step ({cause}); open the recovery screen to finish it"
    )]
    Interrupted {
        /// The operation.
        operation: OperationId,
        /// What went wrong.
        cause: Box<OpsError>,
    },
    /// A test seam stopped the operation here (never in a production build).
    #[error("injected fault at {0} (test only)")]
    InjectedFault(String),
}

impl OpsError {
    /// The operation this error belongs to, when it stopped one.
    pub fn operation(&self) -> Option<OperationId> {
        match self {
            OpsError::Cancelled { operation, .. }
            | OpsError::Stopped { operation, .. }
            | OpsError::Interrupted { operation, .. } => Some(*operation),
            _ => None,
        }
    }

    /// The underlying cause of a [`OpsError::Stopped`] or [`OpsError::Interrupted`].
    pub fn root_cause(&self) -> &OpsError {
        match self {
            OpsError::Stopped { cause, .. } | OpsError::Interrupted { cause, .. } => {
                cause.root_cause()
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send<T: Send>() {}

    #[test]
    fn fr16_ac1_every_operation_type_can_move_to_a_worker_thread() {
        // Covers: FR-16 AC1, NFR-03
        assert_send::<Ca>();
        assert_send::<CreateMasterPlan>();
        assert_send::<CreateMasterOutcome>();
        assert_send::<YubikeySetupPlan>();
        assert_send::<YubikeySecrets<'static>>();
        assert_send::<MainIntermediateOutcome>();
        assert_send::<SubIntermediatePlan>();
        assert_send::<SubIntermediateOutcome>();
        assert_send::<CrlPlan>();
        assert_send::<IssuerUnlock<'static>>();
        assert_send::<CrlOutcome>();
        assert_send::<ReplaceDrivePlan>();
        assert_send::<ReplaceDriveOutcome>();
        assert_send::<RecoveryItem>();
        assert_send::<RecoverySecrets<'static>>();
        assert_send::<StartupReport>();
        assert_send::<OpsError>();
        assert_send::<CancelFlag>();
        assert_send::<&'static dyn ProgressSink>();
    }

    #[test]
    fn errors_name_their_operation_and_cause_without_secrets() {
        let cause = OpsError::NotReady("wrong PIN".into());
        let stopped = OpsError::Stopped {
            operation: OperationId(7),
            reserved_serials: Vec::new(),
            cause: Box::new(cause),
        };
        assert_eq!(stopped.operation(), Some(OperationId(7)));
        assert!(matches!(stopped.root_cause(), OpsError::NotReady(_)));
        assert!(
            stopped.to_string().contains("operation 7") && stopped.to_string().contains("none")
        );
        let interrupted = OpsError::Interrupted {
            operation: OperationId(8),
            cause: Box::new(stopped),
        };
        assert!(matches!(interrupted.root_cause(), OpsError::NotReady(_)));
        assert!(interrupted.to_string().contains("recovery screen"));
        assert_eq!(OpsError::CancelRequested.operation(), None);
        let serial = Serial::from_hex(&format!("{:040x}", 5)).unwrap();
        let cancelled = OpsError::Cancelled {
            operation: OperationId(9),
            reserved_serials: vec![serial],
        };
        assert!(cancelled.to_string().contains(&serial.to_hex()));
        assert_eq!(cancelled.operation(), Some(OperationId(9)));
        let blocked = OpsError::Blocked(vec![Blocker::StateUnreadable("x".into())]);
        assert!(blocked.to_string().starts_with("signing is blocked: x"));
    }

    #[test]
    fn progress_steps_have_labels_and_no_progress_ignores_reports() {
        for step in [
            Step::PreparingDrives,
            Step::Journaling,
            Step::GeneratingKey,
            Step::EncryptingKey,
            Step::StagingKey,
            Step::UnlockingMaster,
            Step::ChangingPin,
            Step::ChangingPuk,
            Step::SettingManagementKey,
            Step::VerifyingHardening,
            Step::GeneratingKeyOnYubiKey,
            Step::VerifyingAttestation,
            Step::SigningCertificate,
            Step::WritingCertificateToYubiKey,
            Step::SigningCrl,
            Step::StagingOutputs,
            Step::MovingIntoPlace,
            Step::WritingAuditLog,
            Step::Completing,
            Step::Exporting,
            Step::Cancelling,
            Step::Done,
        ] {
            assert!(!step.label().is_empty());
            assert_eq!(step.to_string(), step.label());
        }
        NoProgress.report(Progress::TouchYubiKey);
    }
}
