//! Progress reports and cancel for long operations (FR-16 AC1, AC2, NFR-03).
//!
//! Every operation takes a [`ProgressSink`] and a [`crate::crypto::CancelFlag`]. The
//! GUI runs the operation on a worker thread (every operation type is `Send`) and
//! forwards each [`Progress`] to its main loop, so the window stays responsive.
//!
//! Cancel is honoured only before the operation's first persistent change: a signature,
//! a YubiKey credential change, a key generated on the YubiKey, or a file moved from
//! staging into place. [`Progress::Step::cancel_available`] tells the GUI when the
//! Cancel button must be disabled. A cancelled operation deletes its staged files,
//! marks its journal entry cancelled and keeps its reserved serial.
#![forbid(unsafe_code)]

use std::fmt;

/// Receives progress reports. Called on the thread that runs the operation; it must
/// return quickly and must not block.
pub trait ProgressSink: Send + Sync {
    /// One report.
    fn report(&self, progress: Progress);
}

impl<F: Fn(Progress) + Send + Sync> ProgressSink for F {
    fn report(&self, progress: Progress) {
        self(progress);
    }
}

/// A sink that ignores every report.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoProgress;

impl ProgressSink for NoProgress {
    fn report(&self, _progress: Progress) {}
}

/// The steps of the operations, in the words the GUI shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    /// Checking the drives and preparing the operation journal.
    PreparingDrives,
    /// Writing the pending journal entry (FR-22 AC1).
    Journaling,
    /// Generating an RSA key in software (minutes for RSA 8,192).
    GeneratingKey,
    /// Encrypting the new key with its passphrase.
    EncryptingKey,
    /// Writing the encrypted key to the staging folder of every drive.
    StagingKey,
    /// Unlocking the master key with its passphrase.
    UnlockingMaster,
    /// Changing the YubiKey PIN from the default.
    ChangingPin,
    /// Changing the YubiKey PUK from the default.
    ChangingPuk,
    /// Setting a random PIN-protected AES-256 management key.
    SettingManagementKey,
    /// Re-opening the YubiKey and confirming its hardening.
    VerifyingHardening,
    /// Generating the RSA 4,096 key on the YubiKey.
    GeneratingKeyOnYubiKey,
    /// Verifying the YubiKey's PIV attestation offline.
    VerifyingAttestation,
    /// Signing a certificate.
    SigningCertificate,
    /// Writing the certificate into the YubiKey's signing slot.
    WritingCertificateToYubiKey,
    /// Signing a CRL.
    SigningCrl,
    /// Writing every output to the staging folders and verifying them.
    StagingOutputs,
    /// Moving the outputs into place on every drive.
    MovingIntoPlace,
    /// Appending the audit-log entries on every drive.
    WritingAuditLog,
    /// Writing the completed journal entry.
    Completing,
    /// Writing files to the export drive.
    Exporting,
    /// Cancelling: deleting staged files and marking the journal entry cancelled.
    Cancelling,
    /// Finished.
    Done,
}

impl Step {
    /// One short line for the progress screen.
    pub const fn label(self) -> &'static str {
        match self {
            Step::PreparingDrives => "Checking the drives",
            Step::Journaling => "Recording the operation in the journal",
            Step::GeneratingKey => "Generating the key (this can take several minutes)",
            Step::EncryptingKey => "Encrypting the key with its passphrase",
            Step::StagingKey => "Writing the encrypted key to every drive",
            Step::UnlockingMaster => "Unlocking the master key",
            Step::ChangingPin => "Changing the YubiKey PIN",
            Step::ChangingPuk => "Changing the YubiKey PUK",
            Step::SettingManagementKey => "Setting a random management key on the YubiKey",
            Step::VerifyingHardening => "Checking the YubiKey's new settings",
            Step::GeneratingKeyOnYubiKey => "Generating the key on the YubiKey",
            Step::VerifyingAttestation => "Checking the YubiKey's attestation",
            Step::SigningCertificate => "Signing the certificate",
            Step::WritingCertificateToYubiKey => "Writing the certificate to the YubiKey",
            Step::SigningCrl => "Signing the CRL",
            Step::StagingOutputs => "Writing the files to every drive",
            Step::MovingIntoPlace => "Moving the files into place",
            Step::WritingAuditLog => "Writing the audit log",
            Step::Completing => "Finishing the operation",
            Step::Exporting => "Writing to the export drive",
            Step::Cancelling => "Cancelling",
            Step::Done => "Done",
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One progress report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// A new step started.
    Step {
        /// The step.
        step: Step,
        /// False once the operation made its first persistent change (FR-16 AC2).
        cancel_available: bool,
    },
    /// Software key generation is working (OpenSSL's prime search; the count only
    /// grows, there is no known end).
    KeyGeneration {
        /// Work done so far.
        work: u64,
    },
    /// The operator must touch the YubiKey now (it blinks); the PIN was already sent.
    TouchYubiKey,
}
