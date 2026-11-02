//! The one seam between the GUI and the operations layer (`keystone_core::ops`).
//!
//! Every "execute" step of Flows A to E, the YubiKey slot wipe and the recovery actions
//! goes through [`Backend`]. The GUI collects and validates input with core types
//! (`profile`, `passphrase`, `token`, `clock`), builds one *plan* struct per action and
//! hands it over on a worker thread together with an [`ExecContext`]. It gets back a
//! [`FlowOutcome`] to show (write-and-verify result per drive, SHA-256 fingerprints) or
//! a [`BackendError`].
//!
//! Until the operations layer is merged, [`NotConnected`] is the only implementation:
//! every execute function returns [`BackendError::NotConnected`] and nothing is written.
//!
//! # Contract for the implementation that wires this to `ops`
//! - Run on the worker thread that calls it; never touch GTK.
//! - Plans own their secrets (`ConfirmedPassphrase`, `EnteredPassphrase`, `NewPin`,
//!   `NewPuk`, `SecretString`); drop them as soon as they are used. Never log them.
//! - Call `ctx.progress.report(..)` for progress, and
//!   `ctx.progress.begin_persistent_change()?` right before the first persistent change
//!   (FR-16 AC2). Pass `ctx.progress.cancel_flag()` to `crypto::generate_rsa`.
//!   On cancel, clean up as FR-16 AC2 says and return [`BackendError::Cancelled`].
//! - Use `ctx.clock` as the confirmed time (FR-17 AC1, SEC-16): `ctx.clock.confirmed`
//!   is what the operator confirmed; `ctx.clock.now()` adds the time elapsed since then.
//! - Re-check every rule (drive sync, pending operations, serial uniqueness, validity
//!   against the issuer, CRL existence): the GUI only greys out what is obviously not
//!   possible.
//! - Fill [`FlowOutcome`] with every drive written and its read-back result (FR-12 AC2)
//!   and the SHA-256 fingerprint of every certificate created (FR-20).
#![forbid(unsafe_code)]
// The GUI fills every plan field; only the operations-layer implementation reads them.
// Remove this allowance when `NotConnected` is replaced by the real implementation.
#![allow(
    dead_code,
    reason = "plan fields are read by the operations layer, which is not wired yet"
)]

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use keystone_core::clock::ConfirmedTime;
use keystone_core::crypto::secret::SecretString;
use keystone_core::model::{CaLevel, Fingerprint, RevocationReason, Serial, Timestamp};
use keystone_core::passphrase::{ConfirmedPassphrase, EnteredPassphrase};
use keystone_core::profile::{CrlLocation, NameConstraintsChoice, ValidatedName};
use keystone_core::store::{OperationId, RecoveryAction};
use keystone_core::token::{DeviceInfo, NewPin, NewPuk, TokenSigner, WipeConfirmation};

use crate::worker::Progress;

/// The YubiKey the GUI detected, shared with the worker thread that uses it.
#[derive(Clone)]
pub struct SharedToken(Arc<Mutex<Box<dyn TokenSigner>>>);

impl SharedToken {
    /// Wraps a token.
    pub fn new(token: Box<dyn TokenSigner>) -> Self {
        SharedToken(Arc::new(Mutex::new(token)))
    }

    /// Exclusive access to the token (a poisoned lock is recovered: the token keeps
    /// its own state and every rule is re-checked by core).
    pub fn lock(&self) -> std::sync::MutexGuard<'_, Box<dyn TokenSigner>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl fmt::Debug for SharedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedToken(YubiKey)")
    }
}

/// The folders the operator chose (FR-12 AC1: a primary and at least one backup).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveSelection {
    /// The primary CA drive.
    pub primary: PathBuf,
    /// Backup CA drives (at least one).
    pub backups: Vec<PathBuf>,
    /// The export drive or folder (carried to issuing systems).
    pub export: PathBuf,
}

impl DriveSelection {
    /// Every CA drive, primary first.
    pub fn ca_drives(&self) -> Vec<&std::path::Path> {
        std::iter::once(self.primary.as_path())
            .chain(self.backups.iter().map(PathBuf::as_path))
            .collect()
    }
}

/// The time the operator confirmed (FR-17 AC1) and when, on the monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockConfirmation {
    /// The confirmed time.
    pub confirmed: ConfirmedTime,
    /// When it was confirmed.
    pub at: Instant,
}

impl ClockConfirmation {
    /// A confirmation made now.
    pub fn new(confirmed: ConfirmedTime) -> Self {
        ClockConfirmation {
            confirmed,
            at: Instant::now(),
        }
    }

    /// The confirmed time plus the time elapsed since the confirmation (whole seconds).
    pub fn now(&self) -> Timestamp {
        let elapsed = time::Duration::try_from(self.at.elapsed()).unwrap_or(time::Duration::ZERO);
        let base = self.confirmed.get().get();
        let advanced = base.checked_add(elapsed).unwrap_or(base);
        Timestamp::utc(advanced.replace_nanosecond(0).unwrap_or(base))
    }
}

/// Everything an execute step needs besides its plan.
#[derive(Debug)]
pub struct ExecContext {
    /// The drives to write.
    pub drives: DriveSelection,
    /// The confirmed time (FR-17, SEC-16).
    pub clock: ClockConfirmation,
    /// Progress and cancel (FR-16).
    pub progress: Progress,
    /// The YubiKey, for steps that need it.
    pub token: Option<SharedToken>,
}

/// Flow A: create the master (FR-02, FR-03, FR-04, FR-13 AC6).
#[derive(Debug)]
pub struct CreateMasterPlan {
    /// Validated name fields.
    pub name: ValidatedName,
    /// Validity in whole years (1 to 25, FR-10 AC3).
    pub validity_years: u8,
    /// The confirmed passphrase that encrypts the master key.
    pub passphrase: ConfirmedPassphrase,
}

/// How the YubiKey's PIN is provided in Flow B.
#[derive(Debug)]
pub enum YubikeyCredentials {
    /// Factory defaults: set this new PIN and PUK, then a random management key (FR-06).
    SetNew {
        /// The new PIN (entered twice).
        pin: NewPin,
        /// The new PUK (entered twice).
        puk: NewPuk,
    },
    /// Already hardened: the current PIN.
    Existing {
        /// The current PIN.
        pin: SecretString,
    },
}

/// Flow B: set up the YubiKey and create the main intermediate (FR-05 to FR-07).
#[derive(Debug)]
pub struct SetupYubikeyPlan {
    /// The device shown to the operator before any action (FR-05 AC3).
    pub device: DeviceInfo,
    /// PIN (and PUK) for hardening and signing.
    pub credentials: YubikeyCredentials,
    /// The master's CRL address, when it is asked now (FR-18: once, before the
    /// master's first child). `None`: already set.
    pub master_crl: Option<CrlLocation>,
    /// Main intermediate name.
    pub name: ValidatedName,
    /// Validity in whole years (1 to 15, never past the master).
    pub validity_years: u8,
    /// Unlocks the master key.
    pub master_passphrase: EnteredPassphrase,
}

/// Flow C: create a sub-intermediate (FR-08, FR-09, FR-21).
#[derive(Debug)]
pub struct SubIntermediatePlan {
    /// Validated name fields.
    pub name: ValidatedName,
    /// Validity in whole years (1 to 10, never past the main intermediate).
    pub validity_years: u8,
    /// Name constraints (on by default, FR-21 AC1).
    pub name_constraints: NameConstraintsChoice,
    /// The main intermediate's CRL address, when asked now (FR-18). `None`: already set.
    pub issuer_crl: Option<CrlLocation>,
    /// The confirmed 10-word passphrase that encrypts the new key.
    pub passphrase: ConfirmedPassphrase,
    /// The YubiKey PIN (the main intermediate signs; PIN + touch).
    pub pin: SecretString,
}

/// Who signs a CRL, and the secret that unlocks it.
#[derive(Debug)]
pub enum IssuerCredential {
    /// The master signs (main intermediates): its passphrase.
    MasterPassphrase(EnteredPassphrase),
    /// The main intermediate on the YubiKey signs (sub-intermediates): the PIN.
    YubikeyPin(SecretString),
}

/// Flow D: revoke a certificate and publish a new CRL (FR-13).
#[derive(Debug)]
pub struct RevokePlan {
    /// The certificate to revoke.
    pub serial: Serial,
    /// Its level (decides who signs).
    pub level: CaLevel,
    /// The reason.
    pub reason: RevocationReason,
    /// The issuer's secret.
    pub credential: IssuerCredential,
}

/// FR-13 AC4: re-sign an issuer's current CRL.
#[derive(Debug)]
pub struct RefreshCrlPlan {
    /// The issuing certificate (master or main intermediate).
    pub issuer: Serial,
    /// The issuer's secret.
    pub credential: IssuerCredential,
}

/// Flow E: replace a lost YubiKey (FR-15). Flow B follows on the new YubiKey.
#[derive(Debug)]
pub struct ReplaceYubikeyPlan {
    /// The old main intermediate to revoke.
    pub old_main_intermediate: Serial,
    /// Unlocks the master key.
    pub master_passphrase: EnteredPassphrase,
}

/// FR-07 AC4: wipe the YubiKey signing slot after the typed-serial confirmation.
#[derive(Debug)]
pub struct WipeSlotPlan {
    /// Proof that the operator typed this YubiKey's serial number.
    pub confirmation: WipeConfirmation,
    /// The YubiKey PIN.
    pub pin: SecretString,
}

/// FR-22 AC4, AC5, AC7: a recovery action chosen on the recovery screen.
#[derive(Debug)]
pub struct RecoveryPlan {
    /// The interrupted operation.
    pub operation: OperationId,
    /// The chosen action (one the recovery report offered).
    pub action: RecoveryAction,
    /// For resuming YubiKey setup: the PIN, PUK or passphrase the remaining steps need.
    pub resume: Option<ResumeCredentials>,
}

/// Secrets for resuming an interrupted YubiKey setup (FR-22 AC7). The operator is
/// asked again for a PIN or PUK that was already set; nothing is stored.
#[derive(Debug, Default)]
pub struct ResumeCredentials {
    /// The PIN set before the interruption.
    pub current_pin: Option<SecretString>,
    /// A new PIN, when the PIN step is still to do.
    pub new_pin: Option<NewPin>,
    /// A new PUK, when the PUK step is still to do.
    pub new_puk: Option<NewPuk>,
    /// Unlocks the master to sign the main intermediate.
    pub master_passphrase: Option<EnteredPassphrase>,
}

/// One drive's write-and-verify result (FR-12 AC1, AC2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveWriteResult {
    /// Drive label.
    pub drive: String,
    /// Every copy was read back and matched its SHA-256.
    pub verified: bool,
    /// Files written (paths inside the drive).
    pub files: Vec<String>,
}

/// A certificate created by the action (FR-20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSummary {
    /// Subject (`CN=...`).
    pub subject: String,
    /// Level.
    pub level: CaLevel,
    /// Serial number.
    pub serial: Serial,
    /// SHA-256 fingerprint of the DER certificate.
    pub fingerprint: Fingerprint,
}

/// A CRL signed by the action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlSummary {
    /// Issuer (`CN=...`).
    pub issuer: String,
    /// CRL number.
    pub crl_number: u64,
    /// nextUpdate.
    pub next_update: Timestamp,
}

/// What the GUI should offer next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowUp {
    /// Flow E: continue with Flow B on the new YubiKey.
    SetUpNewYubikey,
    /// Flow E: re-issue these sub-intermediates under the new main intermediate.
    ReissueSubIntermediates(Vec<Serial>),
}

/// The result of an execute step, shown on the result screen.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FlowOutcome {
    /// One line: what was done.
    pub title: String,
    /// Per CA drive: written and read back (FR-12).
    pub drive_writes: Vec<DriveWriteResult>,
    /// Files written to the export folder.
    pub export_files: Vec<PathBuf>,
    /// Certificates created, with fingerprints (FR-20).
    pub certificates: Vec<CertificateSummary>,
    /// CRLs signed.
    pub crls: Vec<CrlSummary>,
    /// Plain sentences for the operator (for example "upload the CRL").
    pub notes: Vec<String>,
    /// What to do next.
    pub follow_up: Vec<FollowUp>,
}

/// Why an execute step did not succeed. Never contains a secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// The operations layer is not connected to this build yet.
    #[error(
        "{action} is not connected yet: this build's operations layer is not wired to the GUI. Nothing was written to any drive or YubiKey."
    )]
    NotConnected {
        /// What was asked for.
        action: &'static str,
    },
    /// Cancelled before any persistent change (FR-16 AC2).
    #[error(
        "Cancelled before anything permanent was done. Staged files were removed; the reserved serial number stays reserved."
    )]
    Cancelled,
    /// The action failed; the message says what happened and what to do.
    #[error("{0}")]
    Failed(String),
}

/// The operations the GUI needs. One method per execute step; see the module
/// documentation for the contract.
pub trait Backend: Send + Sync + fmt::Debug {
    /// Flow A.
    fn create_master(
        &self,
        ctx: ExecContext,
        plan: CreateMasterPlan,
    ) -> Result<FlowOutcome, BackendError>;
    /// Flow B.
    fn setup_yubikey(
        &self,
        ctx: ExecContext,
        plan: SetupYubikeyPlan,
    ) -> Result<FlowOutcome, BackendError>;
    /// Flow C.
    fn create_sub_intermediate(
        &self,
        ctx: ExecContext,
        plan: SubIntermediatePlan,
    ) -> Result<FlowOutcome, BackendError>;
    /// Flow D.
    fn revoke(&self, ctx: ExecContext, plan: RevokePlan) -> Result<FlowOutcome, BackendError>;
    /// FR-13 AC4.
    fn refresh_crl(
        &self,
        ctx: ExecContext,
        plan: RefreshCrlPlan,
    ) -> Result<FlowOutcome, BackendError>;
    /// Flow E (Flow B follows).
    fn replace_yubikey(
        &self,
        ctx: ExecContext,
        plan: ReplaceYubikeyPlan,
    ) -> Result<FlowOutcome, BackendError>;
    /// FR-07 AC4.
    fn wipe_signing_slot(
        &self,
        ctx: ExecContext,
        plan: WipeSlotPlan,
    ) -> Result<FlowOutcome, BackendError>;
    /// FR-22 AC4, AC5, AC7.
    fn recover(&self, ctx: ExecContext, plan: RecoveryPlan) -> Result<FlowOutcome, BackendError>;
    /// FR-18: the CRL address already set for the CA certificate at `issuer` (a
    /// master or main intermediate), or `None` when it has not been asked yet. An
    /// error means "unknown": the GUI then asks for it.
    fn issuer_crl_location(
        &self,
        drives: &DriveSelection,
        issuer: Serial,
    ) -> Result<Option<CrlLocation>, BackendError>;
}

/// The backend of this build: the operations layer is not connected yet.
#[derive(Debug, Default, Clone, Copy)]
pub struct NotConnected;

impl NotConnected {
    fn refuse(action: &'static str) -> Result<FlowOutcome, BackendError> {
        Err(BackendError::NotConnected { action })
    }
}

impl Backend for NotConnected {
    fn create_master(
        &self,
        _ctx: ExecContext,
        _plan: CreateMasterPlan,
    ) -> Result<FlowOutcome, BackendError> {
        Self::refuse("Creating the master")
    }

    fn setup_yubikey(
        &self,
        _ctx: ExecContext,
        _plan: SetupYubikeyPlan,
    ) -> Result<FlowOutcome, BackendError> {
        Self::refuse("Setting up the YubiKey")
    }

    fn create_sub_intermediate(
        &self,
        _ctx: ExecContext,
        _plan: SubIntermediatePlan,
    ) -> Result<FlowOutcome, BackendError> {
        Self::refuse("Creating a sub-intermediate")
    }

    fn revoke(&self, _ctx: ExecContext, _plan: RevokePlan) -> Result<FlowOutcome, BackendError> {
        Self::refuse("Revoking a certificate")
    }

    fn refresh_crl(
        &self,
        _ctx: ExecContext,
        _plan: RefreshCrlPlan,
    ) -> Result<FlowOutcome, BackendError> {
        Self::refuse("Refreshing a CRL")
    }

    fn replace_yubikey(
        &self,
        _ctx: ExecContext,
        _plan: ReplaceYubikeyPlan,
    ) -> Result<FlowOutcome, BackendError> {
        Self::refuse("Replacing the YubiKey")
    }

    fn wipe_signing_slot(
        &self,
        _ctx: ExecContext,
        _plan: WipeSlotPlan,
    ) -> Result<FlowOutcome, BackendError> {
        Self::refuse("Wiping the YubiKey signing slot")
    }

    fn recover(&self, _ctx: ExecContext, _plan: RecoveryPlan) -> Result<FlowOutcome, BackendError> {
        Self::refuse("Recovering the interrupted operation")
    }

    fn issuer_crl_location(
        &self,
        _drives: &DriveSelection,
        _issuer: Serial,
    ) -> Result<Option<CrlLocation>, BackendError> {
        Err(BackendError::NotConnected {
            action: "Reading the stored CRL address",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::clock::{assess, confirm};
    use keystone_core::passphrase::NewPassphrase;
    use keystone_core::profile::ValidatedName;

    fn clock() -> ClockConfirmation {
        let build = keystone_core::build_info::build_date();
        let now = build + time::Duration::days(1);
        ClockConfirmation::new(confirm(&assess(now, None, build), false).expect("confirm"))
    }

    fn ctx() -> ExecContext {
        ExecContext {
            drives: DriveSelection {
                primary: "/nonexistent/a".into(),
                backups: vec!["/nonexistent/b".into()],
                export: "/nonexistent/e".into(),
            },
            clock: clock(),
            progress: Progress::new(true).0,
            token: None,
        }
    }

    fn confirmed_passphrase() -> ConfirmedPassphrase {
        let mut session = NewPassphrase::generate_master(10)
            .expect("generate")
            .into_confirmation();
        session.set_written_down(true);
        let words: Vec<&'static str> = (1..=10)
            .map(|n| session.view_words().word(n).expect("word"))
            .collect();
        for (index, word) in words.iter().enumerate() {
            session.enter_word(index + 1, word).expect("enter");
        }
        for group in 1..=session.group_count() {
            session.check_group(group).expect("check");
        }
        session.finish().expect("confirmed")
    }

    #[test]
    fn every_execute_step_reports_not_connected_and_writes_nothing() {
        let backend = NotConnected;
        let name = ValidatedName::new(&keystone_core::model::NameFields {
            common_name: "KEYSTONE TEST Root".into(),
            organization: None,
            country: None,
        })
        .expect("name");
        let result = backend.create_master(
            ctx(),
            CreateMasterPlan {
                name,
                validity_years: 20,
                passphrase: confirmed_passphrase(),
            },
        );
        let error = result.expect_err("not connected");
        assert!(matches!(error, BackendError::NotConnected { .. }));
        assert!(error.to_string().contains("not connected yet"));
        assert!(error.to_string().contains("Nothing was written"));
        let mut serial = [0u8; 20];
        serial[19] = 1;
        let serial = Serial::from_bytes(serial).expect("serial");
        assert!(matches!(
            backend.refresh_crl(
                ctx(),
                RefreshCrlPlan {
                    issuer: serial,
                    credential: IssuerCredential::YubikeyPin(
                        SecretString::from_str_copy("654321").expect("secret")
                    ),
                }
            ),
            Err(BackendError::NotConnected { .. })
        ));
        assert!(backend.issuer_crl_location(&ctx().drives, serial).is_err());
    }

    #[test]
    fn sec07_plans_never_print_secrets() {
        // Covers: SEC-07
        let plan = RefreshCrlPlan {
            issuer: Serial::from_bytes([1; 20]).expect("serial"),
            credential: IssuerCredential::YubikeyPin(
                SecretString::from_str_copy("918273").expect("secret"),
            ),
        };
        let shown = format!("{plan:?}");
        assert!(!shown.contains("918273"), "{shown}");
        assert!(shown.contains("REDACTED"));
    }

    #[test]
    fn fr17_clock_confirmation_advances_with_elapsed_time() {
        // Covers: FR-17 AC1
        let confirmation = clock();
        assert!(confirmation.now() >= confirmation.confirmed.get());
        assert_eq!(confirmation.now().get().nanosecond(), 0);
    }

    #[test]
    fn drive_selection_lists_primary_first() {
        let selection = ctx().drives;
        let drives = selection.ca_drives();
        assert_eq!(drives.len(), 2);
        assert_eq!(drives[0], std::path::Path::new("/nonexistent/a"));
    }
}
