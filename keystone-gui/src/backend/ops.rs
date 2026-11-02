//! [`OpsBackend`]: every execute step of the GUI through `keystone_core::ops`.
//!
//! - Each step opens the CA on the chosen drives, plans with the confirmed time
//!   (`ExecContext::clock.confirmed`, used by this one step only, SEC-16), and executes
//!   with the plan's secrets. Every rule is re-checked by `ops` (drive sync, pending
//!   operations, serial uniqueness, validity against the issuer, CRL existence).
//! - Progress: `ops` reports go to the worker's [`Progress`] ([`Sink`]). Just before a
//!   step that makes the first persistent change (a signature, a YubiKey change, an
//!   output moved into place) the sink calls `Progress::begin_persistent_change`, so
//!   the Cancel button disappears before the point of no return (FR-16 AC2); the
//!   worker's Cancel sets the core `CancelFlag` that `ops` and key generation poll.
//! - The result: per CA drive, every output of the operation is read back again and
//!   compared with the SHA-256 its completed journal entry lists
//!   (`DriveSet::export_ready`, FR-12 AC2, FR-22 AC2); the SHA-256 fingerprint of every
//!   new certificate (FR-20); the new CRL; what went to the export drive.
//! - Errors become one plain sentence ([`BackendError`]); no secret is ever in it.
#![forbid(unsafe_code)]

use std::path::Path;
#[cfg(not(feature = "production"))]
use std::time::{Duration, Instant};

use keystone_core::crypto::CryptoError;
use keystone_core::model::{CaLevel, Serial, Timestamp};
use keystone_core::ops::{
    self, Ca, CreateMasterRequest, ExportStatus, IssuerUnlock, MainIntermediateRequest, OpsError,
    PinEntry, ProgressSink, RecoveryAction, RecoveryItem, RecoverySecrets, Step,
    SubIntermediateRequest, YubikeySecrets,
};
use keystone_core::profile::CrlLocation;
use keystone_core::store::{OperationId, OperationKind, OutputDir};
use keystone_core::token::{AttestationTrust, TokenSigner};

use super::{
    Backend, BackendError, CertificateSummary, ClockConfirmation, CreateMasterPlan, CrlSummary,
    DriveReplacementReview, DriveSelection, DriveWriteResult, ExecContext, FlowOutcome, FollowUp,
    IssuerCredential, RecoveryPlan, RefreshCrlPlan, ReplaceDrivePlan, ReplaceYubikeyPlan,
    RevokePlan, SetupYubikeyPlan, SharedToken, SubIntermediatePlan, WipeSlotPlan,
    YubikeyCredentials,
};
use crate::worker::Progress;

/// The longest the slow-keygen test hook holds key generation (development builds).
#[cfg(not(feature = "production"))]
pub const SLOW_KEYGEN_LIMIT: Duration = Duration::from_secs(300);

/// The backend that runs every step through the operations layer.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpsBackend {
    /// NFR-03 test hook: key generation waits for Cancel (development builds only).
    #[cfg(not(feature = "production"))]
    slow_keygen: bool,
}

impl OpsBackend {
    /// The backend for this run. `options` can switch on development test hooks.
    pub fn new(options: &crate::cli::Options) -> Self {
        #[cfg(not(feature = "production"))]
        {
            OpsBackend {
                slow_keygen: options.test_hook == Some(crate::cli::TestHook::SlowKeygen),
            }
        }
        #[cfg(feature = "production")]
        {
            let _ = options;
            OpsBackend {}
        }
    }

    fn sink<'a>(&self, progress: &'a Progress) -> Sink<'a> {
        Sink {
            progress,
            #[cfg(not(feature = "production"))]
            slow_keygen: self.slow_keygen.then(|| Instant::now() + SLOW_KEYGEN_LIMIT),
        }
    }
}

/// Forwards `ops` progress to the worker (FR-16 AC1, AC2, NFR-03).
struct Sink<'a> {
    progress: &'a Progress,
    #[cfg(not(feature = "production"))]
    slow_keygen: Option<Instant>,
}

/// True when `step` starts the operation's first persistent change, or comes after it.
fn ends_cancellable_phase(step: Step, cancel_available: bool) -> bool {
    match step {
        Step::Cancelling => false,
        Step::SigningCertificate
        | Step::SigningCrl
        | Step::ChangingPin
        | Step::ChangingPuk
        | Step::SettingManagementKey
        | Step::GeneratingKeyOnYubiKey
        | Step::WritingCertificateToYubiKey
        | Step::MovingIntoPlace => true,
        _ => !cancel_available,
    }
}

impl ProgressSink for Sink<'_> {
    fn report(&self, progress: ops::Progress) {
        match progress {
            ops::Progress::Step {
                step,
                cancel_available,
            } => {
                if ends_cancellable_phase(step, cancel_available) {
                    // A Cancel accepted a moment ago (after ops' last check) cannot stop
                    // this step any more; the outcome then says so (see `cancel_note`).
                    let _ = self.progress.begin_persistent_change();
                }
                self.progress.report(None, format!("{}.", step.label()));
            }
            ops::Progress::KeyGeneration { work } => {
                self.progress.report(
                    None,
                    format!(
                        "Generating the key (this can take several minutes): {work} candidate numbers tested so far."
                    ),
                );
                #[cfg(not(feature = "production"))]
                if let Some(deadline) = self.slow_keygen {
                    // NFR-03 E2E hook: hold the generation until Cancel (or the limit).
                    while !self.progress.cancel_requested() && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            }
            ops::Progress::TouchYubiKey => self.progress.report(
                None,
                "Touch the YubiKey now: it is blinking. The PIN was already sent.",
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// The cause of an `ops` error in words for the operator. Never contains a secret
/// (no `OpsError` does).
pub(crate) fn cause_text(error: &OpsError) -> String {
    match error.root_cause() {
        OpsError::Crypto(CryptoError::WrongPassphrase) => {
            "the master passphrase is wrong, or the master key file is damaged; nothing was decrypted. Check the words on your paper record and try again".to_string()
        }
        OpsError::Crypto(
            e @ (CryptoError::Der(_)
            | CryptoError::Pem(_)
            | CryptoError::UnsupportedKeyEncryption(_)
            | CryptoError::NotEncrypted),
        ) => format!(
            "a file Keystone needed on the primary drive cannot be read ({e}); this is not a wrong passphrase. Check the drives"
        ),
        OpsError::Crypto(e @ CryptoError::SecureHeapUnavailable { .. }) => e.to_string(),
        other => other.to_string(),
    }
}

/// Turns an `ops` error into what the error screen shows.
pub(crate) fn failure(action: &str, error: OpsError) -> BackendError {
    match &error {
        OpsError::Cancelled { .. } | OpsError::CancelledBeforeStart => BackendError::Cancelled,
        OpsError::Interrupted { operation, .. } => BackendError::Failed(format!(
            "{action} was interrupted after a permanent step: {}. Open the recovery screen from the start-up checks to finish {operation}; nothing will be signed twice.",
            cause_text(&error)
        )),
        OpsError::Stopped {
            operation,
            reserved_serials,
            ..
        } => BackendError::Failed(format!(
            "{action} stopped before anything was signed or changed: {}. {} was cancelled{}.",
            cause_text(&error),
            capitalised(&operation.to_string()),
            if reserved_serials.is_empty() {
                String::new()
            } else {
                format!(
                    " and its serial number{} {} stay{} reserved",
                    if reserved_serials.len() == 1 { "" } else { "s" },
                    reserved_serials
                        .iter()
                        .map(Serial::to_hex)
                        .collect::<Vec<_>>()
                        .join(", "),
                    if reserved_serials.len() == 1 { "s" } else { "" }
                )
            }
        )),
        _ => BackendError::Failed(format!("{action} did not run: {}.", cause_text(&error))),
    }
}

fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn open(action: &str, drives: &DriveSelection) -> Result<Ca, BackendError> {
    Ca::open(&drives.ca_drives()).map_err(|e| failure(action, e))
}

fn need_token<'a>(
    action: &str,
    token: Option<&'a SharedToken>,
) -> Result<&'a SharedToken, BackendError> {
    token.ok_or_else(|| {
        BackendError::Failed(format!(
            "{action} did not run: no YubiKey is connected. Insert the YubiKey and try again."
        ))
    })
}

/// Trust anchors for the YubiKey's PIV attestation (FR-07 AC5). The simulator build
/// trusts the simulator's test root; a build without the real driver has none.
fn attestation_trust() -> Option<AttestationTrust> {
    #[cfg(feature = "simulator")]
    {
        Some(keystone_testkit::simulator::test_attestation_trust())
    }
    #[cfg(not(feature = "simulator"))]
    {
        None
    }
}

fn trust(action: &'static str) -> Result<AttestationTrust, BackendError> {
    attestation_trust().ok_or(BackendError::NotConnected {
        action,
        reason: "this build has no YubiKey driver, so it has no Yubico attestation roots",
    })
}

// ---------------------------------------------------------------------------
// The outcome shown on the result screen
// ---------------------------------------------------------------------------

/// FR-12 AC2, FR-22 AC2: every output of `operation` read back from every drive and
/// compared with its completed entry's SHA-256.
fn drive_writes(ca: &Ca, operation: OperationId) -> Vec<DriveWriteResult> {
    let drives = ca.drive_set().drives();
    match ca.drive_set().export_ready(operation) {
        Ok((outputs, verified)) => drives
            .iter()
            .enumerate()
            .map(|(index, drive)| DriveWriteResult {
                drive: drive.label(),
                verified: verified.contains(&index),
                files: outputs
                    .iter()
                    .map(|output| output.path.to_string())
                    .collect(),
            })
            .collect(),
        Err(_) => drives
            .iter()
            .map(|drive| DriveWriteResult {
                drive: drive.label(),
                verified: false,
                files: Vec::new(),
            })
            .collect(),
    }
}

fn certificate(ca: &Ca, serial: Serial) -> Option<CertificateSummary> {
    let state = ca.state().ok()?;
    let cert = state.certificate(serial)?;
    Some(CertificateSummary {
        subject: cert.record.subject.display(),
        level: cert.level(),
        serial,
        fingerprint: cert.record.fingerprint,
    })
}

fn current_crl(ca: &Ca, issuer: Serial) -> Option<CrlSummary> {
    let state = ca.state().ok()?;
    let issuer_cert = state.certificate(issuer)?;
    let crl = state.current_crl(issuer)?;
    Some(CrlSummary {
        issuer: issuer_cert.record.subject.display(),
        crl_number: crl.info.crl_number,
        next_update: Timestamp::utc(crl.info.next_update),
    })
}

fn apply_export(outcome: &mut FlowOutcome, export: ExportStatus) {
    match export {
        ExportStatus::Written(files) => {
            outcome.export_files = files.into_iter().map(|file| file.path).collect();
        }
        ExportStatus::NotRequested => {}
        ExportStatus::Failed(reason) => outcome.notes.push(format!(
            "The operation is complete on every CA drive, but writing to the export drive failed: {reason}. The files stay on the CA drives; check the export drive."
        )),
    }
}

/// A Cancel the operator pressed in the moment before the point of no return.
fn cancel_note(outcome: &mut FlowOutcome, progress: &Progress) {
    if progress.cancel_requested() {
        outcome.notes.push(
            "Cancel was pressed as the first permanent step began, so the operation was finished instead."
                .to_string(),
        );
    }
}

fn outcome(title: impl Into<String>, ca: &Ca, operation: OperationId) -> FlowOutcome {
    FlowOutcome {
        title: title.into(),
        drive_writes: drive_writes(ca, operation),
        ..FlowOutcome::default()
    }
}

fn exports_something(ca: &Ca, operation: OperationId) -> bool {
    let Ok((outputs, _)) = ca.drive_set().export_ready(operation) else {
        return false;
    };
    let kind = ca
        .drive_set()
        .drives()
        .first()
        .and_then(|drive| drive.operation_journal(operation).ok().flatten())
        .map(|journal| journal.kind());
    outputs.iter().any(|output| match kind {
        Some(OperationKind::CreateSubIntermediate) => {
            matches!(output.path.dir(), OutputDir::Certs | OutputDir::Keys)
        }
        _ => output.path.dir() == OutputDir::Crls,
    })
}

const UPLOAD_MASTER_CRL: &str = "Upload the master's first CRL from the export drive to StarnetAuth (or wherever the master's CRL address points) before the main intermediate is deployed.";

// ---------------------------------------------------------------------------
// The steps
// ---------------------------------------------------------------------------

impl Backend for OpsBackend {
    fn create_master(
        &self,
        ctx: ExecContext,
        plan: CreateMasterPlan,
    ) -> Result<FlowOutcome, BackendError> {
        const ACTION: &str = "Creating the master";
        let Some(primary) = ctx.drives.primary.clone() else {
            return Err(BackendError::Failed(format!(
                "{ACTION} did not run: choose the primary drive and at least one backup drive."
            )));
        };
        let request = CreateMasterRequest {
            primary,
            backups: ctx.drives.backups.clone(),
            subject: plan.name.to_fields(),
            validity_years: plan.validity_years,
        };
        let planned = ops::plan_create_master(request, ctx.clock.confirmed)
            .map_err(|e| failure(ACTION, e))?;
        let sink = self.sink(&ctx.progress);
        let done = planned
            .execute(
                &plan.passphrase,
                Some(&ctx.drives.export),
                &sink,
                &ctx.progress.cancel_flag(),
            )
            .map_err(|e| failure(ACTION, e))?;
        drop(plan.passphrase);
        let mut result = outcome(
            "The master (root) certificate was created",
            &done.ca,
            done.operation,
        );
        result
            .certificates
            .extend(certificate(&done.ca, done.serial));
        result.crls.extend(current_crl(&done.ca, done.serial));
        apply_export(&mut result, done.export);
        result.notes.push(UPLOAD_MASTER_CRL.to_string());
        cancel_note(&mut result, &ctx.progress);
        Ok(result)
    }

    fn setup_yubikey(
        &self,
        ctx: ExecContext,
        plan: SetupYubikeyPlan,
    ) -> Result<FlowOutcome, BackendError> {
        const ACTION: &str = "Setting up the YubiKey";
        let trust = trust(ACTION)?;
        let shared = need_token(ACTION, ctx.token.as_ref())?;
        let ca = open(ACTION, &ctx.drives)?;
        let request = MainIntermediateRequest {
            subject: plan.name.to_fields(),
            validity_years: plan.validity_years,
            master_crl: plan.master_crl.clone(),
        };
        let mut token = shared.lock();
        let planned = ca
            .plan_yubikey_setup(&mut **token, &request, ctx.clock.confirmed)
            .map_err(|e| failure(ACTION, e))?;
        if planned.device().serial != plan.device.serial {
            return Err(BackendError::Failed(format!(
                "{ACTION} did not run: this is YubiKey {}, but the flow was started with YubiKey {}. Start the flow again.",
                planned.device().serial,
                plan.device.serial
            )));
        }
        let (pin, new_puk) = match plan.credentials {
            YubikeyCredentials::SetNew { pin, puk } => (PinEntry::New(pin), Some(puk)),
            YubikeyCredentials::Existing { pin } => (PinEntry::Current(pin), None),
        };
        let secrets = YubikeySecrets {
            pin,
            new_puk,
            master_passphrase: Some(&plan.master_passphrase),
        };
        let sink = self.sink(&ctx.progress);
        let done = planned
            .execute(
                &ca,
                &mut **token,
                &secrets,
                &trust,
                Some(&ctx.drives.export),
                &sink,
                &ctx.progress.cancel_flag(),
            )
            .map_err(|e| failure(ACTION, e))?;
        drop(secrets);
        drop(token);
        Ok(main_intermediate_outcome(&ca, done, &ctx.progress))
    }

    fn create_sub_intermediate(
        &self,
        ctx: ExecContext,
        plan: SubIntermediatePlan,
    ) -> Result<FlowOutcome, BackendError> {
        const ACTION: &str = "Creating the sub-intermediate";
        let shared = need_token(ACTION, ctx.token.as_ref())?;
        let ca = open(ACTION, &ctx.drives)?;
        let request = SubIntermediateRequest {
            subject: plan.name.to_fields(),
            validity_years: plan.validity_years,
            name_constraints: plan.name_constraints.clone(),
            main_crl: plan.issuer_crl.clone(),
        };
        let planned = ca
            .plan_sub_intermediate(&request, ctx.clock.confirmed)
            .map_err(|e| failure(ACTION, e))?;
        let sink = self.sink(&ctx.progress);
        let mut token = shared.lock();
        let done = planned
            .execute(
                &ca,
                &mut **token,
                &plan.pin,
                &plan.passphrase,
                Some(&ctx.drives.export),
                &sink,
                &ctx.progress.cancel_flag(),
            )
            .map_err(|e| failure(ACTION, e))?;
        drop(token);
        drop(plan.pin);
        drop(plan.passphrase);
        let mut result = outcome("The sub-intermediate was created", &ca, done.operation);
        result.certificates.extend(certificate(&ca, done.serial));
        apply_export(&mut result, done.export);
        result.notes.push(format!(
            "Files: {stem}.crt (certificate), {stem}.key (encrypted key) and {stem}-chain.pem (sub-intermediate, main intermediate, master). Carry them with the export drive to the issuing system together with the 10-word passphrase from your paper record.",
            stem = done.file_stem
        ));
        cancel_note(&mut result, &ctx.progress);
        Ok(result)
    }

    fn revoke(&self, ctx: ExecContext, plan: RevokePlan) -> Result<FlowOutcome, BackendError> {
        const ACTION: &str = "Revoking the certificate";
        let ca = open(ACTION, &ctx.drives)?;
        let planned = ca
            .plan_revoke(plan.serial, plan.reason, ctx.clock.confirmed)
            .map_err(|e| failure(ACTION, e))?;
        let level = if planned.needs_master() {
            CaLevel::MainIntermediate
        } else {
            CaLevel::SubIntermediate
        };
        if level != plan.level {
            return Err(BackendError::Failed(format!(
                "{ACTION} did not run: the record changed since the certificate was chosen. Choose it again."
            )));
        }
        let done = sign_crl(self, &ctx, &ca, planned, plan.credential, ACTION)?;
        let mut result = crl_outcome(
            "The certificate was revoked and a new CRL signed",
            &ca,
            &done,
        );
        if !done.revoked_by_ancestor.is_empty() {
            result.follow_up.push(FollowUp::ReissueSubIntermediates(
                done.revoked_by_ancestor.clone(),
            ));
        }
        cancel_note(&mut result, &ctx.progress);
        Ok(result)
    }

    fn refresh_crl(
        &self,
        ctx: ExecContext,
        plan: RefreshCrlPlan,
    ) -> Result<FlowOutcome, BackendError> {
        const ACTION: &str = "Refreshing the CRL";
        let ca = open(ACTION, &ctx.drives)?;
        let planned = ca
            .plan_refresh_crl(plan.issuer, ctx.clock.confirmed)
            .map_err(|e| failure(ACTION, e))?;
        let done = sign_crl(self, &ctx, &ca, planned, plan.credential, ACTION)?;
        let mut result = crl_outcome("The CRL was refreshed", &ca, &done);
        cancel_note(&mut result, &ctx.progress);
        Ok(result)
    }

    fn replace_yubikey(
        &self,
        ctx: ExecContext,
        plan: ReplaceYubikeyPlan,
    ) -> Result<FlowOutcome, BackendError> {
        const ACTION: &str = "Replacing the lost YubiKey";
        let ca = open(ACTION, &ctx.drives)?;
        let planned = ca
            .plan_replace_yubikey(plan.reason, ctx.clock.confirmed)
            .map_err(|e| failure(ACTION, e))?;
        match planned.kind() {
            ops::CrlPlanKind::ReplaceYubikey { old_main, .. }
                if old_main == plan.old_main_intermediate => {}
            _ => {
                return Err(BackendError::Failed(format!(
                    "{ACTION} did not run: the active main intermediate changed since the flow started. Start it again."
                )));
            }
        }
        let done = sign_crl(
            self,
            &ctx,
            &ca,
            planned,
            IssuerCredential::MasterPassphrase(plan.master_passphrase),
            ACTION,
        )?;
        let mut result = crl_outcome(
            "The old main intermediate was revoked by the master",
            &ca,
            &done,
        );
        result.notes.push(
            "The old main intermediate's last CRL stays hosted until it expires: it can no longer be refreshed.".to_string(),
        );
        result.follow_up.push(FollowUp::SetUpNewYubikey);
        result.follow_up.push(FollowUp::ReissueSubIntermediates(
            done.revoked_by_ancestor.clone(),
        ));
        cancel_note(&mut result, &ctx.progress);
        Ok(result)
    }

    fn wipe_signing_slot(
        &self,
        ctx: ExecContext,
        plan: WipeSlotPlan,
    ) -> Result<FlowOutcome, BackendError> {
        const ACTION: &str = "Wiping the YubiKey signing slot";
        let shared = need_token(ACTION, ctx.token.as_ref())?;
        let ca = open(ACTION, &ctx.drives)?;
        let serial = plan.confirmation.serial();
        let mut token = shared.lock();
        ca.wipe_yubikey_slot(&mut **token, &serial.to_string(), &plan.pin)
            .map_err(|e| failure(ACTION, e))?;
        drop(token);
        drop(plan.pin);
        Ok(FlowOutcome {
            title: "The YubiKey signing slot was wiped".to_string(),
            notes: vec![format!(
                "The signing slot of YubiKey {serial} is now empty. Nothing was written to the CA drives. Set up the YubiKey to create a new main intermediate on it."
            )],
            ..FlowOutcome::default()
        })
    }

    fn recover(&self, ctx: ExecContext, plan: RecoveryPlan) -> Result<FlowOutcome, BackendError> {
        const ACTION: &str = "Recovering the interrupted operation";
        let ca = open(ACTION, &ctx.drives)?;
        let operation = plan.operation;
        let time = ctx.clock.confirmed;
        let mut resume = plan.resume.unwrap_or_default();
        match plan.action {
            RecoveryAction::ResumeYubikeySetup { .. }
            | RecoveryAction::CompleteSetupWithExistingKey => {
                let trust = trust(ACTION)?;
                let shared = need_token(ACTION, ctx.token.as_ref())?;
                let pin = match (resume.current_pin.take(), resume.new_pin.take()) {
                    (Some(pin), _) => PinEntry::Current(pin),
                    (None, Some(pin)) => PinEntry::New(pin),
                    (None, None) => {
                        return Err(BackendError::Failed(format!(
                            "{ACTION} did not run: enter the YubiKey PIN."
                        )));
                    }
                };
                let request = resume
                    .main_intermediate
                    .take()
                    .map(|main| MainIntermediateRequest {
                        subject: main.name.to_fields(),
                        validity_years: main.validity_years,
                        master_crl: main.master_crl,
                    });
                let secrets = YubikeySecrets {
                    pin,
                    new_puk: resume.new_puk.take(),
                    master_passphrase: resume.master_passphrase.as_ref(),
                };
                let sink = self.sink(&ctx.progress);
                let mut token = shared.lock();
                let done = ca
                    .resume_yubikey_setup(
                        operation,
                        &mut **token,
                        request.as_ref(),
                        &secrets,
                        &trust,
                        time,
                        Some(&ctx.drives.export),
                        &sink,
                        &ctx.progress.cancel_flag(),
                    )
                    .map_err(|e| failure(ACTION, e))?;
                drop(secrets);
                drop(token);
                Ok(main_intermediate_outcome(&ca, done, &ctx.progress))
            }
            action => {
                let secrets = RecoverySecrets {
                    master_passphrase: resume.master_passphrase.as_ref(),
                };
                // The core re-checks the action against the YubiKey actually connected
                // (Abandon of a YubiKey setup is refused while that setup's YubiKey is
                // connected); `None` means no YubiKey is connected.
                let mut token = ctx.token.as_ref().map(SharedToken::lock);
                ca.run_recovery(
                    operation,
                    &action,
                    &secrets,
                    token.as_mut().map(|t| &mut ***t as &mut dyn TokenSigner),
                    time,
                )
                .map_err(|e| failure(ACTION, e))?;
                drop(token);
                drop(resume);
                if action == RecoveryAction::Abandon {
                    return Ok(FlowOutcome {
                        title: format!("{} was marked abandoned", capitalised(&operation.to_string())),
                        notes: vec![
                            "Every drive records the operation as abandoned. Its reserved serial numbers stay reserved; nothing was deleted or overwritten.".to_string(),
                        ],
                        ..FlowOutcome::default()
                    });
                }
                let mut result = outcome(
                    format!("{} was finished", capitalised(&operation.to_string())),
                    &ca,
                    operation,
                );
                if action == RecoveryAction::FinishWithoutYubikey {
                    result.notes.push(
                        "The main intermediate is recorded without its first CRL. Revoke it now with Replace lost YubiKey.".to_string(),
                    );
                }
                if exports_something(&ca, operation) {
                    match ca.export_operation(operation, &ctx.drives.export, time) {
                        Ok(files) => {
                            result.export_files = files.into_iter().map(|f| f.path).collect();
                        }
                        Err(error) => {
                            apply_export(&mut result, ExportStatus::Failed(cause_text(&error)))
                        }
                    }
                }
                Ok(result)
            }
        }
    }

    fn replace_drive(
        &self,
        ctx: ExecContext,
        plan: ReplaceDrivePlan,
    ) -> Result<FlowOutcome, BackendError> {
        const ACTION: &str = "Replacing the lost drive";
        let ca = open(ACTION, &ctx.drives)?;
        let planned = ca
            .plan_replace_drive(&plan.new_drive, ctx.clock.confirmed)
            .map_err(|e| failure(ACTION, e))?;
        let sink = self.sink(&ctx.progress);
        let done = planned
            .execute(&ca, &sink)
            .map_err(|e| failure(ACTION, e))?;
        let mut result = FlowOutcome {
            title: "The lost drive was replaced".to_string(),
            ..FlowOutcome::default()
        };
        result.drive_writes = copied_and_verified(&done.ca);
        result.notes.push(format!(
            "Copied to {}: {} operation{}, {} file{} and {} audit entr{}, each verified by SHA-256; its identity was written last.",
            done.new_drive,
            done.operations_copied,
            if done.operations_copied == 1 { "" } else { "s" },
            done.files_copied,
            if done.files_copied == 1 { "" } else { "s" },
            done.audit_entries_copied,
            if done.audit_entries_copied == 1 { "y" } else { "ies" },
        ));
        match &done.promoted {
            Some(label) => result.notes.push(format!(
                "{label} is now the primary drive. If the old primary drive is found again, it is used only as a backup."
            )),
            None => result
                .notes
                .push("The primary drive did not change.".to_string()),
        }
        result.notes.push(
            "Nothing was signed, and nothing on the other drives was overwritten or deleted."
                .to_string(),
        );
        Ok(result)
    }

    fn issuer_crl_location(
        &self,
        drives: &DriveSelection,
        issuer: Serial,
    ) -> Result<Option<CrlLocation>, BackendError> {
        const ACTION: &str = "Reading the stored CRL address";
        let ca = open(ACTION, drives)?;
        let state = ca.state().map_err(|e| failure(ACTION, e))?;
        state.crl_location(issuer).map_err(|e| failure(ACTION, e))
    }

    fn recovery_items(
        &self,
        drives: &DriveSelection,
        token: Option<&SharedToken>,
    ) -> Result<Vec<RecoveryItem>, BackendError> {
        const ACTION: &str = "Reading the interrupted operations";
        let ca = open(ACTION, drives)?;
        match token {
            Some(shared) => {
                let mut token = shared.lock();
                ca.recovery_items(Some(&mut **token as &mut dyn TokenSigner))
            }
            None => ca.recovery_items(None),
        }
        .map_err(|e| failure(ACTION, e))
    }

    fn review_replace_drive(
        &self,
        drives: &DriveSelection,
        new_drive: &Path,
        clock: &ClockConfirmation,
    ) -> Result<DriveReplacementReview, BackendError> {
        const ACTION: &str = "Reviewing the drive replacement";
        let ca = open(ACTION, drives)?;
        let planned = ca
            .plan_replace_drive(new_drive, clock.confirmed)
            .map_err(|e| failure(ACTION, e))?;
        Ok(DriveReplacementReview {
            lines: planned.review().lines.clone(),
            warnings: planned.review().warnings.clone(),
            promotes: planned.promotes().map(str::to_string),
        })
    }
}

/// Flow B's (or its resumed setup's) result.
fn main_intermediate_outcome(
    ca: &Ca,
    done: ops::MainIntermediateOutcome,
    progress: &Progress,
) -> FlowOutcome {
    let mut result = outcome(
        format!(
            "The YubiKey {} is set up and the main intermediate was created",
            done.yubikey_serial
        ),
        ca,
        done.operation,
    );
    result.certificates.extend(certificate(ca, done.serial));
    result.crls.extend(current_crl(ca, done.serial));
    apply_export(&mut result, done.export);
    result.notes.push(ops::UPLOAD_CRL_NOTE.to_string());
    result.notes.push(
        "The main intermediate's key was generated on the YubiKey and never leaves it; its attestation was verified.".to_string(),
    );
    cancel_note(&mut result, progress);
    result
}

fn sign_crl(
    backend: &OpsBackend,
    ctx: &ExecContext,
    ca: &Ca,
    planned: ops::CrlPlan,
    credential: IssuerCredential,
    action: &str,
) -> Result<ops::CrlOutcome, BackendError> {
    let sink = backend.sink(&ctx.progress);
    let cancel = ctx.progress.cancel_flag();
    let export = Some(ctx.drives.export.as_path());
    match credential {
        IssuerCredential::MasterPassphrase(passphrase) => {
            if !planned.needs_master() {
                return Err(BackendError::Failed(format!(
                    "{action} did not run: this CRL is signed by the main intermediate on the YubiKey; enter the YubiKey PIN."
                )));
            }
            let done = planned
                .execute(
                    ca,
                    IssuerUnlock::Master(&passphrase),
                    export,
                    &sink,
                    &cancel,
                )
                .map_err(|e| failure(action, e));
            drop(passphrase);
            done
        }
        IssuerCredential::YubikeyPin(pin) => {
            if planned.needs_master() {
                return Err(BackendError::Failed(format!(
                    "{action} did not run: this CRL is signed by the master; enter the master passphrase."
                )));
            }
            let shared = need_token(action, ctx.token.as_ref())?;
            let mut token = shared.lock();
            let done = planned
                .execute(
                    ca,
                    IssuerUnlock::YubiKey {
                        token: &mut **token,
                        pin: &pin,
                    },
                    export,
                    &sink,
                    &cancel,
                )
                .map_err(|e| failure(action, e));
            drop(token);
            drop(pin);
            done
        }
    }
}

fn crl_outcome(title: &str, ca: &Ca, done: &ops::CrlOutcome) -> FlowOutcome {
    let mut result = outcome(title, ca, done.operation);
    result.crls.extend(current_crl(ca, done.issuer_serial));
    if let Some(revoked) = done.revoked
        && let Some(cert) = ca.state().ok().and_then(|state| {
            state
                .certificate(revoked)
                .map(|cert| cert.record.subject.display())
        })
    {
        result
            .notes
            .push(format!("Revoked: {cert}, serial {revoked}."));
    }
    if !done.revoked_by_ancestor.is_empty() {
        result.notes.push(format!(
            "Marked revoked by ancestor in the issuance record: {}.",
            done.revoked_by_ancestor
                .iter()
                .map(Serial::to_hex)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    apply_export(&mut result, done.export.clone());
    result.notes.push(
        "Upload the new CRL from the export drive to where it is hosted (for example StarnetAuth)."
            .to_string(),
    );
    result
}

/// After "Replace a lost drive": every completed operation's outputs read back from
/// every drive (the new one included) and compared with the completed entries.
fn copied_and_verified(ca: &Ca) -> Vec<DriveWriteResult> {
    let drives = ca.drive_set().drives();
    let mut results: Vec<DriveWriteResult> = drives
        .iter()
        .map(|drive| DriveWriteResult {
            drive: drive.label(),
            verified: true,
            files: Vec::new(),
        })
        .collect();
    let operations = drives
        .first()
        .and_then(|drive| drive.journal().ok())
        .unwrap_or_default();
    for (operation, journal) in operations {
        if journal.completed_outputs().is_none_or(<[_]>::is_empty) {
            continue;
        }
        match ca.drive_set().export_ready(operation) {
            Ok((outputs, verified)) => {
                for (index, result) in results.iter_mut().enumerate() {
                    result.verified &= verified.contains(&index);
                    result
                        .files
                        .extend(outputs.iter().map(|output| output.path.to_string()));
                }
            }
            Err(_) => results
                .iter_mut()
                .for_each(|result| result.verified = false),
        }
    }
    results
}

#[cfg(all(test, feature = "simulator"))]
mod tests;
