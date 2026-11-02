//! Flow B: set up the YubiKey and create the main intermediate (FR-05, FR-06, FR-07,
//! FR-13 AC6, FR-18, FR-22 AC5, AC7), its resume after an interruption, and the explicit
//! slot wipe (FR-07 AC4).
//!
//! Setup is journaled step by step (PIN changed, PUK changed, management key set, key
//! generated, certificate written). Each step first reads the YubiKey's real state, so
//! the same code both runs a fresh setup and resumes an interrupted one from the first
//! incomplete step; a PIN or PUK that was already set is asked for again and never
//! stored (FR-22 AC7). A key in the slot without a certificate is used only when
//! resuming, and only after its attestation verifies (FR-22 AC5).
#![forbid(unsafe_code)]

use std::path::Path;

use crate::cert::{
    CaCertificateRequest, IssuedCertificate, Issuer, PlannedSerial, SoftwareSigner,
    issue_ca_certificate, parse_certificate_pem,
};
use crate::clock::ConfirmedTime;
use crate::crl::first_crl;
use crate::crypto::pkcs8::decrypt_key_pem;
use crate::crypto::secret::SecretString;
use crate::crypto::verify::certificate_der_to_pem;
use crate::crypto::{CancelFlag, RsaPrivateKey};
use crate::limits::MAX_PEM_BYTES;
use crate::model::{CaLevel, Fingerprint, NameFields, Serial};
use crate::passphrase::EnteredPassphrase;
use crate::profile::{
    CRL_NONE_WARNING, CertValidity, CrlLocation, MAIN_INTERMEDIATE, ValidatedName,
    default_crl_next_update, plan_validity, rfc3339,
};
use crate::store::{
    CertStatus, CertificateRecord, OperationHandle, OperationId, OperationKind, OperationState,
    SignedCrl, SignedObject, SubjectName, YubikeySetupStep,
};
use crate::token::{
    AttestationExpectation, AttestationTrust, CredentialStatus, DEFAULT_PIN, DEFAULT_PUK,
    DeviceInfo, KeyOrigin, ManagementKeyAlgorithm, NewPin, NewPuk, PinPolicy, SIGNING_SLOT,
    SlotStatus, TOKEN_KEY_BITS, TokenCaSigner, TokenError, TokenSigner, TouchPolicy,
    WipeConfirmation, check_firmware, check_hardening_report, ensure_hardened, ensure_slot_empty,
    verify_piv_attestation,
};

use super::ca::ExportStatus;
use super::pipeline::{
    OpContext, assemble_and_finish, begin, certificate_record, plan_unique_serial,
    record_certificate, record_crl, resolve_crl_location, run, signed_crl,
};
use super::seam::{self, FaultPoint};
use super::state::{CaState, StoredCert, key_path};
use super::{Ca, OpsError, Progress, ProgressSink, Review, Step};

/// What the GUI tells the operator after the main intermediate's first CRL is exported
/// (FR-13 AC6).
pub const UPLOAD_CRL_NOTE: &str = "Upload this CRL to StarnetAuth (or wherever the CRL \
address points) before the issuer's first child certificate is deployed.";

/// What the YubiKey holds, read before any action (FR-05 AC3, FR-06 AC1, FR-07 AC4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInspection {
    /// Serial number and firmware, shown before any action (FR-05 AC3).
    pub device: DeviceInfo,
    /// Why the firmware is refused (FR-05 AC2), if it is.
    pub firmware_problem: Option<String>,
    /// PIN, PUK and management-key state.
    pub credentials: CredentialStatus,
    /// What the signing slot holds.
    pub slot: SlotStatus,
    /// The slot, in words (FR-07 AC4 "shows what is there").
    pub slot_description: String,
    /// The PIN is the factory default: the operator chooses a new one (FR-06 AC2).
    pub needs_new_pin: bool,
    /// The PUK is the factory default: the operator chooses a new one (FR-06 AC2).
    pub needs_new_puk: bool,
}

/// Reads the YubiKey's serial, firmware, credentials and slot (nothing is changed).
pub fn inspect_yubikey(token: &mut dyn TokenSigner) -> Result<TokenInspection, OpsError> {
    let device = token.device_info()?;
    let firmware_problem = check_firmware(&device).err().map(|e| e.to_string());
    let credentials = token.credential_status()?;
    let slot = token.slot_status(SIGNING_SLOT)?;
    Ok(TokenInspection {
        device,
        firmware_problem,
        needs_new_pin: credentials.pin_is_default,
        needs_new_puk: credentials.puk_is_default,
        slot_description: slot.describe(),
        slot,
        credentials,
    })
}

/// What the operator entered for the main intermediate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainIntermediateRequest {
    /// Name fields.
    pub subject: NameFields,
    /// Validity in years (1 to 15, default 10, never past the master).
    pub validity_years: u8,
    /// The master's CRL address (FR-18): required for the master's first child, then
    /// stored; `None` reuses the stored one.
    pub master_crl: Option<CrlLocation>,
}

impl MainIntermediateRequest {
    /// A request with the default validity (10 years).
    pub fn new(subject: NameFields, master_crl: Option<CrlLocation>) -> Self {
        MainIntermediateRequest {
            subject,
            validity_years: MAIN_INTERMEDIATE.default_validity_years,
            master_crl,
        }
    }
}

/// The YubiKey PIN for setup: a new one when the PIN is still the default, otherwise
/// the current one (asked again after an interruption, never stored, FR-22 AC7).
#[derive(Debug)]
pub enum PinEntry {
    /// The PIN is the factory default; set this new PIN (entered twice, FR-06 AC2).
    New(NewPin),
    /// The PIN was already changed; this is the current PIN.
    Current(SecretString),
}

/// The secrets Flow B needs. None of them is stored.
#[derive(Debug)]
pub struct YubikeySecrets<'a> {
    /// The PIN.
    pub pin: PinEntry,
    /// A new PUK, when the PUK is still the factory default.
    pub new_puk: Option<NewPuk>,
    /// The master passphrase (needed until the main intermediate is signed).
    pub master_passphrase: Option<&'a EnteredPassphrase>,
}

/// A checked Flow B plan. Nothing was written and the YubiKey was not changed.
#[derive(Debug)]
pub struct YubikeySetupPlan {
    device: DeviceInfo,
    name: ValidatedName,
    validity: CertValidity,
    serial: PlannedSerial,
    master_crl: CrlLocation,
    time: ConfirmedTime,
    review: Review,
}

/// The result of Flow B.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainIntermediateOutcome {
    /// The journaled operation.
    pub operation: OperationId,
    /// The main intermediate's serial.
    pub serial: Serial,
    /// SHA-256 fingerprint (FR-20).
    pub fingerprint: Fingerprint,
    /// The fingerprint as `AB:CD:...` (FR-20 AC1).
    pub fingerprint_text: String,
    /// The certificate (PEM).
    pub certificate_pem: String,
    /// The YubiKey's serial number.
    pub yubikey_serial: u32,
    /// The first CRL's number.
    pub crl_number: u64,
    /// Export of the first CRL (FR-13 AC6); see [`UPLOAD_CRL_NOTE`].
    pub export: ExportStatus,
}

/// Unlocks the master key (Flows B, D, E): decrypts `keys/master.key` with the
/// passphrase and checks that it belongs to the master certificate. A wrong passphrase
/// gives a clear error and nothing else (FR-04 AC3). The caller drops the key right
/// after signing, which wipes it.
pub(crate) fn unlock_master(
    ca: &Ca,
    master: &StoredCert,
    passphrase: &EnteredPassphrase,
) -> Result<RsaPrivateKey, OpsError> {
    let path = key_path(
        CaLevel::Master,
        &master.record.subject.common_name,
        master.serial(),
    );
    let pem = ca.drive_set().drives()[0]
        .read_at(path.dir().name(), path.name(), MAX_PEM_BYTES)?
        .ok_or_else(|| OpsError::Damaged(format!("{path} is missing")))?;
    let key = decrypt_key_pem(&pem, passphrase.secret())?;
    if key.public_key_spki_der()? != master.info.spki_der {
        return Err(OpsError::Damaged(
            "the master key file does not belong to the master certificate".into(),
        ));
    }
    Ok(key)
}

fn master_ready(state: &CaState) -> Result<&StoredCert, OpsError> {
    let master = state
        .master()
        .ok_or_else(|| OpsError::NotReady("create the master first (Flow A)".into()))?;
    if state.current_crl(master.serial()).is_none() {
        return Err(OpsError::NotReady(
            "the master has no CRL yet; it cannot sign its first child (FR-13 AC6)".into(),
        ));
    }
    Ok(master)
}

fn location_text(location: &CrlLocation) -> String {
    match location {
        CrlLocation::Url(url) => url.to_string(),
        CrlLocation::ExplicitlyNone => "none (explicit choice)".to_owned(),
    }
}

impl Ca {
    /// Flow B review: checks the CA (master and its first CRL, no active main
    /// intermediate), the YubiKey (firmware 5.7+, empty signing slot), the name, the
    /// validity (never past the master, FR-10 AC1) and the master's CRL address
    /// (FR-18). Reads the YubiKey; changes nothing.
    pub fn plan_yubikey_setup(
        &self,
        token: &mut dyn TokenSigner,
        request: &MainIntermediateRequest,
        time: ConfirmedTime,
    ) -> Result<YubikeySetupPlan, OpsError> {
        let state = self.ready_for_signing(time)?;
        let master = master_ready(&state)?;
        if let Some(active) = state.active_main(time.get().get()) {
            return Err(OpsError::NotReady(format!(
                "a main intermediate is already active ({}); replace it with \"Replace lost YubiKey\" or revoke it first",
                active.record.subject.display()
            )));
        }
        let inspection = inspect_yubikey(token)?;
        check_firmware(&inspection.device)?;
        if ensure_slot_empty(&inspection.slot).is_err() {
            return Err(OpsError::SlotOccupied {
                description: inspection.slot_description,
            });
        }
        let name = ValidatedName::new(&request.subject)?;
        let validity = plan_validity(
            CaLevel::MainIntermediate,
            request.validity_years,
            time.get().get(),
            Some(master.info.not_after),
        )?;
        let (master_crl, new_address) = resolve_crl_location(
            &state,
            master.serial(),
            &master.record.subject.display(),
            request.master_crl.as_ref(),
        )?;
        let serial = plan_unique_serial(self)?;
        let crl_next = default_crl_next_update(CaLevel::MainIntermediate, validity.not_before())?;
        let mut review = Review::new("Set up the YubiKey and create the main intermediate");
        review.line("YubiKey serial", inspection.device.serial.to_string());
        review.line("YubiKey firmware", inspection.device.firmware.to_string());
        let mut hardening = Vec::new();
        if inspection.needs_new_pin {
            hardening.push("set a new PIN");
        }
        if inspection.needs_new_puk {
            hardening.push("set a new PUK");
        }
        if inspection.credentials.management_key_is_default
            || inspection.credentials.management_key_algorithm != ManagementKeyAlgorithm::Aes256
            || !inspection.credentials.management_key_pin_protected
        {
            hardening.push("set a random PIN-protected AES-256 management key");
        }
        review.line(
            "YubiKey hardening",
            if hardening.is_empty() {
                "already hardened".to_owned()
            } else {
                hardening.join(", ")
            },
        );
        review.line(
            "Key",
            "RSA 4,096 bits generated on the YubiKey (slot 9C); PIN and touch for every signature",
        );
        review.line("Common Name", name.common_name());
        review.line("Organization", name.organization().unwrap_or("(none)"));
        review.line("Country", name.country().unwrap_or("(none)"));
        review.line("Signed by", master.record.subject.display());
        review.line("Valid from", rfc3339(validity.not_before()));
        review.line("Valid until", rfc3339(validity.not_after()));
        review.line("Basic constraints", "critical; CA; path length 1");
        review.line("Key usage", "critical; certificate signing, CRL signing");
        review.line("Serial number", serial.serial().to_hex());
        review.line(
            "Master CRL address",
            format!(
                "{}{}",
                location_text(&master_crl),
                if new_address {
                    " (set now, used for every later main intermediate)"
                } else {
                    ""
                }
            ),
        );
        if master_crl == CrlLocation::ExplicitlyNone {
            review.warnings.push(CRL_NONE_WARNING.to_owned());
        }
        review.line(
            "First CRL",
            format!(
                "empty, number 1, signed by the YubiKey (PIN + touch), next update {}",
                rfc3339(crl_next)
            ),
        );
        Ok(YubikeySetupPlan {
            device: inspection.device,
            name,
            validity,
            serial,
            master_crl,
            time,
            review,
        })
    }

    /// FR-22 AC5, AC7: resumes an interrupted YubiKey setup from the first incomplete
    /// step, reading the YubiKey's real state. `request` is needed while the main
    /// intermediate is not signed yet (its name must match the interrupted setup);
    /// `secrets` hold the PIN asked again (never stored) and, when still needed, a new
    /// PUK and the master passphrase. A key already in the slot without a certificate
    /// is used only after its attestation verifies; nothing is ever wiped here.
    #[allow(clippy::too_many_arguments)]
    pub fn resume_yubikey_setup(
        &self,
        operation: OperationId,
        token: &mut dyn TokenSigner,
        request: Option<&MainIntermediateRequest>,
        secrets: &YubikeySecrets<'_>,
        trust: &AttestationTrust,
        time: ConfirmedTime,
        export: Option<&Path>,
        progress: &dyn ProgressSink,
        cancel: &CancelFlag,
    ) -> Result<MainIntermediateOutcome, OpsError> {
        let state = self.ready_for_recovery(operation, OperationKind::SetupYubikey, time)?;
        let journal = self.drive_set().drives()[0]
            .operation_journal(operation)?
            .ok_or_else(|| OpsError::NotReady(format!("{operation} has no journal")))?;
        let serial = *journal
            .planned_serials()
            .first()
            .ok_or_else(|| OpsError::Damaged(format!("{operation} reserved no serial")))?;
        let master = master_ready(&state)?;
        let signed = journal
            .signed()
            .any(|object| matches!(object, SignedObject::Certificate { .. }));
        let unsigned = if signed {
            None
        } else {
            let request = request.ok_or_else(|| {
                OpsError::NotReady(
                    "enter the main intermediate's name and validity again to finish the setup"
                        .into(),
                )
            })?;
            let name = ValidatedName::new(&request.subject)?;
            if SubjectName::from(&name.to_fields()).display() != journal.subject() {
                return Err(OpsError::NotReady(format!(
                    "the name differs from the interrupted setup ({})",
                    journal.subject()
                )));
            }
            let validity = plan_validity(
                CaLevel::MainIntermediate,
                request.validity_years,
                time.get().get(),
                Some(master.info.not_after),
            )?;
            let (location, _) = resolve_crl_location(
                &state,
                master.serial(),
                &master.record.subject.display(),
                request.master_crl.as_ref(),
            )?;
            Some(Unsigned {
                name,
                validity,
                master_crl: location,
            })
        };
        self.drive_set().sync_operation_journal(operation)?;
        let handle = self.drive_set().resume_operation(operation)?;
        let mut ctx = OpContext::new(time, progress, cancel);
        let inputs = SetupInputs {
            serial: PlannedSerial::from_reserved(serial),
            unsigned,
            secrets,
            trust,
            expected_device: None,
            resuming: true,
        };
        let (operation, result) = run(handle, &mut ctx, |handle, ctx| {
            setup_steps(self, handle, ctx, token, &state, &inputs)
        })?;
        Ok(self.main_outcome(operation, result, export, time, progress))
    }

    /// FR-07 AC4: the explicit wipe of the YubiKey's signing slot, a separate action
    /// that needs the operator to type the YubiKey's serial number. Refused when the
    /// slot holds a main intermediate that is still valid in the issuance record.
    pub fn wipe_yubikey_slot(
        &self,
        token: &mut dyn TokenSigner,
        typed_serial: &str,
        pin: &SecretString,
    ) -> Result<(), OpsError> {
        let device = token.device_info()?;
        let confirmation = WipeConfirmation::new(typed_serial, &device)?;
        let slot = token.slot_status(SIGNING_SLOT)?;
        let state = self.state()?;
        let holds_valid_main = state.main_intermediates().iter().any(|main| {
            main.status == CertStatus::Valid
                && (slot
                    .key
                    .as_ref()
                    .is_some_and(|key| key.public_key_der == main.info.spki_der)
                    || slot.certificate_der.as_deref() == Some(main.der.as_slice()))
        });
        if holds_valid_main {
            return Err(OpsError::NotReady(
                "this YubiKey holds a main intermediate that is still valid; it is never wiped. Revoke it first (Replace lost YubiKey or Revoke)".into(),
            ));
        }
        token.wipe_slot(SIGNING_SLOT, &confirmation, pin)?;
        Ok(())
    }

    fn main_outcome(
        &self,
        operation: OperationId,
        result: SetupResult,
        export: Option<&Path>,
        time: ConfirmedTime,
        progress: &dyn ProgressSink,
    ) -> MainIntermediateOutcome {
        let export = self.export_after(operation, export, time, progress);
        MainIntermediateOutcome {
            operation,
            serial: result.record.serial,
            fingerprint: result.record.fingerprint,
            fingerprint_text: result.record.fingerprint.to_fingerprint_string(),
            certificate_pem: result.pem,
            yubikey_serial: result.device_serial,
            crl_number: result.crl_number,
            export,
        }
    }

    /// The gate for a recovery action on `operation`: drives writable and identical
    /// histories, the operation pending and of `kind`, the time not earlier than the
    /// newest audit entry. Returns the state before the operation.
    pub(crate) fn ready_for_recovery(
        &self,
        operation: OperationId,
        kind: OperationKind,
        time: ConfirmedTime,
    ) -> Result<CaState, OpsError> {
        self.drive_set().ensure_writable()?;
        let comparison = self.drive_set().compare()?;
        if !comparison.signing_allowed() {
            return Err(OpsError::Blocked(vec![super::Blocker::DrivesDamaged {
                problems: vec![
                    "compare and repair the drives before finishing an interrupted operation"
                        .to_owned(),
                ],
            }]));
        }
        let report = self.drive_set().recovery_report()?;
        let pending = report
            .pending
            .iter()
            .find(|p| p.operation == operation)
            .ok_or_else(|| OpsError::NotReady(format!("{operation} is not interrupted")))?;
        if pending.kind != kind {
            return Err(OpsError::NotReady(format!(
                "{operation} is not a {kind:?} operation"
            )));
        }
        let log = self.drive_set().audit_log()?;
        if let Some(baseline) = crate::clock::baseline(log.entries())
            && time.get() < baseline
        {
            return Err(OpsError::Blocked(vec![
                super::Blocker::ClockConfirmationStale {
                    confirmed: time.get(),
                    baseline,
                },
            ]));
        }
        CaState::load(&self.drive_set().drives()[0])
    }
}

impl YubikeySetupPlan {
    /// What the review step shows.
    pub fn review(&self) -> &Review {
        &self.review
    }

    /// The YubiKey this plan was made for.
    pub fn device(&self) -> DeviceInfo {
        self.device
    }

    /// The serial the main intermediate will get.
    pub fn serial(&self) -> Serial {
        self.serial.serial()
    }

    /// Flow B, steps 2 to 5. The master passphrase is checked before the YubiKey is
    /// changed; then the YubiKey is hardened, the key generated on it, its attestation
    /// verified with `trust` (FR-07 AC5), the master signs the certificate (and its key
    /// is wiped), the certificate goes to the YubiKey and every drive, and the YubiKey
    /// signs the first empty CRL (PIN + touch), which is exported (FR-13 AC6).
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        self,
        ca: &Ca,
        token: &mut dyn TokenSigner,
        secrets: &YubikeySecrets<'_>,
        trust: &AttestationTrust,
        export: Option<&Path>,
        progress: &dyn ProgressSink,
        cancel: &CancelFlag,
    ) -> Result<MainIntermediateOutcome, OpsError> {
        if cancel.is_cancelled() {
            return Err(OpsError::CancelledBeforeStart);
        }
        let state = ca.ready_for_signing(self.time)?;
        let master = master_ready(&state)?;
        if state.active_main(self.time.get().get()).is_some() {
            return Err(OpsError::NotReady(
                "a main intermediate is already active".into(),
            ));
        }
        let device = token.device_info()?;
        if device.serial != self.device.serial {
            return Err(OpsError::NotReady(format!(
                "this is YubiKey {}, but the plan was made for YubiKey {}",
                device.serial, self.device.serial
            )));
        }
        let passphrase = secrets.master_passphrase.ok_or_else(|| {
            OpsError::NotReady("enter the master passphrase to sign the main intermediate".into())
        })?;
        progress.report(Progress::Step {
            step: Step::UnlockingMaster,
            cancel_available: true,
        });
        // FR-04 AC3: a wrong passphrase stops here, before the YubiKey is changed.
        drop(unlock_master(ca, master, passphrase)?);
        let mut ctx = OpContext::new(self.time, progress, cancel);
        let subject = SubjectName::from(&self.name.to_fields());
        let handle = begin(
            ca,
            &ctx,
            OperationKind::SetupYubikey,
            &subject.display(),
            &[self.serial.serial()],
        )?;
        let inputs = SetupInputs {
            serial: self.serial,
            unsigned: Some(Unsigned {
                name: self.name,
                validity: self.validity,
                master_crl: self.master_crl,
            }),
            secrets,
            trust,
            expected_device: Some(self.device.serial),
            resuming: false,
        };
        let (operation, result) = run(handle, &mut ctx, |handle, ctx| {
            setup_steps(ca, handle, ctx, token, &state, &inputs)
        })?;
        Ok(ca.main_outcome(operation, result, export, self.time, progress))
    }
}

/// What is needed to sign the main intermediate when it is not signed yet.
struct Unsigned {
    name: ValidatedName,
    validity: CertValidity,
    master_crl: CrlLocation,
}

struct SetupInputs<'a, 's> {
    serial: PlannedSerial,
    unsigned: Option<Unsigned>,
    secrets: &'a YubikeySecrets<'s>,
    trust: &'a AttestationTrust,
    expected_device: Option<u32>,
    resuming: bool,
}

struct SetupResult {
    record: CertificateRecord,
    pem: String,
    device_serial: u32,
    crl_number: u64,
}

fn secret(text: &str) -> Result<SecretString, OpsError> {
    Ok(SecretString::from_str_copy(text)?)
}

/// Performs one YubiKey setup step: the change on the token, then its journal entry
/// (FR-22 AC7), with the fault points between them.
fn token_step(
    handle: &mut OperationHandle<'_>,
    ctx: &mut OpContext<'_>,
    step: YubikeySetupStep,
    progress_step: Step,
    device_serial: u32,
    done: &[YubikeySetupStep],
    change: impl FnOnce() -> Result<(), TokenError>,
) -> Result<(), OpsError> {
    ctx.check_cancel(handle)?;
    ctx.step(handle, progress_step);
    ctx.persistent = true;
    change()?;
    seam::fault(FaultPoint::AfterTokenStep(step))?;
    journal_step(handle, ctx, step, device_serial, done)
}

fn journal_step(
    handle: &mut OperationHandle<'_>,
    ctx: &OpContext<'_>,
    step: YubikeySetupStep,
    device_serial: u32,
    done: &[YubikeySetupStep],
) -> Result<(), OpsError> {
    if !done.contains(&step) {
        handle.record_yubikey_step(step, device_serial, ctx.ts())?;
    }
    seam::fault(FaultPoint::AfterTokenStepRecorded(step))
}

fn is_hardened(status: &CredentialStatus) -> bool {
    !status.management_key_is_default
        && status.management_key_algorithm == ManagementKeyAlgorithm::Aes256
        && status.management_key_pin_protected
}

/// The journaled certificate (record, PEM) and CRL of an operation.
type Journaled = (Option<(CertificateRecord, String)>, Option<SignedCrl>);

/// The journaled certificate and CRL of this operation, if signed already.
fn journaled(ca: &Ca, operation: OperationId) -> Result<Journaled, OpsError> {
    let journal = ca.drive_set().drives()[0]
        .operation_journal(operation)?
        .ok_or_else(|| OpsError::Damaged(format!("{operation} has no journal")))?;
    if journal.state() != OperationState::Pending {
        return Err(OpsError::NotReady(format!(
            "{operation} is already finished"
        )));
    }
    let mut cert = None;
    let mut crl = None;
    for object in journal.signed() {
        match object {
            SignedObject::Certificate { record, pem } => {
                cert = Some(((**record).clone(), pem.clone()))
            }
            SignedObject::Crl(signed) => crl = Some((**signed).clone()),
        }
    }
    Ok((cert, crl))
}

/// Every Flow B step from the YubiKey's real state (fresh setup and resume).
fn setup_steps(
    ca: &Ca,
    handle: &mut OperationHandle<'_>,
    ctx: &mut OpContext<'_>,
    token: &mut dyn TokenSigner,
    state: &CaState,
    inputs: &SetupInputs<'_, '_>,
) -> Result<SetupResult, OpsError> {
    let master = master_ready(state)?;
    let done: Vec<YubikeySetupStep> = handle
        .completed_yubikey_steps()?
        .into_iter()
        .map(|(step, _)| step)
        .collect();
    let journaled_device = handle.completed_yubikey_steps()?.first().map(|(_, s)| *s);
    let (journaled_cert, journaled_crl) = journaled(ca, handle.id())?;

    // FR-05: the same YubiKey, firmware 5.7 or newer.
    let device = token.device_info()?;
    check_firmware(&device)?;
    if let Some(expected) = inputs.expected_device.or(journaled_device)
        && expected != device.serial
    {
        return Err(OpsError::NotReady(format!(
            "this is YubiKey {}, but the setup uses YubiKey {expected}",
            device.serial
        )));
    }

    // FR-06: hardening, each step from the token's real state (FR-22 AC7).
    let status = token.credential_status()?;
    let pin = match (&inputs.secrets.pin, status.pin_is_default) {
        (PinEntry::New(new), true) => {
            let default = secret(DEFAULT_PIN)?;
            token_step(
                handle,
                ctx,
                YubikeySetupStep::PinChanged,
                Step::ChangingPin,
                device.serial,
                &done,
                || token.change_pin(&default, new),
            )?;
            new.secret().duplicate()?
        }
        (PinEntry::Current(pin), false) => pin.duplicate()?,
        (PinEntry::New(_), false) => {
            return Err(OpsError::NotReady(
                "the YubiKey's PIN is no longer the default; enter its current PIN".into(),
            ));
        }
        (PinEntry::Current(_), true) => {
            return Err(OpsError::NotReady(
                "the YubiKey still has the default PIN; choose a new PIN (6 to 8 characters, entered twice)".into(),
            ));
        }
    };
    if status.puk_is_default {
        let new = inputs.secrets.new_puk.as_ref().ok_or_else(|| {
            OpsError::NotReady(
                "the YubiKey still has the default PUK; choose a new PUK (entered twice)".into(),
            )
        })?;
        let default = secret(DEFAULT_PUK)?;
        token_step(
            handle,
            ctx,
            YubikeySetupStep::PukChanged,
            Step::ChangingPuk,
            device.serial,
            &done,
            || token.change_puk(&default, new),
        )?;
    }
    if !is_hardened(&status) {
        token_step(
            handle,
            ctx,
            YubikeySetupStep::ManagementKeySet,
            Step::SettingManagementKey,
            device.serial,
            &done,
            || token.set_random_management_key(&pin),
        )?;
    }
    ctx.step(handle, Step::VerifyingHardening);
    let report = token.reopen_and_verify_hardening(&pin)?;
    check_hardening_report(&report)?;
    ensure_hardened(&token.credential_status()?)?;

    // FR-07 AC1, AC4: the key, generated into an empty slot.
    let slot = token.slot_status(SIGNING_SLOT)?;
    let certified_key = match &journaled_cert {
        Some((_, pem)) => Some(parse_certificate_pem(pem.as_bytes())?),
        None => None,
    };
    let mut key_step_after_attestation = false;
    let public_key = match (&slot.key, &slot.certificate_der, &certified_key) {
        (None, None, None) => {
            ctx.check_cancel(handle)?;
            ctx.step(handle, Step::GeneratingKeyOnYubiKey);
            ctx.persistent = true;
            let spki = token.generate_signing_key(&pin)?;
            seam::fault(FaultPoint::AfterTokenStep(YubikeySetupStep::KeyGenerated))?;
            journal_step(
                handle,
                ctx,
                YubikeySetupStep::KeyGenerated,
                device.serial,
                &done,
            )?;
            spki
        }
        (Some(key), certificate, Some((der, info)))
            if key.public_key_der == info.spki_der
                && certificate.as_ref().is_none_or(|stored| stored == der) =>
        {
            key.public_key_der.clone()
        }
        (_, _, Some(_)) => {
            return Err(OpsError::NotReady(
                "the YubiKey no longer holds the key the master already certified for this setup; this setup cannot be completed with this YubiKey".into(),
            ));
        }
        (Some(key), None, None)
            if inputs.resuming || done.contains(&YubikeySetupStep::KeyGenerated) =>
        {
            // FR-22 AC5: complete setup with the existing key; its attestation is
            // verified below before the step is journaled or anything is signed.
            key_step_after_attestation = true;
            key.public_key_der.clone()
        }
        _ => {
            return Err(OpsError::SlotOccupied {
                description: slot.describe(),
            });
        }
    };
    if let Some(key) = &slot.key
        && (key.rsa_bits != TOKEN_KEY_BITS
            || key.origin != KeyOrigin::Generated
            || key.pin_policy != PinPolicy::Always
            || key.touch_policy != TouchPolicy::Always)
    {
        return Err(OpsError::NotReady(format!(
            "setup cannot be completed with the key in this YubiKey: it is {}; wipe the slot explicitly (typing the serial) and resume",
            slot.describe()
        )));
    }

    // FR-07 AC5: attestation, verified offline before the master signs.
    ctx.step(handle, Step::VerifyingAttestation);
    let attestation = token.attest_signing_key()?;
    verify_piv_attestation(
        inputs.trust,
        &attestation,
        &AttestationExpectation {
            device: &device,
            public_key_der: &public_key,
        },
        ctx.ts().get(),
    )
    .map_err(|error| {
        OpsError::NotReady(format!(
            "setup cannot be completed with this key: {error}. The key is not replaced; wipe the slot explicitly (typing the serial) and resume, or use another YubiKey"
        ))
    })?;
    if key_step_after_attestation {
        journal_step(
            handle,
            ctx,
            YubikeySetupStep::KeyGenerated,
            device.serial,
            &done,
        )?;
    }

    // FR-07 AC2: the master signs (once; a journaled certificate is never re-signed).
    let (record, pem, der) = match &journaled_cert {
        Some((record, pem)) => {
            let (der, _) = parse_certificate_pem(pem.as_bytes())?;
            (record.clone(), pem.clone(), der)
        }
        None => {
            let unsigned = inputs.unsigned.as_ref().ok_or_else(|| {
                OpsError::NotReady("enter the main intermediate's name and validity".into())
            })?;
            let passphrase = inputs.secrets.master_passphrase.ok_or_else(|| {
                OpsError::NotReady(
                    "enter the master passphrase to sign the main intermediate".into(),
                )
            })?;
            ctx.step(handle, Step::UnlockingMaster);
            let master_key = unlock_master(ca, master, passphrase)?;
            seam::fault(FaultPoint::BeforeSigning)?;
            ctx.step(handle, Step::SigningCertificate);
            let issued: IssuedCertificate = issue_ca_certificate(
                &CaCertificateRequest {
                    level: CaLevel::MainIntermediate,
                    subject: &unsigned.name,
                    subject_public_key_der: &public_key,
                    validity: unsigned.validity,
                    serial: inputs.serial,
                    issuer: Issuer::Certificate(&master.der),
                    issuer_crl: Some(&unsigned.master_crl),
                    name_constraints: None,
                },
                &mut SoftwareSigner::new(&master_key),
            )?;
            // Flow B step 5: the master key is wiped from memory right after signing.
            drop(master_key);
            let record = certificate_record(
                CaLevel::MainIntermediate,
                &issued,
                SubjectName::from(&unsigned.name.to_fields()),
                Some(&master.record),
                None,
                Some(certificate_der_to_pem(&attestation.slot_certificate_der)?),
            );
            record_certificate(handle, ctx, record.clone(), issued.pem.clone())?;
            (record, issued.pem, issued.der)
        }
    };

    // FR-07 AC3: the certificate in the YubiKey slot.
    if token.read_signing_certificate()?.as_deref() != Some(der.as_slice()) {
        ctx.step(handle, Step::WritingCertificateToYubiKey);
        ctx.persistent = true;
        token.write_signing_certificate(&pin, &der)?;
        seam::fault(FaultPoint::AfterTokenStep(
            YubikeySetupStep::CertificateWritten,
        ))?;
    }
    journal_step(
        handle,
        ctx,
        YubikeySetupStep::CertificateWritten,
        device.serial,
        &done,
    )?;

    // FR-13 AC6: the main intermediate's first, empty CRL, signed by the YubiKey.
    let crl_number = match journaled_crl {
        Some(crl) => crl.crl_number,
        None => {
            ctx.step(handle, Step::SigningCrl);
            ctx.progress.report(Progress::TouchYubiKey);
            let crl = first_crl(&der, ctx.ts().get(), &mut TokenCaSigner::new(token, &pin))?;
            record_crl(handle, ctx, signed_crl(record.serial, &crl))?;
            crl.info.crl_number
        }
    };
    drop(pin);
    assemble_and_finish(ca, handle, ctx, state, None)?;
    Ok(SetupResult {
        record,
        pem,
        device_serial: device.serial,
        crl_number,
    })
}
