//! A software YubiKey 5 behind the same `TokenSigner` trait as the real driver
//! (PRD NFR-08).
//!
//! It models what the patched real driver will do (Dependencies doc, "YubiKey
//! driver: required production work"):
//! - factory defaults: PIN 123456, PUK 12345678, default AES-192 management key,
//!   three PIN and three PUK attempts;
//! - `set_random_management_key` sets a random AES-256 key stored PIN-protected
//!   (item 4), and `reopen_and_verify_hardening` reads the state back through a
//!   fresh handle and authenticates with the stored key (item 5);
//! - `slot_status` reports key metadata and certificate storage separately (item 6);
//! - `wipe_slot` deletes one slot's key and certificate (item 7);
//! - every signature needs the PIN and a touch (PIN and touch policy "always");
//! - generating a key overwrites the slot like the real device does: refusing an
//!   occupied slot is core logic (`ensure_slot_empty`), not the token's job;
//! - its own attestation hierarchy: "KEYSTONE TEST Attestation Root" (one per test
//!   process) -> per-device F9 certificate -> slot attestation certificate with
//!   Yubico's firmware (3.3), serial (3.7) and policy (3.8) extensions.
//!
//! Fault injection ([`SimController`]): remove and reinsert the device, fail the next
//! N operations of a kind (before or after their effect), a silent partial
//! management-key write, touch timeouts, slow operations, an occupied slot at start,
//! and wrong attested serial or policy. Several handles can share one device
//! ([`SimulatedYubiKey::reopen`]) for re-verification and interrupted-setup tests.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use keystone_core::crypto::RsaPrivateKey;
use keystone_core::crypto::rand::fill;
use keystone_core::crypto::secret::SecretString;
use keystone_core::token::{
    AttestationTrust, CredentialStatus, DEFAULT_PIN, DEFAULT_PUK, DeviceInfo, FirmwareVersion,
    HardeningReport, KeyOrigin, ManagementKeyAlgorithm, NewPin, NewPuk, PinPolicy, PivSlot,
    SlotAttestation, SlotKeyInfo, SlotStatus, TokenError, TokenSigner, TouchPolicy,
    WipeConfirmation,
};
use time::{Duration as TimeDuration, OffsetDateTime};
use x509_cert::der::Encode;
use x509_cert::der::asn1::Uint;

use crate::keys;
use crate::x509::{
    TestCertSpec, TestIssuer, build_test_certificate, cn_name_der, raw_extension,
    test_ca_extensions,
};

/// Attempts allowed for the PIN and the PUK (YubiKey default).
pub const SIM_MAX_RETRIES: u8 = 3;

/// The operations a fault can target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SimOp {
    /// `device_info`.
    DeviceInfo,
    /// `credential_status`.
    CredentialStatus,
    /// `change_pin`.
    ChangePin,
    /// `change_puk`.
    ChangePuk,
    /// `set_random_management_key`.
    SetManagementKey,
    /// `reopen_and_verify_hardening`.
    VerifyHardening,
    /// `slot_status`.
    SlotStatus,
    /// `generate_signing_key`.
    GenerateKey,
    /// `attest_signing_key`.
    Attest,
    /// `write_signing_certificate`.
    WriteCertificate,
    /// `read_signing_certificate`.
    ReadCertificate,
    /// `sign_sha384_digest`.
    Sign,
    /// `wipe_slot`.
    Wipe,
}

/// What an injected fault does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// Fails with a communication error before the operation has any effect.
    FailBefore,
    /// Applies the operation, then fails with a communication error (the caller
    /// cannot tell that it took effect).
    FailAfter,
    /// The device is pulled out before the operation has any effect.
    RemoveBefore,
    /// The operation takes effect, then the device is pulled out.
    RemoveAfter,
    /// Only for `SetManagementKey`: the new AES-256 key is set but the
    /// PIN-protected copy is not stored, and the call still reports success.
    SilentPartialWrite,
}

/// Whether the simulated operator touches the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchBehaviour {
    /// Every touch request is answered.
    Touch,
    /// No touch: signatures fail with `TouchTimeout`.
    NoTouch,
}

/// What slot 9C holds when the simulator starts (FR-07 AC4, FR-22 AC5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotPreset {
    /// Empty.
    Empty,
    /// A device-generated key without a certificate (interrupted setup).
    KeyWithoutCertificate,
    /// A key and a certificate.
    KeyAndCertificate,
    /// Only a certificate object.
    CertificateOnly,
}

/// Where on-device keys come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// The cached simulator pool (fast). The pool has
    /// `keys::SIMULATOR_POOL_COUNT` keys handed out round-robin per process, so two
    /// devices can share a key only after that many generations.
    Pool,
    /// A freshly generated RSA 4,096 key (slow, always unique).
    Fresh,
}

/// Simulator settings.
#[derive(Debug, Clone, Copy)]
pub struct SimulatorConfig {
    /// Device serial number.
    pub serial: u32,
    /// Firmware version.
    pub firmware: FirmwareVersion,
    /// What slot 9C holds at start.
    pub slot: SlotPreset,
    /// Key source for on-device generation.
    pub key_source: KeySource,
}

impl Default for SimulatorConfig {
    fn default() -> Self {
        SimulatorConfig {
            serial: 31_415_926,
            firmware: FirmwareVersion::new(5, 7, 4),
            slot: SlotPreset::Empty,
            key_source: KeySource::Pool,
        }
    }
}

enum SimKey {
    Pooled(&'static RsaPrivateKey),
    Owned(Box<RsaPrivateKey>),
}

impl SimKey {
    fn key(&self) -> &RsaPrivateKey {
        match self {
            SimKey::Pooled(key) => key,
            SimKey::Owned(key) => key,
        }
    }
}

struct SlotKey {
    key: SimKey,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
    origin: KeyOrigin,
}

struct ManagementKey {
    algorithm: ManagementKeyAlgorithm,
    is_default: bool,
    pin_protected: bool,
    /// The stored key value; only its presence matters in the simulator.
    _value: [u8; 32],
}

struct Fault {
    op: SimOp,
    remaining: u32,
    kind: FaultKind,
}

struct DeviceState {
    serial: u32,
    firmware: FirmwareVersion,
    present: bool,
    pin: SecretString,
    puk: SecretString,
    pin_retries: u8,
    puk_retries: u8,
    management: ManagementKey,
    slot_key: Option<SlotKey>,
    slot_certificate: Option<Vec<u8>>,
    f9_key: RsaPrivateKey,
    f9_certificate: Vec<u8>,
    touch: TouchBehaviour,
    faults: Vec<Fault>,
    delays: HashMap<SimOp, Duration>,
    key_source: KeySource,
    keygen_policy: (PinPolicy, TouchPolicy),
    attested_serial_override: Option<u32>,
    signatures: u64,
    touches_requested: u64,
    reopen_count: u64,
}

/// The process-wide test attestation root: key and certificate.
struct AttestationRoot {
    key: &'static RsaPrivateKey,
    certificate: Vec<u8>,
    name_der: Vec<u8>,
}

static ROOT: OnceLock<AttestationRoot> = OnceLock::new();
static POOL_NEXT: AtomicUsize = AtomicUsize::new(0);

/// The `rsa2048` index reserved for the attestation root.
pub const ATTESTATION_ROOT_KEY_INDEX: usize = keys::RSA2048_COUNT - 1;

fn attestation_root() -> &'static AttestationRoot {
    ROOT.get_or_init(|| {
        let key = keys::rsa2048(ATTESTATION_ROOT_KEY_INDEX);
        let spki = key.public_key_spki_der().expect("root key");
        let name_der = cn_name_der("KEYSTONE TEST Attestation Root");
        let now = OffsetDateTime::now_utc();
        let certificate = build_test_certificate(&TestCertSpec {
            subject_der: name_der.clone(),
            subject_public_key_der: spki.clone(),
            issuer: None,
            self_key: Some(key),
            not_before: now - TimeDuration::days(365),
            not_after: now + TimeDuration::days(365 * 40),
            extensions: test_ca_extensions(&spki, None),
        });
        AttestationRoot {
            key,
            certificate,
            name_der,
        }
    })
}

/// The test attestation root certificate (DER), the trust anchor for simulated
/// devices.
pub fn attestation_root_der() -> Vec<u8> {
    attestation_root().certificate.clone()
}

/// Attestation trust containing only the test root.
pub fn test_attestation_trust() -> AttestationTrust {
    AttestationTrust::new(vec![attestation_root_der()], vec![]).expect("test trust")
}

fn secret(text: &str) -> SecretString {
    SecretString::from_str_copy(text).expect("locked memory")
}

fn new_key(source: KeySource) -> SimKey {
    match source {
        KeySource::Pool => {
            let index = POOL_NEXT.fetch_add(1, Ordering::Relaxed) % keys::SIMULATOR_POOL_COUNT;
            SimKey::Pooled(keys::simulator_pool(index))
        }
        KeySource::Fresh => SimKey::Owned(Box::new(keys::generate_uncached(4096))),
    }
}

fn communication(op: SimOp, when: &str) -> TokenError {
    TokenError::Communication(format!("simulated fault in {op:?} ({when})"))
}

impl DeviceState {
    fn verify_pin(&mut self, pin: &SecretString) -> Result<(), TokenError> {
        if self.pin_retries == 0 {
            return Err(TokenError::PinBlocked);
        }
        if self.pin.ct_eq(pin) {
            self.pin_retries = SIM_MAX_RETRIES;
            Ok(())
        } else {
            self.pin_retries -= 1;
            if self.pin_retries == 0 {
                Err(TokenError::PinBlocked)
            } else {
                Err(TokenError::WrongPin {
                    retries_left: self.pin_retries,
                })
            }
        }
    }

    fn verify_puk(&mut self, puk: &SecretString) -> Result<(), TokenError> {
        if self.puk_retries == 0 {
            return Err(TokenError::PukBlocked);
        }
        if self.puk.ct_eq(puk) {
            self.puk_retries = SIM_MAX_RETRIES;
            Ok(())
        } else {
            self.puk_retries -= 1;
            if self.puk_retries == 0 {
                Err(TokenError::PukBlocked)
            } else {
                Err(TokenError::WrongPuk {
                    retries_left: self.puk_retries,
                })
            }
        }
    }

    /// Authenticates with the management key: the default key is known; a
    /// PIN-protected key is retrieved with the PIN.
    fn authenticate_management(&mut self, pin: &SecretString) -> Result<(), TokenError> {
        if self.management.is_default {
            return Ok(());
        }
        if self.management.pin_protected {
            return self.verify_pin(pin);
        }
        Err(TokenError::ManagementKeyUnavailable)
    }

    fn status(&self) -> CredentialStatus {
        CredentialStatus {
            pin_is_default: self.pin.expose() == DEFAULT_PIN,
            puk_is_default: self.puk.expose() == DEFAULT_PUK,
            management_key_is_default: self.management.is_default,
            management_key_algorithm: self.management.algorithm,
            management_key_pin_protected: self.management.pin_protected,
            pin_retries_left: self.pin_retries,
            puk_retries_left: self.puk_retries,
        }
    }

    fn take_fault(&mut self, op: SimOp, after: bool) -> Option<FaultKind> {
        let index = self.faults.iter().position(|fault| {
            fault.op == op
                && fault.remaining > 0
                && match fault.kind {
                    FaultKind::FailBefore | FaultKind::RemoveBefore => !after,
                    FaultKind::FailAfter | FaultKind::RemoveAfter => after,
                    FaultKind::SilentPartialWrite => false,
                }
        })?;
        let fault = &mut self.faults[index];
        fault.remaining -= 1;
        let kind = fault.kind;
        self.faults.retain(|fault| fault.remaining > 0);
        Some(kind)
    }

    fn take_silent_partial_write(&mut self) -> bool {
        let Some(index) = self.faults.iter().position(|fault| {
            fault.op == SimOp::SetManagementKey && fault.kind == FaultKind::SilentPartialWrite
        }) else {
            return false;
        };
        self.faults[index].remaining -= 1;
        self.faults.retain(|fault| fault.remaining > 0);
        true
    }

    fn slot_attestation(&self) -> Result<SlotAttestation, TokenError> {
        let slot = self.slot_key.as_ref().ok_or(TokenError::SlotEmpty)?;
        if slot.origin != KeyOrigin::Generated {
            return Err(TokenError::Communication(
                "an imported key cannot be attested".into(),
            ));
        }
        let spki = slot.key.key().public_key_spki_der()?;
        let serial = self.attested_serial_override.unwrap_or(self.serial);
        let serial_value = Uint::new(&serial.to_be_bytes())
            .and_then(|value| value.to_der())
            .expect("serial extension");
        let f9 = keystone_core::cert::parse_certificate_der(&self.f9_certificate).expect("F9");
        let certificate = build_test_certificate(&TestCertSpec {
            subject_der: cn_name_der("KEYSTONE TEST YubiKey PIV Attestation 9c"),
            subject_public_key_der: spki,
            issuer: Some(TestIssuer {
                name_der: &f9.subject_der,
                key: &self.f9_key,
            }),
            self_key: None,
            not_before: f9.not_before,
            not_after: f9.not_after,
            extensions: vec![
                raw_extension(
                    "1.3.6.1.4.1.41482.3.3",
                    vec![
                        self.firmware.major,
                        self.firmware.minor,
                        self.firmware.patch,
                    ],
                ),
                raw_extension("1.3.6.1.4.1.41482.3.7", serial_value),
                raw_extension(
                    "1.3.6.1.4.1.41482.3.8",
                    vec![slot.pin_policy.to_byte(), slot.touch_policy.to_byte()],
                ),
            ],
        });
        Ok(SlotAttestation {
            slot_certificate_der: certificate,
            f9_certificate_der: self.f9_certificate.clone(),
        })
    }
}

/// A simulated YubiKey 5. Cloning is not offered; use [`SimulatedYubiKey::reopen`]
/// for another handle to the same device.
pub struct SimulatedYubiKey {
    device: Arc<Mutex<DeviceState>>,
}

impl fmt::Debug for SimulatedYubiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.device);
        write!(f, "SimulatedYubiKey(serial {})", state.serial)
    }
}

fn lock(device: &Mutex<DeviceState>) -> MutexGuard<'_, DeviceState> {
    device
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl SimulatedYubiKey {
    /// A factory-fresh device (defaults as on a new YubiKey), with its own F9
    /// attestation certificate under the test attestation root.
    pub fn new(config: SimulatorConfig) -> Self {
        let root = attestation_root();
        let f9_key = keys::generate_uncached(2048);
        let f9_spki = f9_key.public_key_spki_der().expect("F9 key");
        let now = OffsetDateTime::now_utc();
        let f9_certificate = build_test_certificate(&TestCertSpec {
            subject_der: cn_name_der(&format!(
                "KEYSTONE TEST YubiKey PIV Attestation F9 {}",
                config.serial
            )),
            subject_public_key_der: f9_spki.clone(),
            issuer: Some(TestIssuer {
                name_der: &root.name_der,
                key: root.key,
            }),
            self_key: None,
            not_before: now - TimeDuration::days(30),
            not_after: now + TimeDuration::days(365 * 30),
            extensions: test_ca_extensions(&f9_spki, None),
        });
        let mut value = [0u8; 32];
        fill(&mut value).expect("random");
        let mut state = DeviceState {
            serial: config.serial,
            firmware: config.firmware,
            present: true,
            pin: secret(DEFAULT_PIN),
            puk: secret(DEFAULT_PUK),
            pin_retries: SIM_MAX_RETRIES,
            puk_retries: SIM_MAX_RETRIES,
            management: ManagementKey {
                algorithm: ManagementKeyAlgorithm::Aes192,
                is_default: true,
                pin_protected: false,
                _value: value,
            },
            slot_key: None,
            slot_certificate: None,
            f9_key,
            f9_certificate,
            touch: TouchBehaviour::Touch,
            faults: Vec::new(),
            delays: HashMap::new(),
            key_source: config.key_source,
            keygen_policy: (PinPolicy::Always, TouchPolicy::Always),
            attested_serial_override: None,
            signatures: 0,
            touches_requested: 0,
            reopen_count: 0,
        };
        let preset_key = || SlotKey {
            key: new_key(config.key_source),
            pin_policy: PinPolicy::Always,
            touch_policy: TouchPolicy::Always,
            origin: KeyOrigin::Generated,
        };
        let preset_certificate = || {
            let key = keys::rsa2048(6);
            let spki = key.public_key_spki_der().expect("key");
            build_test_certificate(&TestCertSpec {
                subject_der: cn_name_der("KEYSTONE TEST previous slot certificate"),
                subject_public_key_der: spki.clone(),
                issuer: None,
                self_key: Some(key),
                not_before: now - TimeDuration::days(1),
                not_after: now + TimeDuration::days(30),
                extensions: test_ca_extensions(&spki, None),
            })
        };
        match config.slot {
            SlotPreset::Empty => {}
            SlotPreset::KeyWithoutCertificate => state.slot_key = Some(preset_key()),
            SlotPreset::KeyAndCertificate => {
                state.slot_key = Some(preset_key());
                state.slot_certificate = Some(preset_certificate());
            }
            SlotPreset::CertificateOnly => state.slot_certificate = Some(preset_certificate()),
        }
        SimulatedYubiKey {
            device: Arc::new(Mutex::new(state)),
        }
    }

    /// A second handle to the same device, as after closing and reopening the
    /// PC/SC connection.
    pub fn reopen(&self) -> SimulatedYubiKey {
        lock(&self.device).reopen_count += 1;
        SimulatedYubiKey {
            device: Arc::clone(&self.device),
        }
    }

    /// A control handle for fault injection and inspection that stays usable after
    /// the token is moved into a `Box<dyn TokenSigner>`.
    pub fn controller(&self) -> SimController {
        SimController {
            device: Arc::clone(&self.device),
        }
    }

    /// Trust material for this device's attestations (the test root).
    pub fn attestation_trust(&self) -> AttestationTrust {
        test_attestation_trust()
    }

    fn run<T>(
        &mut self,
        op: SimOp,
        effect: impl FnOnce(&mut DeviceState) -> Result<T, TokenError>,
    ) -> Result<T, TokenError> {
        let delay = {
            let state = lock(&self.device);
            if !state.present {
                return Err(TokenError::NotPresent);
            }
            state.delays.get(&op).copied()
        };
        if let Some(delay) = delay {
            // Sleep without holding the lock, so a test can remove the device meanwhile.
            std::thread::sleep(delay);
        }
        let mut state = lock(&self.device);
        if !state.present {
            return Err(if delay.is_some() {
                TokenError::Removed
            } else {
                TokenError::NotPresent
            });
        }
        match state.take_fault(op, false) {
            Some(FaultKind::RemoveBefore) => {
                state.present = false;
                return Err(TokenError::Removed);
            }
            Some(_) => return Err(communication(op, "before")),
            None => {}
        }
        let value = effect(&mut state)?;
        match state.take_fault(op, true) {
            Some(FaultKind::RemoveAfter) => {
                state.present = false;
                Err(TokenError::Removed)
            }
            Some(_) => Err(communication(op, "after")),
            None => Ok(value),
        }
    }
}

impl TokenSigner for SimulatedYubiKey {
    fn device_info(&mut self) -> Result<DeviceInfo, TokenError> {
        self.run(SimOp::DeviceInfo, |state| {
            Ok(DeviceInfo {
                serial: state.serial,
                firmware: state.firmware,
            })
        })
    }

    fn credential_status(&mut self) -> Result<CredentialStatus, TokenError> {
        self.run(SimOp::CredentialStatus, |state| Ok(state.status()))
    }

    fn change_pin(&mut self, current: &SecretString, new: &NewPin) -> Result<(), TokenError> {
        self.run(SimOp::ChangePin, |state| {
            state.verify_pin(current)?;
            state.pin = new.secret().duplicate()?;
            Ok(())
        })
    }

    fn change_puk(&mut self, current_puk: &SecretString, new: &NewPuk) -> Result<(), TokenError> {
        self.run(SimOp::ChangePuk, |state| {
            state.verify_puk(current_puk)?;
            state.puk = new.secret().duplicate()?;
            Ok(())
        })
    }

    fn set_random_management_key(&mut self, pin: &SecretString) -> Result<(), TokenError> {
        self.run(SimOp::SetManagementKey, |state| {
            state.authenticate_management(pin)?;
            // Storing the key PIN-protected writes a PIN-protected object.
            state.verify_pin(pin)?;
            let mut value = [0u8; 32];
            fill(&mut value)?;
            let partial = state.take_silent_partial_write();
            state.management = ManagementKey {
                algorithm: ManagementKeyAlgorithm::Aes256,
                is_default: false,
                pin_protected: !partial,
                _value: value,
            };
            Ok(())
        })
    }

    fn reopen_and_verify_hardening(
        &mut self,
        pin: &SecretString,
    ) -> Result<HardeningReport, TokenError> {
        let mut fresh = self.reopen();
        fresh.run(SimOp::VerifyHardening, |state| {
            let status = state.status();
            let management_key_authenticated = if status.management_key_pin_protected {
                state.verify_pin(pin)?;
                true
            } else {
                false
            };
            Ok(HardeningReport {
                status,
                management_key_authenticated,
            })
        })
    }

    fn slot_status(&mut self, _slot: PivSlot) -> Result<SlotStatus, TokenError> {
        self.run(SimOp::SlotStatus, |state| {
            let key = match &state.slot_key {
                Some(slot) => Some(SlotKeyInfo {
                    rsa_bits: slot.key.key().bits(),
                    pin_policy: slot.pin_policy,
                    touch_policy: slot.touch_policy,
                    origin: slot.origin,
                    public_key_der: slot.key.key().public_key_spki_der()?,
                }),
                None => None,
            };
            Ok(SlotStatus {
                key,
                certificate_der: state.slot_certificate.clone(),
            })
        })
    }

    fn generate_signing_key(&mut self, pin: &SecretString) -> Result<Vec<u8>, TokenError> {
        self.run(SimOp::GenerateKey, |state| {
            state.authenticate_management(pin)?;
            let (pin_policy, touch_policy) = state.keygen_policy;
            let key = new_key(state.key_source);
            let spki = key.key().public_key_spki_der()?;
            state.slot_key = Some(SlotKey {
                key,
                pin_policy,
                touch_policy,
                origin: KeyOrigin::Generated,
            });
            Ok(spki)
        })
    }

    fn attest_signing_key(&mut self) -> Result<SlotAttestation, TokenError> {
        self.run(SimOp::Attest, |state| state.slot_attestation())
    }

    fn write_signing_certificate(
        &mut self,
        pin: &SecretString,
        certificate_der: &[u8],
    ) -> Result<(), TokenError> {
        self.run(SimOp::WriteCertificate, |state| {
            state.authenticate_management(pin)?;
            state.slot_certificate = Some(certificate_der.to_vec());
            Ok(())
        })
    }

    fn read_signing_certificate(&mut self) -> Result<Option<Vec<u8>>, TokenError> {
        self.run(SimOp::ReadCertificate, |state| {
            Ok(state.slot_certificate.clone())
        })
    }

    fn sign_sha384_digest(
        &mut self,
        pin: &SecretString,
        digest: &[u8; 48],
    ) -> Result<Vec<u8>, TokenError> {
        self.run(SimOp::Sign, |state| {
            if state.slot_key.is_none() {
                return Err(TokenError::SlotEmpty);
            }
            let (pin_policy, touch_policy) = {
                let slot = state.slot_key.as_ref().ok_or(TokenError::SlotEmpty)?;
                (slot.pin_policy, slot.touch_policy)
            };
            if pin_policy == PinPolicy::Always {
                state.verify_pin(pin)?;
            }
            if touch_policy == TouchPolicy::Always {
                state.touches_requested += 1;
                if state.touch == TouchBehaviour::NoTouch {
                    return Err(TokenError::TouchTimeout);
                }
            }
            let slot = state.slot_key.as_ref().ok_or(TokenError::SlotEmpty)?;
            let signature = slot.key.key().sign_sha384_digest(digest)?;
            state.signatures += 1;
            Ok(signature)
        })
    }

    fn wipe_slot(
        &mut self,
        _slot: PivSlot,
        confirmation: &WipeConfirmation,
        pin: &SecretString,
    ) -> Result<(), TokenError> {
        self.run(SimOp::Wipe, |state| {
            if confirmation.serial() != state.serial {
                return Err(TokenError::WipeConfirmationMismatch);
            }
            state.authenticate_management(pin)?;
            state.slot_key = None;
            state.slot_certificate = None;
            Ok(())
        })
    }
}

/// Fault injection and inspection for a simulated device.
pub struct SimController {
    device: Arc<Mutex<DeviceState>>,
}

impl fmt::Debug for SimController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SimController")
    }
}

impl SimController {
    /// Pulls the device out: every operation fails with `NotPresent`.
    pub fn remove(&self) {
        lock(&self.device).present = false;
    }

    /// Plugs the same device back in, with its state unchanged.
    pub fn reinsert(&self) {
        lock(&self.device).present = true;
    }

    /// True while plugged in.
    pub fn is_present(&self) -> bool {
        lock(&self.device).present
    }

    /// Makes the next `count` calls of `op` fail as `kind` says.
    pub fn fail_next(&self, op: SimOp, count: u32, kind: FaultKind) {
        lock(&self.device).faults.push(Fault {
            op,
            remaining: count,
            kind,
        });
    }

    /// Sets whether the simulated operator touches the key.
    pub fn set_touch(&self, touch: TouchBehaviour) {
        lock(&self.device).touch = touch;
    }

    /// Makes every call of `op` take `delay` (slow operations, NFR-03).
    pub fn set_delay(&self, op: SimOp, delay: Duration) {
        lock(&self.device).delays.insert(op, delay);
    }

    /// Generates future keys with this policy instead of PIN/touch "always"
    /// (to prove attestation catches a wrong policy).
    pub fn set_keygen_policy(&self, pin: PinPolicy, touch: TouchPolicy) {
        lock(&self.device).keygen_policy = (pin, touch);
    }

    /// Attests a different serial number than the device's (a counterfeit).
    pub fn set_attested_serial(&self, serial: u32) {
        lock(&self.device).attested_serial_override = Some(serial);
    }

    /// Replaces the slot key with an imported one (cannot be attested).
    pub fn import_key_into_slot(&self) {
        let mut state = lock(&self.device);
        let key = new_key(state.key_source);
        state.slot_key = Some(SlotKey {
            key,
            pin_policy: PinPolicy::Always,
            touch_policy: TouchPolicy::Always,
            origin: KeyOrigin::Imported,
        });
    }

    /// Number of signatures made.
    pub fn signature_count(&self) -> u64 {
        lock(&self.device).signatures
    }

    /// Number of touch requests (one per signature with touch policy "always").
    pub fn touch_requests(&self) -> u64 {
        lock(&self.device).touches_requested
    }

    /// Number of times a handle was reopened.
    pub fn reopen_count(&self) -> u64 {
        lock(&self.device).reopen_count
    }

    /// PIN attempts left.
    pub fn pin_retries(&self) -> u8 {
        lock(&self.device).pin_retries
    }

    /// The device's F9 certificate (DER).
    pub fn f9_certificate_der(&self) -> Vec<u8> {
        lock(&self.device).f9_certificate.clone()
    }
}

/// Runs the real hardening steps through the trait on a factory-fresh device:
/// new PIN, new PUK, random PIN-protected AES-256 management key.
pub fn harden(token: &mut dyn TokenSigner, new_pin: &str, new_puk: &str) -> Result<(), TokenError> {
    let pin = secret(new_pin);
    let puk = secret(new_puk);
    token.change_pin(&secret(DEFAULT_PIN), &NewPin::from_entries(&pin, &pin)?)?;
    token.change_puk(&secret(DEFAULT_PUK), &NewPuk::from_entries(&puk, &puk)?)?;
    token.set_random_management_key(&pin)?;
    Ok(())
}
