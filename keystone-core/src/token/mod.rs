//! The `TokenSigner` trait, YubiKey hardening rules and PIV attestation
//! verification (FR-05, FR-06, FR-07, FR-08, FR-22 AC5, AC7, NFR-08, SEC-06, SEC-23).
//!
//! The trait models native PIV over PC/SC (FR-05 AC1). It has two
//! implementations: the real driver (a later PR, on the patched `yubikey` crate)
//! and `keystone_testkit::SimulatedYubiKey` for CI (NFR-08). Every rule that must
//! hold for both lives here as a plain function, so the simulator cannot weaken it:
//! [`check_firmware`], [`ensure_hardened`], [`check_hardening_report`],
//! [`ensure_slot_empty`], [`WipeConfirmation::new`] and
//! [`attestation::verify_piv_attestation`].
//!
//! Contract for implementations (the real driver must keep it too):
//! - The signing slot is 9C; keys are RSA 4,096 generated on the device with PIN
//!   policy "always" and touch policy "always" (FR-06 AC4, FR-07 AC1).
//! - The management key is a random AES-256 key (explicitly AES-256, never the
//!   firmware's automatic choice), stored on the device protected by the PIN
//!   (FR-06 AC3). It never leaves the driver.
//! - `slot_status` inspects both key metadata and certificate storage
//!   (Dependencies doc, YubiKey item 6).
//! - `reopen_and_verify_hardening` closes and reopens the connection and confirms
//!   PIN-protected management-key retrieval and authentication (item 5).
//! - `wipe_slot` deletes only the one slot's key and certificate (item 7).
//! - PINs and PUKs arrive as `SecretString` and are never stored or logged.
#![forbid(unsafe_code)]

pub mod attestation;
mod credentials;
mod signer;

use std::fmt;

use serde::{Deserialize, Serialize};

pub use attestation::{
    AttestationExpectation, AttestationTrust, VerifiedAttestation, verify_piv_attestation,
};
pub use credentials::{NewPin, NewPuk, WipeConfirmation};
pub use signer::TokenCaSigner;

use crate::crypto::secret::SecretString;

/// Factory-default PIV PIN.
pub const DEFAULT_PIN: &str = "123456";
/// Factory-default PIV PUK.
pub const DEFAULT_PUK: &str = "12345678";
/// Oldest firmware Keystone accepts (FR-05 AC2).
pub const MIN_FIRMWARE: FirmwareVersion = FirmwareVersion {
    major: 5,
    minor: 7,
    patch: 0,
};
/// The signing slot.
pub const SIGNING_SLOT: PivSlot = PivSlot::Signature;
/// PIN policy of the signing key (FR-06 AC4).
pub const REQUIRED_PIN_POLICY: PinPolicy = PinPolicy::Always;
/// Touch policy of the signing key (FR-06 AC4).
pub const REQUIRED_TOUCH_POLICY: TouchPolicy = TouchPolicy::Always;
/// RSA size of the on-device key (FR-07 AC1).
pub const TOKEN_KEY_BITS: u32 = 4096;

/// Errors from the token. Every message is written for the operator and never
/// contains a PIN, PUK or key.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// No YubiKey is connected.
    #[error("no YubiKey found; insert the YubiKey")]
    NotPresent,
    /// The YubiKey was removed while an operation was running.
    #[error("the YubiKey was removed during the operation; insert it again and check its state")]
    Removed,
    /// FR-05 AC2.
    #[error(
        "this YubiKey has firmware {found}; Keystone needs firmware {required} or newer (for RSA 4,096 and AES-256 management keys)"
    )]
    FirmwareTooOld {
        /// Firmware found.
        found: FirmwareVersion,
        /// Oldest accepted firmware.
        required: FirmwareVersion,
    },
    /// Wrong PIN.
    #[error("wrong PIN; {retries_left} attempts left before the PIN is blocked")]
    WrongPin {
        /// Attempts left.
        retries_left: u8,
    },
    /// No PIN attempts left.
    #[error("the PIN is blocked; unblock it with the PUK")]
    PinBlocked,
    /// Wrong PUK.
    #[error("wrong PUK; {retries_left} attempts left before the PUK is blocked")]
    WrongPuk {
        /// Attempts left.
        retries_left: u8,
    },
    /// No PUK attempts left.
    #[error("the PUK is blocked; this YubiKey's PIV application can only be reset")]
    PukBlocked,
    /// FR-06 AC1, AC3: factory defaults or a weak management key remain.
    #[error("the YubiKey is not hardened: {0}")]
    NotHardened(String),
    /// Re-verification after hardening failed (Dependencies doc item 5).
    #[error("the YubiKey's hardening could not be confirmed: {0}")]
    HardeningNotConfirmed(String),
    /// The management key is neither the default nor PIN-protected, so Keystone
    /// cannot authenticate.
    #[error(
        "the YubiKey's management key is not available to Keystone (neither default nor PIN-protected)"
    )]
    ManagementKeyUnavailable,
    /// FR-07 AC4: the slot holds something.
    #[error("the signing slot is not empty: {description}")]
    SlotOccupied {
        /// What the slot holds.
        description: String,
    },
    /// There is no key in the signing slot.
    #[error("the signing slot holds no key")]
    SlotEmpty,
    /// The operator did not touch the YubiKey in time.
    #[error("the YubiKey was not touched in time; try again and touch it when it blinks")]
    TouchTimeout,
    /// FR-06 AC2: the new PIN or PUK breaks a rule.
    #[error("{0}")]
    InvalidNewCredential(&'static str),
    /// FR-07 AC4: the typed serial does not match.
    #[error("the typed serial number does not match this YubiKey; nothing was wiped")]
    WipeConfirmationMismatch,
    /// FR-07 AC5: attestation failed. Setup must stop.
    #[error("the YubiKey's attestation is not valid: {0}")]
    Attestation(String),
    /// Communication with the YubiKey failed.
    #[error("communication with the YubiKey failed: {0}")]
    Communication(String),
    /// A crypto operation failed.
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
}

/// A YubiKey firmware version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FirmwareVersion {
    /// Major.
    pub major: u8,
    /// Minor.
    pub minor: u8,
    /// Patch.
    pub patch: u8,
}

impl FirmwareVersion {
    /// A version.
    pub const fn new(major: u8, minor: u8, patch: u8) -> Self {
        FirmwareVersion {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// What the GUI shows before any action (FR-05 AC3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device serial number.
    pub serial: u32,
    /// Firmware version.
    pub firmware: FirmwareVersion,
}

/// Refuses firmware older than 5.7 with the reason (FR-05 AC2).
pub fn check_firmware(info: &DeviceInfo) -> Result<(), TokenError> {
    if info.firmware < MIN_FIRMWARE {
        return Err(TokenError::FirmwareTooOld {
            found: info.firmware,
            required: MIN_FIRMWARE,
        });
    }
    Ok(())
}

/// PIV management-key algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagementKeyAlgorithm {
    /// Three-key Triple-DES (old default).
    TripleDes,
    /// AES-128.
    Aes128,
    /// AES-192 (firmware 5.7 default).
    Aes192,
    /// AES-256 (what Keystone sets, FR-06 AC3).
    Aes256,
}

/// The state of the PIV credentials (from the device's metadata).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialStatus {
    /// PIN is the factory default.
    pub pin_is_default: bool,
    /// PUK is the factory default.
    pub puk_is_default: bool,
    /// Management key is the factory default.
    pub management_key_is_default: bool,
    /// Management-key algorithm.
    pub management_key_algorithm: ManagementKeyAlgorithm,
    /// Management key stored on the device protected by the PIN.
    pub management_key_pin_protected: bool,
    /// PIN attempts left.
    pub pin_retries_left: u8,
    /// PUK attempts left.
    pub puk_retries_left: u8,
}

fn hardening_problems(status: &CredentialStatus) -> Vec<&'static str> {
    let mut problems = Vec::new();
    if status.pin_is_default {
        problems.push("the PIN is the factory default");
    }
    if status.puk_is_default {
        problems.push("the PUK is the factory default");
    }
    if status.management_key_is_default {
        problems.push("the management key is the factory default");
    }
    if status.management_key_algorithm != ManagementKeyAlgorithm::Aes256 {
        problems.push("the management key is not AES-256");
    }
    if !status.management_key_pin_protected {
        problems.push("the management key is not stored protected by the PIN");
    }
    problems
}

/// Refuses to proceed while any credential is a factory default, or the
/// management key is not a PIN-protected AES-256 key (FR-06 AC1, AC3; SEC-06).
pub fn ensure_hardened(status: &CredentialStatus) -> Result<(), TokenError> {
    let problems = hardening_problems(status);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(TokenError::NotHardened(problems.join("; ")))
    }
}

/// The result of reopening the device and re-reading its state after hardening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardeningReport {
    /// Credential state read after reopening.
    pub status: CredentialStatus,
    /// The PIN-protected management key was retrieved with the PIN and
    /// authenticated successfully.
    pub management_key_authenticated: bool,
}

/// Accepts hardening only when the re-read state is hardened and the stored
/// management key really authenticates (Dependencies doc item 5).
pub fn check_hardening_report(report: &HardeningReport) -> Result<(), TokenError> {
    let mut problems = hardening_problems(&report.status);
    if !report.management_key_authenticated {
        problems.push("the stored management key did not authenticate");
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(TokenError::HardeningNotConfirmed(problems.join("; ")))
    }
}

/// PIV slots Keystone uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PivSlot {
    /// Slot 9C, "Digital Signature".
    Signature,
}

impl PivSlot {
    /// The PIV slot number.
    pub const fn id(self) -> u8 {
        match self {
            PivSlot::Signature => 0x9c,
        }
    }
}

/// PIN policy values as Yubico encodes them (attestation extension 3.8, metadata).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinPolicy {
    /// 0: device default.
    Default,
    /// 1: never.
    Never,
    /// 2: once per session.
    Once,
    /// 3: always (every signature).
    Always,
    /// 4: biometric match once.
    MatchOnce,
    /// 5: biometric match always.
    MatchAlways,
}

impl PinPolicy {
    /// Yubico's byte value.
    pub const fn to_byte(self) -> u8 {
        match self {
            PinPolicy::Default => 0,
            PinPolicy::Never => 1,
            PinPolicy::Once => 2,
            PinPolicy::Always => 3,
            PinPolicy::MatchOnce => 4,
            PinPolicy::MatchAlways => 5,
        }
    }

    /// From Yubico's byte value.
    pub const fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            0 => PinPolicy::Default,
            1 => PinPolicy::Never,
            2 => PinPolicy::Once,
            3 => PinPolicy::Always,
            4 => PinPolicy::MatchOnce,
            5 => PinPolicy::MatchAlways,
            _ => return None,
        })
    }
}

/// Touch policy values as Yubico encodes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TouchPolicy {
    /// 0: device default.
    Default,
    /// 1: never.
    Never,
    /// 2: always (every signature).
    Always,
    /// 3: cached for 15 seconds.
    Cached,
}

impl TouchPolicy {
    /// Yubico's byte value.
    pub const fn to_byte(self) -> u8 {
        match self {
            TouchPolicy::Default => 0,
            TouchPolicy::Never => 1,
            TouchPolicy::Always => 2,
            TouchPolicy::Cached => 3,
        }
    }

    /// From Yubico's byte value.
    pub const fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            0 => TouchPolicy::Default,
            1 => TouchPolicy::Never,
            2 => TouchPolicy::Always,
            3 => TouchPolicy::Cached,
            _ => return None,
        })
    }
}

/// Where a slot's key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyOrigin {
    /// Generated on the device.
    Generated,
    /// Imported from outside.
    Imported,
}

/// Key metadata of a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotKeyInfo {
    /// RSA modulus size (0 for non-RSA keys).
    pub rsa_bits: u32,
    /// PIN policy.
    pub pin_policy: PinPolicy,
    /// Touch policy.
    pub touch_policy: TouchPolicy,
    /// Origin.
    pub origin: KeyOrigin,
    /// Public key as DER SubjectPublicKeyInfo.
    pub public_key_der: Vec<u8>,
}

/// What a slot holds: key metadata AND certificate storage, read separately
/// (Dependencies doc item 6).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SlotStatus {
    /// The key, if any.
    pub key: Option<SlotKeyInfo>,
    /// The stored certificate (DER), if any.
    pub certificate_der: Option<Vec<u8>>,
}

impl SlotStatus {
    /// True when the slot holds neither a key nor a certificate.
    pub fn is_empty(&self) -> bool {
        self.key.is_none() && self.certificate_der.is_none()
    }

    /// A plain description for the operator (FR-07 AC4: "shows what is there").
    pub fn describe(&self) -> String {
        let key = match &self.key {
            Some(key) => format!(
                "a {} key ({}-bit RSA, PIN policy {:?}, touch policy {:?})",
                match key.origin {
                    KeyOrigin::Generated => "device-generated",
                    KeyOrigin::Imported => "imported",
                },
                key.rsa_bits,
                key.pin_policy,
                key.touch_policy
            ),
            None => "no key".to_owned(),
        };
        let certificate = match &self.certificate_der {
            Some(der) => match crate::cert::parse_certificate_der(der) {
                Ok(info) => format!("a certificate for {}", info.subject),
                Err(_) => "an unreadable certificate".to_owned(),
            },
            None => "no certificate".to_owned(),
        };
        format!("{key} and {certificate}")
    }
}

/// Refuses to generate into an occupied slot, saying what is there (FR-07 AC4).
/// The only way forward is the explicit wipe ([`WipeConfirmation`]).
pub fn ensure_slot_empty(status: &SlotStatus) -> Result<(), TokenError> {
    if status.is_empty() {
        Ok(())
    } else {
        Err(TokenError::SlotOccupied {
            description: status.describe(),
        })
    }
}

/// The device's attestation of the signing slot (FR-07 AC5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAttestation {
    /// The slot attestation certificate the device generated (DER).
    pub slot_certificate_der: Vec<u8>,
    /// The device's F9 attestation signing certificate (DER).
    pub f9_certificate_der: Vec<u8>,
}

/// A YubiKey PIV token (PRD section 10, NFR-08). Object-safe.
///
/// See the module documentation for the contract every implementation keeps.
pub trait TokenSigner: Send {
    /// Serial number and firmware (FR-05 AC3).
    fn device_info(&mut self) -> Result<DeviceInfo, TokenError>;

    /// Credential metadata (FR-06 AC1).
    fn credential_status(&mut self) -> Result<CredentialStatus, TokenError>;

    /// Changes the PIN (FR-06 AC2).
    fn change_pin(&mut self, current: &SecretString, new: &NewPin) -> Result<(), TokenError>;

    /// Changes the PUK (FR-06 AC2).
    fn change_puk(&mut self, current_puk: &SecretString, new: &NewPuk) -> Result<(), TokenError>;

    /// Authenticates with the current management key (default or PIN-protected),
    /// then sets a new random AES-256 management key stored on the device
    /// protected by the PIN (FR-06 AC3). The key never leaves the driver.
    fn set_random_management_key(&mut self, pin: &SecretString) -> Result<(), TokenError>;

    /// Closes and reopens the device, re-reads the credential state and
    /// authenticates with the PIN-protected management key (item 5).
    fn reopen_and_verify_hardening(
        &mut self,
        pin: &SecretString,
    ) -> Result<HardeningReport, TokenError>;

    /// Reads key metadata and certificate storage of `slot` (FR-07 AC4, item 6).
    fn slot_status(&mut self, slot: PivSlot) -> Result<SlotStatus, TokenError>;

    /// Generates the RSA 4,096 signing key in slot 9C with PIN policy "always" and
    /// touch policy "always"; returns its public key (DER SPKI) (FR-06 AC4, FR-07 AC1).
    /// Callers check [`ensure_slot_empty`] first.
    fn generate_signing_key(&mut self, pin: &SecretString) -> Result<Vec<u8>, TokenError>;

    /// Generates the attestation certificate of slot 9C and reads the F9
    /// certificate (FR-07 AC5).
    fn attest_signing_key(&mut self) -> Result<SlotAttestation, TokenError>;

    /// Stores the main intermediate certificate in slot 9C (FR-07 AC3).
    fn write_signing_certificate(
        &mut self,
        pin: &SecretString,
        certificate_der: &[u8],
    ) -> Result<(), TokenError>;

    /// Reads the certificate stored in slot 9C.
    fn read_signing_certificate(&mut self) -> Result<Option<Vec<u8>>, TokenError>;

    /// Signs a SHA-384 digest with the slot 9C key, RSA PKCS#1 v1.5; needs the PIN
    /// and a touch every time (FR-08 AC2).
    fn sign_sha384_digest(
        &mut self,
        pin: &SecretString,
        digest: &[u8; 48],
    ) -> Result<Vec<u8>, TokenError>;

    /// Deletes the key and certificate of one slot (item 7, FR-07 AC4). Only with a
    /// confirmation whose typed serial matched this device.
    fn wipe_slot(
        &mut self,
        slot: PivSlot,
        confirmation: &WipeConfirmation,
        pin: &SecretString,
    ) -> Result<(), TokenError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hardened() -> CredentialStatus {
        CredentialStatus {
            pin_is_default: false,
            puk_is_default: false,
            management_key_is_default: false,
            management_key_algorithm: ManagementKeyAlgorithm::Aes256,
            management_key_pin_protected: true,
            pin_retries_left: 3,
            puk_retries_left: 3,
        }
    }

    #[test]
    fn fr05_ac2_firmware_below_5_7_is_refused_with_reason() {
        // Covers: FR-05 AC2
        for (major, minor, patch) in [(4, 3, 7), (5, 4, 3), (5, 6, 9)] {
            let info = DeviceInfo {
                serial: 1,
                firmware: FirmwareVersion::new(major, minor, patch),
            };
            let error = check_firmware(&info).unwrap_err();
            assert!(error.to_string().contains("5.7.0 or newer"), "{error}");
        }
        for (major, minor, patch) in [(5, 7, 0), (5, 7, 4), (6, 0, 0)] {
            let info = DeviceInfo {
                serial: 1,
                firmware: FirmwareVersion::new(major, minor, patch),
            };
            assert!(check_firmware(&info).is_ok());
        }
    }

    #[test]
    fn fr06_ac1_ac3_defaults_and_weak_management_key_are_refused() {
        // Covers: FR-06 AC1, FR-06 AC3, SEC-06
        assert!(ensure_hardened(&hardened()).is_ok());
        let mut status = hardened();
        status.pin_is_default = true;
        assert!(
            ensure_hardened(&status)
                .unwrap_err()
                .to_string()
                .contains("PIN")
        );
        let mut status = hardened();
        status.puk_is_default = true;
        assert!(
            ensure_hardened(&status)
                .unwrap_err()
                .to_string()
                .contains("PUK")
        );
        let mut status = hardened();
        status.management_key_is_default = true;
        assert!(ensure_hardened(&status).is_err());
        let mut status = hardened();
        status.management_key_algorithm = ManagementKeyAlgorithm::Aes192;
        assert!(
            ensure_hardened(&status)
                .unwrap_err()
                .to_string()
                .contains("AES-256")
        );
        let mut status = hardened();
        status.management_key_pin_protected = false;
        assert!(ensure_hardened(&status).is_err());
        let report = HardeningReport {
            status: hardened(),
            management_key_authenticated: false,
        };
        assert!(matches!(
            check_hardening_report(&report),
            Err(TokenError::HardeningNotConfirmed(_))
        ));
    }

    #[test]
    fn fr07_ac4_occupied_slot_is_refused_with_description() {
        // Covers: FR-07 AC4
        assert!(ensure_slot_empty(&SlotStatus::default()).is_ok());
        let key_only = SlotStatus {
            key: Some(SlotKeyInfo {
                rsa_bits: 4096,
                pin_policy: PinPolicy::Always,
                touch_policy: TouchPolicy::Always,
                origin: KeyOrigin::Generated,
                public_key_der: vec![],
            }),
            certificate_der: None,
        };
        let error = ensure_slot_empty(&key_only).unwrap_err();
        assert!(
            error.to_string().contains("device-generated key"),
            "{error}"
        );
        assert!(error.to_string().contains("no certificate"), "{error}");
        let cert_only = SlotStatus {
            key: None,
            certificate_der: Some(vec![0x30, 0x00]),
        };
        assert!(
            ensure_slot_empty(&cert_only)
                .unwrap_err()
                .to_string()
                .contains("unreadable certificate")
        );
    }

    #[test]
    fn policy_bytes_round_trip() {
        for value in 0..=5 {
            assert_eq!(PinPolicy::from_byte(value).unwrap().to_byte(), value);
        }
        for value in 0..=3 {
            assert_eq!(TouchPolicy::from_byte(value).unwrap().to_byte(), value);
        }
        assert!(PinPolicy::from_byte(9).is_none());
        assert!(TouchPolicy::from_byte(9).is_none());
        assert_eq!(REQUIRED_PIN_POLICY.to_byte(), 3);
        assert_eq!(REQUIRED_TOUCH_POLICY.to_byte(), 2);
        assert_eq!(SIGNING_SLOT.id(), 0x9c);
    }
}
