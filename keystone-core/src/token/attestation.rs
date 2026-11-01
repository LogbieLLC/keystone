//! Offline PIV attestation verification (FR-07 AC5, FR-22 AC5, SEC-23).
//!
//! [`verify_piv_attestation`] is a pure function: the trust anchors and
//! intermediates are parameters ([`AttestationTrust`]). Production will supply
//! Yubico's PIV attestation roots and the published intermediates required by
//! firmware 5.7.4 and later, embedded in the binary; embedding them is deferred to
//! the real-driver PR. Tests supply the simulator's "KEYSTONE TEST Attestation Root".
//!
//! Checks, all of which must pass (any failure stops setup):
//! 1. The slot attestation certificate chains, through the device's F9
//!    certificate and the given intermediates, to one of the roots
//!    (OpenSSL `X509_verify_cert` at the given time), and is signed directly by
//!    the F9 certificate's key.
//! 2. The attested public key equals the public key that will be certified.
//! 3. The serial extension (1.3.6.1.4.1.41482.3.7) equals the device serial
//!    (FR-05 AC3).
//! 4. The policy extension (1.3.6.1.4.1.41482.3.8) is PIN "always" (0x03) and touch
//!    "always" (0x02).
//! 5. If present, the firmware extension (1.3.6.1.4.1.41482.3.3) equals the
//!    device's firmware.
#![forbid(unsafe_code)]

use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::asn1::{ObjectIdentifier, Uint};

use super::{DeviceInfo, FirmwareVersion, PinPolicy, SlotAttestation, TokenError, TouchPolicy};
use crate::crypto::verify::{
    RevocationCheck, VerifyOptions, verify_certificate_signature, verify_chain,
};
use crate::limits::MAX_CERT_DER_BYTES;

/// Yubico extension: firmware version (3 bytes).
pub const OID_YUBICO_FIRMWARE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.3");
/// Yubico extension: device serial number (DER INTEGER).
pub const OID_YUBICO_SERIAL: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.7");
/// Yubico extension: PIN policy and touch policy (2 bytes).
pub const OID_YUBICO_POLICY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");

/// Trust material for attestation: roots (trust anchors) and intermediates, DER.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationTrust {
    roots: Vec<Vec<u8>>,
    intermediates: Vec<Vec<u8>>,
}

impl AttestationTrust {
    /// Trust material from DER certificates. At least one root is required; every
    /// certificate must parse.
    pub fn new(roots: Vec<Vec<u8>>, intermediates: Vec<Vec<u8>>) -> Result<Self, TokenError> {
        if roots.is_empty() {
            return Err(TokenError::Attestation(
                "no attestation root configured".into(),
            ));
        }
        for der in roots.iter().chain(&intermediates) {
            parse(der, "trust certificate")?;
        }
        Ok(AttestationTrust {
            roots,
            intermediates,
        })
    }

    /// Root certificates (DER).
    pub fn roots(&self) -> &[Vec<u8>] {
        &self.roots
    }

    /// Intermediate certificates (DER).
    pub fn intermediates(&self) -> &[Vec<u8>] {
        &self.intermediates
    }
}

/// What the attestation must show.
#[derive(Debug, Clone, Copy)]
pub struct AttestationExpectation<'a> {
    /// The device as read before setup (FR-05 AC3).
    pub device: &'a DeviceInfo,
    /// The public key that the master will certify (DER SPKI).
    pub public_key_der: &'a [u8],
}

/// A verified attestation, to be stored with the issuance record (FR-07 AC5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// Attested device serial.
    pub serial: u32,
    /// Attested PIN policy.
    pub pin_policy: PinPolicy,
    /// Attested touch policy.
    pub touch_policy: TouchPolicy,
    /// Attested firmware, if the extension is present.
    pub firmware: Option<FirmwareVersion>,
    /// The slot attestation certificate (DER).
    pub slot_certificate_der: Vec<u8>,
    /// The F9 certificate (DER).
    pub f9_certificate_der: Vec<u8>,
}

fn fail(reason: impl Into<String>) -> TokenError {
    TokenError::Attestation(reason.into())
}

fn parse(der: &[u8], what: &str) -> Result<Certificate, TokenError> {
    if der.len() > MAX_CERT_DER_BYTES {
        return Err(fail(format!("{what} is too large")));
    }
    Certificate::from_der(der).map_err(|e| fail(format!("{what} could not be read: {e}")))
}

fn extension_value(cert: &Certificate, oid: ObjectIdentifier) -> Result<Option<&[u8]>, TokenError> {
    let mut found = cert
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .filter(|ext| ext.extn_id == oid);
    let first = found.next().map(|ext| ext.extn_value.as_bytes());
    if found.next().is_some() {
        return Err(fail(format!("extension {oid} appears twice")));
    }
    Ok(first)
}

/// Verifies a slot attestation (see the module documentation for every check).
pub fn verify_piv_attestation(
    trust: &AttestationTrust,
    attestation: &SlotAttestation,
    expected: &AttestationExpectation<'_>,
    at: OffsetDateTime,
) -> Result<VerifiedAttestation, TokenError> {
    let slot = parse(
        &attestation.slot_certificate_der,
        "slot attestation certificate",
    )?;
    let f9 = parse(
        &attestation.f9_certificate_der,
        "F9 attestation certificate",
    )?;

    // 1. Chain to a trusted root, and the slot certificate signed directly by F9.
    let mut untrusted: Vec<&[u8]> = vec![&attestation.f9_certificate_der];
    untrusted.extend(trust.intermediates.iter().map(Vec::as_slice));
    let roots: Vec<&[u8]> = trust.roots.iter().map(Vec::as_slice).collect();
    let options = VerifyOptions {
        at,
        revocation: RevocationCheck::None,
        // Yubico's device certificates do not meet OpenSSL's strict profile
        // (for example no authorityKeyIdentifier); the chain itself is checked.
        strict: false,
    };
    verify_chain(
        &attestation.slot_certificate_der,
        &untrusted,
        &roots,
        &[],
        &options,
    )
    .map_err(|e| fail(format!("the attestation chain does not verify: {e}")))?;
    let f9_spki = x509_cert::der::Encode::to_der(f9.tbs_certificate().subject_public_key_info())
        .map_err(|e| fail(format!("F9 public key: {e}")))?;
    verify_certificate_signature(&attestation.slot_certificate_der, &f9_spki).map_err(|_| {
        fail("the slot attestation certificate is not signed by this device's F9 certificate")
    })?;

    // 2. The attested key is the key to be certified.
    let attested_key =
        x509_cert::der::Encode::to_der(slot.tbs_certificate().subject_public_key_info())
            .map_err(|e| fail(format!("attested public key: {e}")))?;
    if attested_key != expected.public_key_der {
        return Err(fail(
            "the attested public key is not the key that would be certified",
        ));
    }

    // 3. Serial.
    let serial_value = extension_value(&slot, OID_YUBICO_SERIAL)?
        .ok_or_else(|| fail("the serial number extension is missing"))?;
    let serial_int = Uint::from_der(serial_value)
        .map_err(|_| fail("the serial number extension is malformed"))?;
    let serial_bytes = serial_int.as_bytes();
    if serial_bytes.len() > 4 {
        return Err(fail("the serial number extension is out of range"));
    }
    let serial = serial_bytes
        .iter()
        .fold(0u32, |acc, b| (acc << 8) | u32::from(*b));
    if serial != expected.device.serial {
        return Err(fail(format!(
            "the attested serial {serial} is not this YubiKey's serial {}",
            expected.device.serial
        )));
    }

    // 4. PIN and touch policy.
    let policy = extension_value(&slot, OID_YUBICO_POLICY)?
        .ok_or_else(|| fail("the policy extension is missing"))?;
    let [pin_byte, touch_byte] = policy else {
        return Err(fail("the policy extension is malformed"));
    };
    let pin_policy = PinPolicy::from_byte(*pin_byte).ok_or_else(|| fail("unknown PIN policy"))?;
    let touch_policy =
        TouchPolicy::from_byte(*touch_byte).ok_or_else(|| fail("unknown touch policy"))?;
    if pin_policy != PinPolicy::Always || touch_policy != TouchPolicy::Always {
        return Err(fail(format!(
            "the key's policy is PIN {pin_policy:?} and touch {touch_policy:?}; both must be Always"
        )));
    }

    // 5. Firmware, when attested.
    let firmware = match extension_value(&slot, OID_YUBICO_FIRMWARE)? {
        Some([major, minor, patch]) => {
            let firmware = FirmwareVersion::new(*major, *minor, *patch);
            if firmware != expected.device.firmware {
                return Err(fail(format!(
                    "the attested firmware {firmware} is not this YubiKey's firmware {}",
                    expected.device.firmware
                )));
            }
            Some(firmware)
        }
        Some(_) => return Err(fail("the firmware extension is malformed")),
        None => None,
    };

    Ok(VerifiedAttestation {
        serial,
        pin_policy,
        touch_policy,
        firmware,
        slot_certificate_der: attestation.slot_certificate_der.clone(),
        f9_certificate_der: attestation.f9_certificate_der.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr07_ac5_trust_needs_a_root() {
        // Covers: FR-07 AC5
        assert!(AttestationTrust::new(vec![], vec![]).is_err());
        assert!(AttestationTrust::new(vec![vec![0x30, 0x00]], vec![]).is_err());
    }
}
