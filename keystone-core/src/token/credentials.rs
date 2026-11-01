//! New PIN/PUK values and the typed wipe confirmation (FR-06 AC2, FR-07 AC4).
//!
//! Decisions (most conservative reading of "6 to 8 characters"):
//! - A new PIN or PUK is 6 to 8 printable ASCII characters without spaces
//!   (0x21 to 0x7E). Other characters would not fit the YubiKey's 8-byte limit or
//!   could be mistyped invisibly.
//! - The factory default may not be chosen again.
//! - Both entries must match exactly (constant-time comparison).
//! - The wipe confirmation must be exactly the device's decimal serial number, with
//!   no surrounding spaces.
#![forbid(unsafe_code)]

use std::fmt;

use super::{DEFAULT_PIN, DEFAULT_PUK, DeviceInfo, TokenError};
use crate::crypto::secret::SecretString;

fn validate(
    first: &SecretString,
    second: &SecretString,
    default: &str,
    mismatch: &'static str,
    length: &'static str,
    charset: &'static str,
    is_default: &'static str,
) -> Result<SecretString, TokenError> {
    if !first.ct_eq(second) {
        return Err(TokenError::InvalidNewCredential(mismatch));
    }
    let text = first.expose();
    if !(6..=8).contains(&text.len()) {
        return Err(TokenError::InvalidNewCredential(length));
    }
    if !text.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(TokenError::InvalidNewCredential(charset));
    }
    let default = SecretString::from_str_copy(default)?;
    if first.ct_eq(&default) {
        return Err(TokenError::InvalidNewCredential(is_default));
    }
    Ok(first.duplicate()?)
}

/// A new PIN, entered twice and validated (FR-06 AC2).
pub struct NewPin(SecretString);

impl NewPin {
    /// Validates the two entries.
    pub fn from_entries(first: &SecretString, second: &SecretString) -> Result<Self, TokenError> {
        validate(
            first,
            second,
            DEFAULT_PIN,
            "the two PIN entries do not match",
            "the PIN must be 6 to 8 characters",
            "the PIN may contain only letters, digits and symbols (no spaces)",
            "the new PIN must not be the factory default 123456",
        )
        .map(NewPin)
    }

    /// The new PIN.
    pub fn secret(&self) -> &SecretString {
        &self.0
    }
}

impl fmt::Debug for NewPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NewPin([REDACTED])")
    }
}

/// A new PUK, entered twice and validated (FR-06 AC2).
pub struct NewPuk(SecretString);

impl NewPuk {
    /// Validates the two entries.
    pub fn from_entries(first: &SecretString, second: &SecretString) -> Result<Self, TokenError> {
        validate(
            first,
            second,
            DEFAULT_PUK,
            "the two PUK entries do not match",
            "the PUK must be 6 to 8 characters",
            "the PUK may contain only letters, digits and symbols (no spaces)",
            "the new PUK must not be the factory default 12345678",
        )
        .map(NewPuk)
    }

    /// The new PUK.
    pub fn secret(&self) -> &SecretString {
        &self.0
    }
}

impl fmt::Debug for NewPuk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NewPuk([REDACTED])")
    }
}

/// Proof that the operator typed this YubiKey's serial number to confirm a slot
/// wipe (FR-07 AC4). Implementations of `wipe_slot` refuse a confirmation for a
/// different serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WipeConfirmation {
    serial: u32,
}

impl WipeConfirmation {
    /// Accepts `typed` only if it is exactly the decimal serial of `device`.
    pub fn new(typed: &str, device: &DeviceInfo) -> Result<Self, TokenError> {
        if typed == device.serial.to_string() {
            Ok(WipeConfirmation {
                serial: device.serial,
            })
        } else {
            Err(TokenError::WipeConfirmationMismatch)
        }
    }

    /// The confirmed serial.
    pub fn serial(&self) -> u32 {
        self.serial
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::FirmwareVersion;

    fn s(text: &str) -> SecretString {
        SecretString::from_str_copy(text).unwrap()
    }

    #[test]
    fn fr06_ac2_new_pin_rules() {
        // Covers: FR-06 AC2
        assert!(NewPin::from_entries(&s("Kx7#pq"), &s("Kx7#pq")).is_ok());
        assert!(NewPin::from_entries(&s("Kx7#pq12"), &s("Kx7#pq12")).is_ok());
        let cases = [
            ("Kx7#pq", "Kx7#pQ", "do not match"),
            ("12345", "12345", "6 to 8"),
            ("123456789", "123456789", "6 to 8"),
            ("abc def", "abc def", "no spaces"),
            ("123456", "123456", "factory default"),
            ("äbcdef", "äbcdef", "no spaces"),
        ];
        for (first, second, expected) in cases {
            let error = NewPin::from_entries(&s(first), &s(second)).unwrap_err();
            assert!(error.to_string().contains(expected), "{first:?}: {error}");
        }
        let shown = format!(
            "{:?}",
            NewPin::from_entries(&s("Kx7#pq"), &s("Kx7#pq")).unwrap()
        );
        assert!(!shown.contains("Kx7"));
    }

    #[test]
    fn fr06_ac2_new_puk_rules() {
        // Covers: FR-06 AC2
        assert!(NewPuk::from_entries(&s("87654321"), &s("87654321")).is_ok());
        assert!(NewPuk::from_entries(&s("12345678"), &s("12345678")).is_err());
        assert!(NewPuk::from_entries(&s("876543"), &s("876544")).is_err());
    }

    #[test]
    fn fr07_ac4_wipe_needs_exact_serial() {
        // Covers: FR-07 AC4
        let device = DeviceInfo {
            serial: 31_415_926,
            firmware: FirmwareVersion::new(5, 7, 4),
        };
        assert_eq!(
            WipeConfirmation::new("31415926", &device).unwrap().serial(),
            31_415_926
        );
        for wrong in ["", "3141592", "31415926 ", "031415926", "31415927"] {
            assert!(matches!(
                WipeConfirmation::new(wrong, &device),
                Err(TokenError::WipeConfirmationMismatch)
            ));
        }
    }
}
