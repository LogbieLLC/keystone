//! Shared domain types used by every part of the core crate.
#![forbid(unsafe_code)]

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;

/// The three levels of the CA hierarchy (PRD section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaLevel {
    /// RSA 8,192 root, key in an encrypted file.
    Master,
    /// RSA 4,096 on the YubiKey, signed by the master.
    MainIntermediate,
    /// RSA 4,096 in an encrypted file, signed by the main intermediate.
    SubIntermediate,
}

impl CaLevel {
    /// The level that signs this level, or `None` for the self-signed master.
    pub const fn issuer_level(self) -> Option<CaLevel> {
        match self {
            CaLevel::Master => None,
            CaLevel::MainIntermediate => Some(CaLevel::Master),
            CaLevel::SubIntermediate => Some(CaLevel::MainIntermediate),
        }
    }

    /// Human-readable name for the GUI and audit log.
    pub const fn display_name(self) -> &'static str {
        match self {
            CaLevel::Master => "master (root)",
            CaLevel::MainIntermediate => "main intermediate",
            CaLevel::SubIntermediate => "sub-intermediate",
        }
    }
}

/// Number of bytes in a certificate serial number (FR-10 AC2: 159 random bits, positive).
pub const SERIAL_LEN: usize = 20;

/// A certificate serial number: 159 random bits, always positive (top bit clear)
/// and never zero (FR-10 AC2).
///
/// Generate new serials only with `crypto::rand::random_serial`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Serial([u8; SERIAL_LEN]);

impl Serial {
    /// Wraps raw bytes. Fails if the value would be negative or zero as a DER INTEGER.
    pub fn from_bytes(bytes: [u8; SERIAL_LEN]) -> Option<Self> {
        if bytes[0] & 0x80 != 0 || bytes.iter().all(|b| *b == 0) {
            return None;
        }
        Some(Serial(bytes))
    }

    /// Parses a serial from the big-endian magnitude of a positive DER INTEGER,
    /// as found in a certificate (leading zero bytes are allowed and ignored).
    pub fn from_be_slice(bytes: &[u8]) -> Option<Self> {
        let trimmed: &[u8] = {
            let first_non_zero = bytes.iter().position(|b| *b != 0)?;
            &bytes[first_non_zero..]
        };
        if trimmed.len() > SERIAL_LEN {
            return None;
        }
        let mut out = [0u8; SERIAL_LEN];
        out[SERIAL_LEN - trimmed.len()..].copy_from_slice(trimmed);
        Serial::from_bytes(out)
    }

    /// The 20 big-endian bytes (top bit always clear).
    pub const fn as_bytes(&self) -> &[u8; SERIAL_LEN] {
        &self.0
    }

    /// Lowercase hex, 40 characters.
    pub fn to_hex(&self) -> String {
        hex_lower(&self.0)
    }

    /// Parses 40 hex characters.
    pub fn from_hex(text: &str) -> Option<Self> {
        let bytes = parse_hex::<SERIAL_LEN>(text)?;
        Serial::from_bytes(bytes)
    }
}

impl fmt::Debug for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Serial({})", self.to_hex())
    }
}

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Serial {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Serial {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Serial::from_hex(&text).ok_or_else(|| serde::de::Error::custom("invalid serial number"))
    }
}

/// A SHA-256 digest (file hashes, audit-log chain, certificate fingerprints).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Digest(pub [u8; 32]);

impl Sha256Digest {
    /// Lowercase hex, 64 characters (used in files).
    pub fn to_hex(&self) -> String {
        hex_lower(&self.0)
    }

    /// Parses 64 hex characters.
    pub fn from_hex(text: &str) -> Option<Self> {
        parse_hex::<32>(text).map(Sha256Digest)
    }

    /// Copy-friendly fingerprint for the operator: uppercase hex pairs separated by
    /// colons, as `openssl x509 -fingerprint -sha256` prints it (FR-20 AC1).
    pub fn to_fingerprint_string(&self) -> String {
        let mut out = String::with_capacity(32 * 3);
        for (index, byte) in self.0.iter().enumerate() {
            if index > 0 {
                out.push(':');
            }
            out.push_str(&format!("{byte:02X}"));
        }
        out
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256({})", self.to_hex())
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Sha256Digest::from_hex(&text).ok_or_else(|| serde::de::Error::custom("invalid SHA-256"))
    }
}

/// SHA-256 fingerprint of a certificate's DER encoding (FR-11 AC1, FR-20, SEC-10).
pub type Fingerprint = Sha256Digest;

/// Subject name fields the operator may edit (FR-02 AC4, FR-10 AC3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameFields {
    /// Common Name, required.
    pub common_name: String,
    /// Organization, optional.
    pub organization: Option<String>,
    /// Country, optional, exactly 2 letters.
    pub country: Option<String>,
}

/// Reason codes offered when revoking (RFC 5280 section 5.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
}

impl RevocationReason {
    /// RFC 5280 CRLReason enumerated value.
    pub const fn code(self) -> u8 {
        match self {
            RevocationReason::Unspecified => 0,
            RevocationReason::KeyCompromise => 1,
            RevocationReason::CaCompromise => 2,
            RevocationReason::AffiliationChanged => 3,
            RevocationReason::Superseded => 4,
            RevocationReason::CessationOfOperation => 5,
        }
    }

    /// Every reason, in the order the GUI lists them.
    pub const ALL: [RevocationReason; 6] = [
        RevocationReason::Unspecified,
        RevocationReason::KeyCompromise,
        RevocationReason::CaCompromise,
        RevocationReason::AffiliationChanged,
        RevocationReason::Superseded,
        RevocationReason::CessationOfOperation,
    ];
}

/// UTC timestamp stored in every persisted file as RFC 3339 text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(#[serde(with = "time::serde::rfc3339")] pub OffsetDateTime);

impl Timestamp {
    /// Converts any offset to UTC (persisted timestamps are always UTC).
    pub fn utc(value: OffsetDateTime) -> Self {
        Timestamp(value.to_offset(time::UtcOffset::UTC))
    }

    /// The wrapped value.
    pub const fn get(self) -> OffsetDateTime {
        self.0
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn parse_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let raw = text.as_bytes();
    if raw.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (index, [high, low]) in raw.as_chunks::<2>().0.iter().enumerate() {
        let high = hex_value(*high)?;
        let low = hex_value(*low)?;
        out[index] = (high << 4) | low;
    }
    Some(out)
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr10_ac2_serial_rejects_negative_and_zero() {
        // Covers: FR-10 AC2
        let mut negative = [0u8; SERIAL_LEN];
        negative[0] = 0x80;
        assert!(Serial::from_bytes(negative).is_none());
        assert!(Serial::from_bytes([0u8; SERIAL_LEN]).is_none());
        let mut ok = [0u8; SERIAL_LEN];
        ok[0] = 0x7f;
        assert!(Serial::from_bytes(ok).is_some());
    }

    #[test]
    fn serial_hex_round_trip_and_be_slice() {
        let mut bytes = [0u8; SERIAL_LEN];
        bytes[19] = 0x42;
        let serial = Serial::from_bytes(bytes).expect("valid");
        assert_eq!(Serial::from_hex(&serial.to_hex()), Some(serial));
        assert_eq!(Serial::from_be_slice(&[0x00, 0x42]), Some(serial));
        assert!(Serial::from_be_slice(&[0u8; 21]).is_none());
        assert!(Serial::from_be_slice(&[1u8; 21]).is_none());
    }

    #[test]
    fn fr20_ac1_fingerprint_is_copy_friendly() {
        // Covers: FR-20 AC1
        let digest = Sha256Digest([0xab; 32]);
        let text = digest.to_fingerprint_string();
        assert_eq!(text.len(), 32 * 3 - 1);
        assert!(text.starts_with("AB:AB:"));
        assert_eq!(Sha256Digest::from_hex(&digest.to_hex()), Some(digest));
    }

    #[test]
    fn timestamp_serializes_as_rfc3339_utc() {
        let value = Timestamp::utc(
            OffsetDateTime::from_unix_timestamp(1_793_491_200).expect("valid epoch"),
        );
        let json = serde_json::to_string(&value).expect("serialize");
        assert_eq!(json, "\"2026-11-01T00:00:00Z\"");
        let back: Timestamp = serde_json::from_str(&json).expect("parse");
        assert_eq!(back, value);
    }
}
