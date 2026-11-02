//! Identifiers stored on the drives.
#![forbid(unsafe_code)]

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::CryptoError;
use crate::crypto::rand::fill;

macro_rules! id128 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; 16]);

        impl $name {
            /// A new random identifier.
            pub fn random() -> Result<Self, CryptoError> {
                let mut bytes = [0u8; 16];
                fill(&mut bytes)?;
                Ok($name(bytes))
            }

            /// Lowercase hex, 32 characters.
            pub fn to_hex(&self) -> String {
                self.0.iter().map(|b| format!("{b:02x}")).collect()
            }

            /// Parses exactly 32 lowercase hex characters.
            pub fn from_hex(text: &str) -> Option<Self> {
                let raw = text.as_bytes();
                if raw.len() != 32 || !raw.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                    return None;
                }
                let mut out = [0u8; 16];
                for (index, slot) in out.iter_mut().enumerate() {
                    *slot = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).ok()?;
                }
                Some($name(out))
            }

            /// First 8 hex characters, for labels shown to the operator.
            pub fn short(&self) -> String {
                self.to_hex()[..8].to_string()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                $name::from_hex(&text)
                    .ok_or_else(|| serde::de::Error::custom(concat!("invalid ", stringify!($name))))
            }
        }
    };
}

id128!(
    /// Identifies one CA: every drive of the same CA carries the same id.
    CaId
);
id128!(
    /// Identifies one physical CA drive.
    DriveId
);

/// Operation number (FR-22 AC1): 1, 2, 3 ... in the order operations began.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationId(pub u64);

/// Largest operation number (fits the 6-digit folder name).
pub const MAX_OPERATION_ID: u64 = 999_999;

impl OperationId {
    /// Folder and file stem: `op-000012`.
    pub fn stem(self) -> String {
        format!("op-{:06}", self.0)
    }

    /// Parses `op-NNNNNN` (exactly six digits, not zero).
    pub fn from_stem(text: &str) -> Option<Self> {
        let digits = text.strip_prefix("op-")?;
        if digits.len() != 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let value: u64 = digits.parse().ok()?;
        (value >= 1).then_some(OperationId(value))
    }

    /// True for 1..=999,999.
    pub fn is_valid(self) -> bool {
        (1..=MAX_OPERATION_ID).contains(&self.0)
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "operation {}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_and_reject_bad_hex() {
        let id = CaId::random().expect("random");
        assert_eq!(CaId::from_hex(&id.to_hex()), Some(id));
        assert_eq!(id.short().len(), 8);
        assert!(
            CaId::from_hex(&"A".repeat(32)).is_none(),
            "uppercase is not canonical"
        );
        assert!(DriveId::from_hex("zz").is_none());
        assert!(DriveId::from_hex(&"g".repeat(32)).is_none());
        let json = serde_json::to_string(&id).expect("json");
        assert_eq!(serde_json::from_str::<CaId>(&json).expect("parse"), id);
    }

    #[test]
    fn operation_stems() {
        assert_eq!(OperationId(12).stem(), "op-000012");
        assert_eq!(OperationId::from_stem("op-000012"), Some(OperationId(12)));
        assert_eq!(OperationId::from_stem("op-000000"), None);
        assert_eq!(OperationId::from_stem("op-12"), None);
        assert_eq!(OperationId::from_stem("op-+00012"), None);
        assert!(OperationId(1).is_valid());
        assert!(!OperationId(0).is_valid());
        assert!(!OperationId(1_000_000).is_valid());
    }
}
