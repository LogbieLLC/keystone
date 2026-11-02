//! `keystone/binary.sha256`: the binary's SHA-256 recorded at install (SEC-19).
//!
//! Format, one line in `sha256sum` style: `<64 lowercase hex>  keystone\n`. The check on
//! start only detects corruption or an accidental change (a deliberately modified binary
//! could skip its own check); the real authenticity check is the operator's `sha256sum`
//! before install.
#![forbid(unsafe_code)]

use super::audit::{AuditAction, AuditDetails, AuditDraft, AuditResult};
use super::drive::{CaDrive, DriveSet, check_len};
use super::fsio::WriteMode;
use super::paths::BINARY_HASH_FILE;
use super::{ParseError, StoreError};
use crate::limits::MAX_METADATA_BYTES;
use crate::model::{Sha256Digest, Timestamp};

/// The file name written after the hash.
pub const BINARY_NAME: &str = "keystone";

/// Parses a binary hash record (SEC-08). Never panics on any input.
pub fn parse_binary_hash_record(bytes: &[u8]) -> Result<Sha256Digest, ParseError> {
    check_len(bytes, MAX_METADATA_BYTES)?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ParseError::invalid("binary hash record is not text"))?;
    let line = text
        .strip_suffix('\n')
        .ok_or_else(|| ParseError::invalid("binary hash record must end with a newline"))?;
    let (hex, name) = line
        .split_once("  ")
        .ok_or_else(|| ParseError::invalid("binary hash record must be '<sha256>  keystone'"))?;
    if name != BINARY_NAME || hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(ParseError::invalid(
            "binary hash record must be '<sha256>  keystone'",
        ));
    }
    Sha256Digest::from_hex(hex)
        .ok_or_else(|| ParseError::invalid("invalid SHA-256 in binary hash record"))
}

/// The record's file content for `digest`.
pub fn format_binary_hash_record(digest: Sha256Digest) -> String {
    format!("{}  {BINARY_NAME}\n", digest.to_hex())
}

impl CaDrive {
    /// The binary hash recorded on this drive, if any (SEC-19).
    pub fn binary_hash(&self) -> Result<Option<Sha256Digest>, StoreError> {
        match self
            .keystone()
            .read_if_exists(BINARY_HASH_FILE, MAX_METADATA_BYTES)?
        {
            None => Ok(None),
            Some(bytes) => parse_binary_hash_record(&bytes)
                .map(Some)
                .map_err(|source| StoreError::Parse {
                    path: self.keystone().child(BINARY_HASH_FILE),
                    source,
                }),
        }
    }
}

impl DriveSet {
    /// Records the installed binary's SHA-256 on every drive (SEC-19, "updated at each
    /// install") and appends an audit entry.
    pub fn record_binary_hash(
        &self,
        digest: Sha256Digest,
        time: Timestamp,
    ) -> Result<(), StoreError> {
        self.ensure_writable()?;
        self.audit_log()?;
        self.write_verified(
            "",
            BINARY_HASH_FILE,
            format_binary_hash_record(digest).as_bytes(),
            WriteMode::Replace,
        )?;
        let mut draft = AuditDraft::new(AuditAction::BinaryHashRecorded, "", AuditResult::Success);
        draft.details = Some(AuditDetails {
            note: Some(format!("binary SHA-256 {}", digest.to_hex())),
            ..AuditDetails::default()
        });
        self.append_audit(&[draft], time)?;
        Ok(())
    }

    /// The binary hash recorded on each drive, in drive order.
    pub fn binary_hashes(&self) -> Result<Vec<(String, Option<Sha256Digest>)>, StoreError> {
        self.drives()
            .iter()
            .map(|drive| Ok((drive.label(), drive.binary_hash()?)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec19_record_round_trip_and_strict_parse() {
        // Covers: SEC-19, SEC-08
        let digest = Sha256Digest([0xab; 32]);
        let text = format_binary_hash_record(digest);
        assert_eq!(parse_binary_hash_record(text.as_bytes()), Ok(digest));
        for bad in [
            text.trim_end().to_string(),
            text.replace("keystone", "other"),
            text.to_uppercase(),
            text.replacen("  ", " ", 1),
            format!("{text}extra\n"),
            "\u{0}".to_string(),
        ] {
            assert!(parse_binary_hash_record(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert!(parse_binary_hash_record(&vec![b'a'; MAX_METADATA_BYTES + 1]).is_err());
    }

    proptest::proptest! {
        #[test]
        fn sec08_binary_hash_parser_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            // Covers: SEC-08
            let _ = parse_binary_hash_record(&bytes);
        }
    }
}
