//! Secret buffers: zeroizing, memory-locked, never printed (SEC-07).
//!
//! Passphrases, PINs, PUKs and other secrets are held only in these types.
//! - The memory is locked into RAM (not swappable) and excluded from core dumps.
//! - The buffer has a fixed capacity and never reallocates, so no unwiped copy is
//!   left behind by growth.
//! - It is wiped when dropped.
//! - `Debug` never shows the content.
//! - There is no `Clone`, `Display`, `Serialize` or `Deserialize`, so a secret
//!   cannot reach a log, a file or the clipboard by accident.
#![forbid(unsafe_code)]

use std::fmt;

use super::CryptoError;
use super::ffi::LockedRegion;

/// Secret bytes in locked, wiped-on-drop memory.
pub struct SecretBytes {
    region: LockedRegion,
    len: usize,
}

impl SecretBytes {
    /// An empty secret that can hold at least `capacity` bytes.
    pub fn with_capacity(capacity: usize) -> Result<Self, CryptoError> {
        Ok(SecretBytes {
            region: LockedRegion::new(capacity)?,
            len: 0,
        })
    }

    /// Copies `data` into a new secret. The caller remains responsible for wiping `data`.
    pub fn from_slice(data: &[u8]) -> Result<Self, CryptoError> {
        let mut secret = SecretBytes::with_capacity(data.len())?;
        secret.extend_from_slice(data)?;
        Ok(secret)
    }

    /// Appends bytes. Fails instead of reallocating when the capacity is exceeded.
    pub fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let end = self
            .len
            .checked_add(data.len())
            .filter(|end| *end <= self.region.capacity())
            .ok_or(CryptoError::SecretCapacity)?;
        self.region.as_mut_slice()[self.len..end].copy_from_slice(data);
        self.len = end;
        Ok(())
    }

    /// Shortens the secret to `new_len` bytes and wipes the removed bytes.
    pub fn truncate(&mut self, new_len: usize) {
        if new_len < self.len {
            self.region.as_mut_slice()[new_len..self.len].fill(0);
            self.len = new_len;
        }
    }

    /// Wipes the content; capacity is kept.
    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// Read access to the secret. Keep the borrow as short as possible.
    pub fn expose(&self) -> &[u8] {
        &self.region.as_slice()[..self.len]
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Maximum length without reallocation.
    pub fn capacity(&self) -> usize {
        self.region.capacity()
    }

    /// Constant-time equality (does not leak where two secrets differ).
    pub fn ct_eq(&self, other: &SecretBytes) -> bool {
        constant_time_eq(self.expose(), other.expose())
    }

    /// Explicit copy into new locked memory (there is deliberately no `Clone`).
    pub fn duplicate(&self) -> Result<SecretBytes, CryptoError> {
        SecretBytes::from_slice(self.expose())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED; {}])", self.len)
    }
}

/// Secret UTF-8 text (passphrases, PIN, PUK) in locked, wiped-on-drop memory.
pub struct SecretString {
    bytes: SecretBytes,
}

impl SecretString {
    /// An empty secret string that can hold at least `capacity` bytes.
    pub fn with_capacity(capacity: usize) -> Result<Self, CryptoError> {
        Ok(SecretString {
            bytes: SecretBytes::with_capacity(capacity)?,
        })
    }

    /// Copies `text` into a new secret. The caller remains responsible for wiping `text`.
    pub fn from_str_copy(text: &str) -> Result<Self, CryptoError> {
        Ok(SecretString {
            bytes: SecretBytes::from_slice(text.as_bytes())?,
        })
    }

    /// Appends text. Fails instead of reallocating when the capacity is exceeded.
    pub fn push_str(&mut self, text: &str) -> Result<(), CryptoError> {
        self.bytes.extend_from_slice(text.as_bytes())
    }

    /// Appends one character.
    pub fn push(&mut self, ch: char) -> Result<(), CryptoError> {
        let mut buffer = [0u8; 4];
        let encoded = ch.encode_utf8(&mut buffer);
        let result = self.bytes.extend_from_slice(encoded.as_bytes());
        buffer.fill(0);
        result
    }

    /// Read access to the secret text. Keep the borrow as short as possible.
    pub fn expose(&self) -> &str {
        std::str::from_utf8(self.bytes.expose()).expect("only valid UTF-8 is ever appended")
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Wipes the content; capacity is kept.
    pub fn clear(&mut self) {
        self.bytes.clear();
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &SecretString) -> bool {
        self.bytes.ct_eq(&other.bytes)
    }

    /// Explicit copy into new locked memory.
    pub fn duplicate(&self) -> Result<SecretString, CryptoError> {
        Ok(SecretString {
            bytes: self.bytes.duplicate()?,
        })
    }

    /// The secret as bytes.
    pub fn as_secret_bytes(&self) -> &SecretBytes {
        &self.bytes
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString([REDACTED; {}])", self.bytes.len())
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    openssl::memcmp::eq(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec07_secret_debug_is_redacted() {
        // Covers: SEC-07
        let secret = SecretString::from_str_copy("correct horse").expect("lock");
        let shown = format!("{secret:?}");
        assert!(!shown.contains("horse"));
        assert!(shown.contains("REDACTED"));
    }

    #[test]
    fn sec07_secret_never_reallocates() {
        // Covers: SEC-07
        let mut secret = SecretBytes::with_capacity(4).expect("lock");
        let capacity = secret.capacity();
        secret
            .extend_from_slice(&vec![1u8; capacity])
            .expect("fits");
        assert!(matches!(
            secret.extend_from_slice(&[1]),
            Err(CryptoError::SecretCapacity)
        ));
    }

    #[test]
    fn secret_string_push_truncate_and_compare() {
        let mut first = SecretString::with_capacity(32).expect("lock");
        first.push_str("abc").expect("fits");
        first.push('é').expect("fits");
        assert_eq!(first.expose(), "abcé");
        let second = first.duplicate().expect("lock");
        assert!(first.ct_eq(&second));
        first.clear();
        assert!(first.is_empty());
        assert!(!first.ct_eq(&second));
    }
}
