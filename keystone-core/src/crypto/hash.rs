//! Hash functions (OpenSSL).
#![forbid(unsafe_code)]

use openssl::hash::{MessageDigest, hash};

use crate::model::Sha256Digest;

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> Sha256Digest {
    let digest = hash(MessageDigest::sha256(), data).expect("OpenSSL SHA-256 cannot fail");
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Sha256Digest(out)
}

/// SHA-384 of `data` (the signature hash in the fixed profile).
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let digest = hash(MessageDigest::sha384(), data).expect("OpenSSL SHA-384 cannot fail");
    let mut out = [0u8; 48];
    out.copy_from_slice(&digest);
    out
}

/// SHA-1 of `data`. Used only for the subjectKeyIdentifier method (1) of
/// RFC 5280 section 4.2.1.2, never for signatures.
pub fn sha1_for_key_identifier(data: &[u8]) -> [u8; 20] {
    let digest = hash(MessageDigest::sha1(), data).expect("OpenSSL SHA-1 cannot fail");
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

/// Streaming SHA-256 for large files.
pub struct Sha256Stream(openssl::sha::Sha256);

impl std::fmt::Debug for Sha256Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sha256Stream")
    }
}

impl Sha256Stream {
    /// A new, empty hash.
    pub fn new() -> Self {
        Sha256Stream(openssl::sha::Sha256::new())
    }

    /// Adds bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finishes the hash.
    pub fn finish(self) -> Sha256Digest {
        Sha256Digest(self.0.finish())
    }
}

impl Default for Sha256Stream {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            sha256(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut stream = Sha256Stream::new();
        stream.update(b"a");
        stream.update(b"bc");
        assert_eq!(stream.finish(), sha256(b"abc"));
    }

    #[test]
    fn sha384_known_answer() {
        let digest = sha384(b"abc");
        assert_eq!(digest[0], 0xcb);
        assert_eq!(digest[47], 0xa7);
    }
}
