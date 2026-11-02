//! Encrypted PKCS#8 private keys (FR-04, SEC-04, SEC-15).
//!
//! Parameters (fixed, FR-04 AC1):
//! - Master key: PBES2 with scrypt and AES-256-CBC. scrypt N = 2^14, r = 8, p = 1.
//!   This is the strongest setting that stock `openssl pkey` can still decrypt:
//!   OpenSSL's default scrypt memory limit is 32 MiB, and N = 2^15 with r = 8 needs
//!   just over 32 MiB (checked with OpenSSL 3.0 `openssl pkey`, which fails with
//!   "memory limit exceeded" at N = 2^15). The passphrase (10 to 20 words, about 129 to
//!   258 bits, SEC-05) carries the strength; scrypt adds memory-hard cost on top.
//! - Sub-intermediate key: PBES2 with PBKDF2-HMAC-SHA256, exactly 600,000 iterations,
//!   and AES-256-CBC, the variant other issuing systems can read with standard
//!   libraries (OQ-1).
//! - Both: a fresh random 16-byte salt and 16-byte IV from the OS-seeded DRBG.
//!
//! Every encryption is checked by decrypting the result with the same passphrase and
//! comparing the public key before the PEM is returned, so an unreadable key file is
//! never written.
#![forbid(unsafe_code)]

use super::CryptoError;
use super::ffi::{self, Pbes2Kdf};
use super::pem;
use super::rsa::RsaPrivateKey;
use super::secret::SecretString;
use crate::limits::MAX_PEM_BYTES;

/// scrypt cost parameter N = 2^14 for the master key (see module docs).
pub const MASTER_SCRYPT_N: u64 = 1 << 14;
/// scrypt block size r for the master key.
pub const MASTER_SCRYPT_R: u64 = 8;
/// scrypt parallelism p for the master key.
pub const MASTER_SCRYPT_P: u64 = 1;
/// PBKDF2-HMAC-SHA256 iterations for sub-intermediate keys (FR-04 AC1: at least
/// 600,000; Keystone uses exactly 600,000).
pub const SUB_PBKDF2_ITERATIONS: u32 = 600_000;
/// Salt length in bytes for both schemes.
pub const SALT_LEN: usize = 16;

/// Encrypts the master key: PBES2, scrypt (N = 2^14, r = 8, p = 1), AES-256-CBC.
pub fn encrypt_master_key_pem(
    key: &RsaPrivateKey,
    passphrase: &SecretString,
) -> Result<String, CryptoError> {
    encrypt(
        key,
        passphrase,
        Pbes2Kdf::Scrypt {
            n: MASTER_SCRYPT_N,
            r: MASTER_SCRYPT_R,
            p: MASTER_SCRYPT_P,
        },
    )
}

/// Encrypts a sub-intermediate key: PBES2, PBKDF2-HMAC-SHA256 with 600,000
/// iterations, AES-256-CBC.
pub fn encrypt_sub_key_pem(
    key: &RsaPrivateKey,
    passphrase: &SecretString,
) -> Result<String, CryptoError> {
    encrypt(
        key,
        passphrase,
        Pbes2Kdf::Pbkdf2HmacSha256 {
            iterations: SUB_PBKDF2_ITERATIONS,
        },
    )
}

fn encrypt(
    key: &RsaPrivateKey,
    passphrase: &SecretString,
    kdf: Pbes2Kdf,
) -> Result<String, CryptoError> {
    if passphrase.is_empty() {
        return Err(CryptoError::EmptyPassphrase);
    }
    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; 16];
    super::rand::fill(&mut salt)?;
    super::rand::fill(&mut iv)?;
    let encrypted = ffi::encrypt_pkcs8_der(
        key.handle(),
        passphrase.as_secret_bytes().expose(),
        kdf,
        &salt,
        &iv,
    )?;
    let pem = pem::encode(pem::LABEL_ENCRYPTED_PRIVATE_KEY, &encrypted);
    let check = decrypt_key_pem(pem.as_bytes(), passphrase)?;
    if check.public_key_spki_der()? != key.public_key_spki_der()? {
        return Err(CryptoError::OpenSsl(
            "encrypted key failed its read-back check".into(),
        ));
    }
    Ok(pem)
}

/// Decrypts an encrypted PKCS#8 PEM key (FR-04 AC2, AC3).
///
/// The size limit is checked first (SEC-08). A plaintext key is refused
/// ([`CryptoError::NotEncrypted`]). A wrong passphrase gives
/// [`CryptoError::WrongPassphrase`] and no output.
pub fn decrypt_key_pem(
    pem: &[u8],
    passphrase: &SecretString,
) -> Result<RsaPrivateKey, CryptoError> {
    if pem.len() > MAX_PEM_BYTES {
        return Err(CryptoError::InputTooLarge {
            what: "key file",
            limit: MAX_PEM_BYTES,
            actual: pem.len(),
        });
    }
    let der = match pem::decode_one(pem, pem::LABEL_ENCRYPTED_PRIVATE_KEY, MAX_PEM_BYTES) {
        Ok(der) => der,
        Err(_) if contains_plaintext_private_key(pem) => return Err(CryptoError::NotEncrypted),
        Err(error) => return Err(error),
    };
    if passphrase.is_empty() {
        return Err(CryptoError::WrongPassphrase);
    }
    // The passphrase goes to OpenSSL straight from its locked buffer, with its length
    // (SEC-07); see `ffi::decrypt_pkcs8_der`.
    let key = ffi::decrypt_pkcs8_der(&der, passphrase.as_secret_bytes().expose())?;
    RsaPrivateKey::from_handle(key)
}

/// True when `bytes` contain an unencrypted private key: a PEM block labelled
/// `PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY` or any other `... PRIVATE KEY`
/// except `ENCRYPTED PRIVATE KEY`, or DER of an unencrypted PKCS#8 `PrivateKeyInfo`,
/// a PKCS#1 `RSAPrivateKey` or a SEC 1 `ECPrivateKey`, anywhere in the bytes,
/// including inside base64 PEM bodies with any label (SEC-04).
///
/// Used by the output scanner in tests. It never reports what it found beyond `true`.
pub fn contains_plaintext_private_key(bytes: &[u8]) -> bool {
    if has_plaintext_pem_label(bytes) || der_scan(bytes) {
        return true;
    }
    pem_bodies(bytes).any(|der| der_scan(&der))
}

fn has_plaintext_pem_label(bytes: &[u8]) -> bool {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const SUFFIX: &[u8] = b"PRIVATE KEY-----";
    let mut rest = bytes;
    while let Some(start) = find(rest, BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let label_end = find(after, b"-----").unwrap_or(after.len());
        let line = &after[..(label_end + 5).min(after.len())];
        if line.ends_with(SUFFIX) && !line.starts_with(b"ENCRYPTED ") {
            return true;
        }
        rest = after;
    }
    false
}

/// Base64 bodies of every PEM block in `bytes`, decoded leniently.
fn pem_bodies(bytes: &[u8]) -> impl Iterator<Item = Vec<u8>> + '_ {
    let mut rest = bytes;
    std::iter::from_fn(move || {
        loop {
            let start = find(rest, b"-----BEGIN ")?;
            let after = &rest[start..];
            let header_end = find(&after[5..], b"-----")? + 10;
            let body_start = &after[header_end.min(after.len())..];
            let end = find(body_start, b"-----END ")?;
            let body: String = body_start[..end]
                .iter()
                .filter(|b| !b.is_ascii_whitespace())
                .map(|b| *b as char)
                .collect();
            rest = &body_start[end..];
            if let Ok(der) = openssl::base64::decode_block(&body) {
                return Some(der);
            }
        }
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A DER tag-length-value header: (tag, content start, content length).
fn tlv(data: &[u8], at: usize) -> Option<(u8, usize, usize)> {
    let tag = *data.get(at)?;
    let first = *data.get(at + 1)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for index in 0..count {
            len = (len << 8) | usize::from(*data.get(at + 2 + index)?);
        }
        (len, 2 + count)
    };
    let start = at.checked_add(header)?;
    let end = start.checked_add(len)?;
    (end <= data.len()).then_some((tag, start, len))
}

/// Looks for the start of an unencrypted private-key structure at any offset.
fn der_scan(data: &[u8]) -> bool {
    (0..data.len()).any(|at| data[at] == 0x30 && looks_like_private_key(data, at))
}

fn looks_like_private_key(data: &[u8], at: usize) -> bool {
    let Some((_, seq_start, seq_len)) = tlv(data, at) else {
        return false;
    };
    let seq_end = seq_start + seq_len;
    // First element: INTEGER version with value 0 or 1.
    let Some((0x02, v_start, 1)) = tlv(data, seq_start) else {
        return false;
    };
    if data[v_start] > 1 {
        return false;
    }
    let next = v_start + 1;
    let Some((tag, start, len)) = tlv(data, next) else {
        return false;
    };
    if start + len > seq_end {
        return false;
    }
    match tag {
        // PKCS#8 PrivateKeyInfo: AlgorithmIdentifier (starting with an OID), then
        // OCTET STRING privateKey.
        0x30 => {
            let Some((0x06, _, _)) = tlv(data, start) else {
                return false;
            };
            matches!(tlv(data, start + len), Some((0x04, s, l)) if l >= 16 && s + l <= seq_end)
        }
        // PKCS#1 RSAPrivateKey: modulus, then publicExponent and privateExponent.
        0x02 => {
            if len < 64 {
                return false;
            }
            let Some((0x02, e_start, e_len)) = tlv(data, start + len) else {
                return false;
            };
            matches!(tlv(data, e_start + e_len), Some((0x02, s, l)) if l >= 64 && s + l <= seq_end)
        }
        // SEC 1 ECPrivateKey: version 1, OCTET STRING privateKey.
        0x04 => data[v_start] == 1 && (16..=66).contains(&len),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec04_detects_plaintext_pem_labels_but_not_encrypted() {
        // Covers: SEC-04
        assert!(contains_plaintext_private_key(
            b"x\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        ));
        assert!(contains_plaintext_private_key(
            b"-----BEGIN RSA PRIVATE KEY-----\n"
        ));
        assert!(contains_plaintext_private_key(
            b"-----BEGIN EC PRIVATE KEY-----"
        ));
        assert!(contains_plaintext_private_key(
            b"-----BEGIN OPENSSH PRIVATE KEY-----"
        ));
        assert!(!contains_plaintext_private_key(
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
        ));
        assert!(!contains_plaintext_private_key(
            b"-----BEGIN CERTIFICATE-----"
        ));
        assert!(!contains_plaintext_private_key(b"no keys here"));
    }

    #[test]
    fn sec04_detects_der_structures() {
        // Covers: SEC-04
        // Minimal SEC 1 EC private key shape: SEQ { INT 1, OCTET STRING(32) }.
        let mut ec = vec![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
        ec.extend_from_slice(&[0x11; 32]);
        let mut wrapped = b"prefix".to_vec();
        wrapped.extend_from_slice(&ec);
        assert!(contains_plaintext_private_key(&wrapped));
        // The same bytes inside a PEM block with an innocent label.
        let pem = pem::encode("DATA", &ec);
        assert!(contains_plaintext_private_key(pem.as_bytes()));
        // A public-key-like SEQ { INT n(big), INT e } is not a private key.
        let mut public = vec![0x30, 0x48, 0x02, 0x41, 0x00];
        public.extend_from_slice(&[0x55; 64]);
        public.extend_from_slice(&[0x02, 0x03, 0x01, 0x00, 0x01]);
        assert!(!contains_plaintext_private_key(&public));
    }
}
