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

use x509_cert::der::oid::ObjectIdentifier;

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
/// ([`CryptoError::NotEncrypted`]). Encryption parameters other than the two sets
/// Keystone writes are refused before any key derivation
/// ([`CryptoError::UnsupportedKeyEncryption`], SEC-08). A wrong passphrase gives
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
    // SEC-08: the KDF parameters come from the file, so a tampered file could ask for
    // an enormous cost and hang decryption. Only Keystone's own two sets are accepted,
    // before any key derivation runs.
    check_encryption_parameters(&der)?;
    if passphrase.is_empty() {
        return Err(CryptoError::WrongPassphrase);
    }
    // The passphrase goes to OpenSSL straight from its locked buffer, with its length
    // (SEC-07); see `ffi::decrypt_pkcs8_der`.
    let key = ffi::decrypt_pkcs8_der(&der, passphrase.as_secret_bytes().expose())?;
    RsaPrivateKey::from_handle(key)
}

/// PBES2 (PKCS #5 v2.0, RFC 8018).
const OID_PBES2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.13");
/// PBKDF2 (RFC 8018).
const OID_PBKDF2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.12");
/// id-scrypt (RFC 7914).
const OID_SCRYPT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11591.4.11");
/// hmacWithSHA256 (RFC 8018).
const OID_HMAC_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.9");
/// aes256-CBC (NIST).
const OID_AES_256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;

/// A strict DER reader for the few fixed structures of an `EncryptedPrivateKeyInfo`:
/// definite, minimal lengths only, every element exactly inside its parent.
struct DerReader<'a> {
    rest: &'a [u8],
}

fn malformed(what: &str) -> CryptoError {
    CryptoError::Der(format!("the encrypted key file is malformed ({what})"))
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        DerReader { rest: data }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn next_tag(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    /// Reads one element with `tag` and returns its content.
    fn read(&mut self, tag: u8, what: &str) -> Result<&'a [u8], CryptoError> {
        let (&found, rest) = self.rest.split_first().ok_or_else(|| malformed(what))?;
        if found != tag {
            return Err(malformed(what));
        }
        let (&first, rest) = rest.split_first().ok_or_else(|| malformed(what))?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            // Long form: 1 to 4 length bytes, no leading zero, and only for >= 128.
            let count = usize::from(first & 0x7f);
            if !(1..=4).contains(&count) || rest.len() < count || rest[0] == 0 {
                return Err(malformed(what));
            }
            let (bytes, rest) = rest.split_at(count);
            let len = bytes
                .iter()
                .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
            if len < 0x80 {
                return Err(malformed(what));
            }
            (len, rest)
        };
        if rest.len() < len {
            return Err(malformed(what));
        }
        let (content, rest) = rest.split_at(len);
        self.rest = rest;
        Ok(content)
    }

    /// Fails unless everything was read.
    fn finish(&self, what: &str) -> Result<(), CryptoError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(malformed(what))
        }
    }
}

/// A non-negative DER INTEGER of at most 64 bits, minimally encoded.
fn small_uint(content: &[u8], what: &str) -> Result<u64, CryptoError> {
    let digits = match content {
        [] => return Err(malformed(what)),
        [first, ..] if *first >= 0x80 => return Err(malformed(what)),
        [0, next, ..] if *next < 0x80 => return Err(malformed(what)),
        [0, rest @ ..] => rest,
        all => all,
    };
    if digits.len() > 8 {
        return Err(CryptoError::UnsupportedKeyEncryption(format!(
            "{what} is out of range"
        )));
    }
    Ok(digits
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)))
}

/// Checks that `der`, an `EncryptedPrivateKeyInfo`, uses exactly one of the two
/// parameter sets Keystone writes (see the module documentation), before anything
/// is decrypted (SEC-08):
/// - PBES2 with scrypt (16-byte salt, N = 2^14, r = 8, p = 1, no key length), or
///   PBES2 with PBKDF2 (16-byte salt, 600,000 iterations, no key length, PRF
///   hmacWithSHA256 with NULL parameters);
/// - in both cases AES-256-CBC with a 16-byte IV.
///
/// A broken structure is [`CryptoError::Der`]; any other parameters are
/// [`CryptoError::UnsupportedKeyEncryption`]. Only a few bytes are read, so a hostile
/// file is refused at once.
fn check_encryption_parameters(der: &[u8]) -> Result<(), CryptoError> {
    let unsupported = |detail: String| CryptoError::UnsupportedKeyEncryption(detail);
    let mut file = DerReader::new(der);
    let mut info = DerReader::new(file.read(TAG_SEQUENCE, "EncryptedPrivateKeyInfo")?);
    file.finish("data after the key")?;
    let mut algorithm = DerReader::new(info.read(TAG_SEQUENCE, "encryption algorithm")?);
    info.read(TAG_OCTET_STRING, "encrypted data")?;
    info.finish("EncryptedPrivateKeyInfo")?;

    if algorithm.read(TAG_OID, "encryption algorithm")? != OID_PBES2.as_bytes() {
        return Err(unsupported("the scheme is not PBES2".into()));
    }
    let mut params = DerReader::new(algorithm.read(TAG_SEQUENCE, "PBES2 parameters")?);
    algorithm.finish("encryption algorithm")?;
    let mut kdf = DerReader::new(params.read(TAG_SEQUENCE, "key derivation function")?);
    let mut cipher = DerReader::new(params.read(TAG_SEQUENCE, "encryption scheme")?);
    params.finish("PBES2 parameters")?;

    if cipher.read(TAG_OID, "encryption scheme")? != OID_AES_256_CBC.as_bytes() {
        return Err(unsupported("the cipher is not AES-256-CBC".into()));
    }
    let iv = cipher.read(TAG_OCTET_STRING, "IV")?;
    cipher.finish("encryption scheme")?;
    if iv.len() != 16 {
        return Err(unsupported(format!("the IV is {} bytes, not 16", iv.len())));
    }

    let kdf_oid = kdf.read(TAG_OID, "key derivation function")?;
    let mut kdf_params = DerReader::new(kdf.read(TAG_SEQUENCE, "key derivation parameters")?);
    kdf.finish("key derivation function")?;
    let salt = kdf_params.read(TAG_OCTET_STRING, "salt")?;
    if salt.len() != SALT_LEN {
        return Err(unsupported(format!(
            "the salt is {} bytes, not {SALT_LEN}",
            salt.len()
        )));
    }
    if kdf_oid == OID_SCRYPT.as_bytes() {
        let n = small_uint(kdf_params.read(TAG_INTEGER, "scrypt N")?, "scrypt N")?;
        let r = small_uint(kdf_params.read(TAG_INTEGER, "scrypt r")?, "scrypt r")?;
        let p = small_uint(kdf_params.read(TAG_INTEGER, "scrypt p")?, "scrypt p")?;
        if (n, r, p) != (MASTER_SCRYPT_N, MASTER_SCRYPT_R, MASTER_SCRYPT_P) {
            return Err(unsupported(format!(
                "scrypt with N = {n}, r = {r}, p = {p}"
            )));
        }
        if !kdf_params.is_empty() {
            return Err(unsupported(
                "the scrypt parameters carry a key length".into(),
            ));
        }
        Ok(())
    } else if kdf_oid == OID_PBKDF2.as_bytes() {
        let iterations = small_uint(
            kdf_params.read(TAG_INTEGER, "PBKDF2 iteration count")?,
            "PBKDF2 iteration count",
        )?;
        if iterations != u64::from(SUB_PBKDF2_ITERATIONS) {
            return Err(unsupported(format!("PBKDF2 with {iterations} iterations")));
        }
        match kdf_params.next_tag() {
            Some(TAG_INTEGER) => {
                return Err(unsupported(
                    "the PBKDF2 parameters carry a key length".into(),
                ));
            }
            None => {
                return Err(unsupported(
                    "the PBKDF2 PRF is not hmacWithSHA256 (HMAC-SHA1 by default)".into(),
                ));
            }
            Some(_) => {}
        }
        let mut prf = DerReader::new(kdf_params.read(TAG_SEQUENCE, "PBKDF2 PRF")?);
        kdf_params.finish("PBKDF2 parameters")?;
        if prf.read(TAG_OID, "PBKDF2 PRF")? != OID_HMAC_WITH_SHA256.as_bytes() {
            return Err(unsupported("the PBKDF2 PRF is not hmacWithSHA256".into()));
        }
        if !prf.read(TAG_NULL, "PBKDF2 PRF parameters")?.is_empty() {
            return Err(malformed("PBKDF2 PRF parameters"));
        }
        prf.finish("PBKDF2 PRF")
    } else {
        Err(unsupported(
            "the key derivation function is neither scrypt nor PBKDF2".into(),
        ))
    }
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

    /// DER tag, minimal length and content (contents here stay below 256 bytes).
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let len = u8::try_from(content.len()).unwrap();
        let mut out = vec![tag];
        if len >= 0x80 {
            out.push(0x81);
        }
        out.push(len);
        out.extend_from_slice(content);
        out
    }

    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(TAG_SEQUENCE, &parts.concat())
    }

    fn oid(oid: &ObjectIdentifier) -> Vec<u8> {
        tlv(TAG_OID, oid.as_bytes())
    }

    /// An `EncryptedPrivateKeyInfo` with the given KDF and cipher AlgorithmIdentifiers.
    fn file(kdf: Vec<u8>, cipher: Vec<u8>) -> Vec<u8> {
        seq(&[
            seq(&[oid(&OID_PBES2), seq(&[kdf, cipher])]),
            tlv(TAG_OCTET_STRING, &[0x5a; 48]),
        ])
    }

    fn aes(iv_len: usize) -> Vec<u8> {
        seq(&[
            oid(&OID_AES_256_CBC),
            tlv(TAG_OCTET_STRING, &vec![7; iv_len]),
        ])
    }

    fn pbkdf2(salt_len: usize, extra: &[Vec<u8>]) -> Vec<u8> {
        let mut params = vec![
            tlv(TAG_OCTET_STRING, &vec![1; salt_len]),
            tlv(TAG_INTEGER, &[0x09, 0x27, 0xc0]),
        ];
        params.extend_from_slice(extra);
        seq(&[oid(&OID_PBKDF2), seq(&params)])
    }

    fn sha256_prf() -> Vec<u8> {
        seq(&[oid(&OID_HMAC_WITH_SHA256), tlv(TAG_NULL, &[])])
    }

    fn scrypt(salt_len: usize, n: &[u8], extra: &[Vec<u8>]) -> Vec<u8> {
        let mut params = vec![
            tlv(TAG_OCTET_STRING, &vec![1; salt_len]),
            tlv(TAG_INTEGER, n),
            tlv(TAG_INTEGER, &[8]),
            tlv(TAG_INTEGER, &[1]),
        ];
        params.extend_from_slice(extra);
        seq(&[oid(&OID_SCRYPT), seq(&params)])
    }

    fn unsupported(der: &[u8], detail: &str) {
        match check_encryption_parameters(der) {
            Err(CryptoError::UnsupportedKeyEncryption(text)) => {
                assert!(text.contains(detail), "{text:?} lacks {detail:?}");
            }
            other => panic!("expected UnsupportedKeyEncryption({detail}), got {other:?}"),
        }
    }

    fn malformed_der(der: &[u8]) {
        assert!(
            matches!(check_encryption_parameters(der), Err(CryptoError::Der(_))),
            "{der:02x?}"
        );
    }

    #[test]
    fn sec08_only_keystones_two_parameter_sets_are_accepted() {
        // Covers: SEC-08, FR-04 AC1
        check_encryption_parameters(&file(pbkdf2(16, &[sha256_prf()]), aes(16))).unwrap();
        check_encryption_parameters(&file(scrypt(16, &[0x40, 0x00], &[]), aes(16))).unwrap();

        unsupported(
            &file(pbkdf2(8, &[sha256_prf()]), aes(16)),
            "salt is 8 bytes",
        );
        unsupported(&file(scrypt(32, &[0x40, 0x00], &[]), aes(16)), "salt is 32");
        unsupported(&file(pbkdf2(16, &[sha256_prf()]), aes(8)), "IV is 8 bytes");
        let key_length = tlv(TAG_INTEGER, &[32]);
        unsupported(
            &file(pbkdf2(16, &[key_length.clone(), sha256_prf()]), aes(16)),
            "key length",
        );
        unsupported(
            &file(scrypt(16, &[0x40, 0x00], &[key_length]), aes(16)),
            "key length",
        );
        unsupported(&file(pbkdf2(16, &[]), aes(16)), "HMAC-SHA1");
        // scrypt N = 2^20 (1 GiB of memory per attempt).
        unsupported(
            &file(scrypt(16, &[0x10, 0x00, 0x00], &[]), aes(16)),
            "N = 1048576",
        );
        unsupported(
            &file(scrypt(16, &[0x01, 0, 0, 0, 0, 0, 0, 0, 0], &[]), aes(16)),
            "out of range",
        );
        let pkcs12_3des = ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.3");
        let not_pbes2 = seq(&[
            seq(&[oid(&pkcs12_3des), seq(&[])]),
            tlv(TAG_OCTET_STRING, &[0; 16]),
        ]);
        unsupported(&not_pbes2, "not PBES2");
        let other_kdf = seq(&[
            oid(&OID_HMAC_WITH_SHA256),
            seq(&[tlv(TAG_OCTET_STRING, &[1; 16])]),
        ]);
        unsupported(&file(other_kdf, aes(16)), "neither scrypt nor PBKDF2");
    }

    #[test]
    fn sec08_encryption_parameters_must_be_strict_der() {
        // Covers: SEC-08
        let good = file(pbkdf2(16, &[sha256_prf()]), aes(16));
        // The file is 128 to 255 bytes long: header 0x30 0x81 <len>.
        assert_eq!(good[1], 0x81);
        let content = &good[3..];
        let with_header = |header: &[u8]| [header, content].concat();
        // Indefinite length, a length with a leading zero byte, and one past the end.
        malformed_der(&with_header(&[TAG_SEQUENCE, 0x80]));
        malformed_der(&with_header(&[TAG_SEQUENCE, 0x82, 0x00, good[2]]));
        malformed_der(&with_header(&[TAG_SEQUENCE, 0x81, good[2] + 1]));
        // A short length written in long form, and more than four length bytes.
        malformed_der(&[TAG_SEQUENCE, 0x81, 0x03, TAG_NULL, 0x01, 0x00]);
        malformed_der(&[TAG_SEQUENCE, 0x85, 1, 2, 3, 4, 5]);
        malformed_der(&[]);
        // Negative and non-minimal integers.
        let iterations = |value: &[u8]| {
            seq(&[
                oid(&OID_PBKDF2),
                seq(&[
                    tlv(TAG_OCTET_STRING, &[1; 16]),
                    tlv(TAG_INTEGER, value),
                    sha256_prf(),
                ]),
            ])
        };
        malformed_der(&file(iterations(&[0x80]), aes(16)));
        malformed_der(&file(iterations(&[0x00, 0x09, 0x27, 0xc0]), aes(16)));
        malformed_der(&file(iterations(&[]), aes(16)));
        // A positive integer with its required leading zero is fine.
        assert_eq!(small_uint(&[0x00, 0x80], "test").unwrap(), 0x80);
        // PRF parameters other than an empty NULL.
        let bad_prf = seq(&[oid(&OID_HMAC_WITH_SHA256), tlv(TAG_NULL, &[0])]);
        malformed_der(&file(pbkdf2(16, &[bad_prf]), aes(16)));
        let prf_extra = seq(&[
            oid(&OID_HMAC_WITH_SHA256),
            tlv(TAG_NULL, &[]),
            tlv(TAG_NULL, &[]),
        ]);
        malformed_der(&file(pbkdf2(16, &[prf_extra]), aes(16)));
        let trailing = pbkdf2(16, &[sha256_prf(), tlv(TAG_NULL, &[])]);
        malformed_der(&file(trailing, aes(16)));
    }

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
