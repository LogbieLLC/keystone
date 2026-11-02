//! RSA keys: cancellable generation, SHA-384 PKCS#1 v1.5 signatures, public-key
//! inspection (FR-02 AC1, FR-07, FR-08, FR-16, NFR-03).
#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Public};
use openssl::rsa::Padding;
use openssl::sign::Verifier;

use super::CryptoError;
use super::ffi;

/// The only public exponent Keystone generates or accepts (FR-02 AC1).
pub const RSA_PUBLIC_EXPONENT: u64 = 65_537;

/// Length of a SHA-384 digest.
pub const SHA384_LEN: usize = 48;

/// Smallest RSA key Keystone generates (test leaves and simulator attestation keys);
/// every CA key size is fixed by the profile (`crate::profile`).
pub const MIN_RSA_BITS: u32 = 2048;
/// Largest RSA key Keystone generates (the master, PRD section 5).
pub const MAX_RSA_BITS: u32 = 8192;

/// A cancel request shared between the GUI thread and a worker (FR-16).
///
/// Cloning shares the same flag.
#[derive(Debug, Clone, Default)]
pub struct CancelFlag(Arc<AtomicBool>);

impl CancelFlag {
    /// A new flag that is not cancelled.
    pub fn new() -> Self {
        CancelFlag::default()
    }

    /// Requests cancellation. Key generation stops at its next progress step.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// True once cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    pub(crate) fn as_atomic(&self) -> &AtomicBool {
        &self.0
    }
}

/// An RSA private key held by OpenSSL.
///
/// There is no `Clone`, `Display` or serialization, and `Debug` shows only the key
/// size, so the key cannot reach a log or file by accident (SEC-07). The only way to
/// write it out is encrypted PKCS#8 (`crypto::pkcs8`).
///
/// The OpenSSL key object is owned by the FFI module and reachable only from inside
/// `crypto` (its accessor `handle` is `pub(super)`), so no other module can
/// call an OpenSSL function on it (SEC-04, SEC-18).
pub struct RsaPrivateKey {
    key: ffi::PrivateKey,
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RsaPrivateKey({} bits, [REDACTED])", self.bits())
    }
}

/// Generates an RSA key of `bits` bits with public exponent 65537 using OpenSSL 3
/// (FR-02 AC1, FR-07 AC1, FR-08 AC1).
///
/// `progress` is called from the generating thread with an increasing step count
/// (OpenSSL's prime-search callbacks); it must be quick and must not block.
/// `cancel` stops generation at the next step and returns
/// [`CryptoError::Cancelled`] with nothing produced (FR-16 AC2).
pub fn generate_rsa(
    bits: u32,
    cancel: &CancelFlag,
    progress: &(dyn Fn(u64) + Sync),
) -> Result<RsaPrivateKey, CryptoError> {
    if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) || !bits.is_multiple_of(1024) {
        return Err(CryptoError::UnsupportedKeySize { bits });
    }
    let key = RsaPrivateKey {
        key: ffi::generate_rsa_key(bits, cancel.as_atomic(), progress)?,
    };
    key.check_rsa(Some(bits))?;
    Ok(key)
}

impl RsaPrivateKey {
    /// Wraps a key decrypted by `crypto::pkcs8`; anything but RSA is refused.
    pub(super) fn from_handle(key: ffi::PrivateKey) -> Result<Self, CryptoError> {
        let key = RsaPrivateKey { key };
        key.check_rsa(None)?;
        Ok(key)
    }

    /// The OpenSSL key, for `crypto::pkcs8` only. Deliberately `pub(super)`: an
    /// accessor visible to the whole crate would let any module call OpenSSL on the
    /// private key without writing `openssl::`, past the boundary check (SEC-18).
    pub(super) fn handle(&self) -> &ffi::PrivateKey {
        &self.key
    }

    fn check_rsa(&self, expected_bits: Option<u32>) -> Result<(), CryptoError> {
        if !self.key.is_rsa() {
            return Err(CryptoError::UnsupportedKey("not an RSA key".into()));
        }
        if let Some(bits) = expected_bits
            && self.bits() != bits
        {
            return Err(CryptoError::UnsupportedKey(format!(
                "generated {} bits instead of {bits}",
                self.bits()
            )));
        }
        Ok(())
    }

    /// Modulus size in bits.
    pub fn bits(&self) -> u32 {
        self.key.bits()
    }

    /// The public exponent.
    pub fn public_exponent(&self) -> Result<u64, CryptoError> {
        inspect_rsa_spki(&self.public_key_spki_der()?).map(|info| info.public_exponent)
    }

    /// The public key as DER `SubjectPublicKeyInfo`.
    pub fn public_key_spki_der(&self) -> Result<Vec<u8>, CryptoError> {
        self.key.public_key_der()
    }

    /// Signs `message` with SHA-384 and RSA PKCS#1 v1.5 (sha384WithRSAEncryption).
    ///
    /// PKCS#1 v1.5 is deterministic, so this equals signing the SHA-384 digest of
    /// `message` with [`RsaPrivateKey::sign_sha384_digest`].
    pub fn sign_sha384_pkcs1(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.key.sign_sha384_digest(&super::hash::sha384(message))
    }

    /// Signs a precomputed SHA-384 digest with RSA PKCS#1 v1.5 (the DigestInfo for
    /// SHA-384 is added by OpenSSL). Used where only the digest crosses a boundary,
    /// as with a token.
    pub fn sign_sha384_digest(&self, digest: &[u8; SHA384_LEN]) -> Result<Vec<u8>, CryptoError> {
        self.key.sign_sha384_digest(digest)
    }
}

/// Facts about an RSA public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPublicKeyInfo {
    /// Modulus size in bits.
    pub bits: u32,
    /// Public exponent.
    pub public_exponent: u64,
}

fn public_key_from_spki(spki_der: &[u8]) -> Result<PKey<Public>, CryptoError> {
    if spki_der.len() > crate::limits::MAX_CERT_DER_BYTES {
        return Err(CryptoError::InputTooLarge {
            what: "public key",
            limit: crate::limits::MAX_CERT_DER_BYTES,
            actual: spki_der.len(),
        });
    }
    let key = PKey::public_key_from_der(spki_der)
        .map_err(|e| CryptoError::Der(format!("public key: {e}")))?;
    if key.id() != Id::RSA {
        return Err(CryptoError::UnsupportedKey("not an RSA public key".into()));
    }
    Ok(key)
}

/// Reads the size and exponent of an RSA `SubjectPublicKeyInfo`.
pub fn inspect_rsa_spki(spki_der: &[u8]) -> Result<RsaPublicKeyInfo, CryptoError> {
    let key = public_key_from_spki(spki_der)?;
    let rsa = key.rsa()?;
    let exponent_bytes = rsa.e().to_vec();
    if exponent_bytes.is_empty() || exponent_bytes.len() > 8 {
        return Err(CryptoError::UnsupportedKey(
            "public exponent out of range".into(),
        ));
    }
    let public_exponent = exponent_bytes
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    Ok(RsaPublicKeyInfo {
        bits: key.bits(),
        public_exponent,
    })
}

/// Verifies a sha384WithRSAEncryption (PKCS#1 v1.5) signature over `message` with
/// the RSA key in `spki_der`. Returns an error unless the signature is valid.
pub fn verify_sha384_pkcs1(
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let key = public_key_from_spki(spki_der)?;
    let mut verifier = Verifier::new(MessageDigest::sha384(), &key)?;
    verifier.set_rsa_padding(Padding::PKCS1)?;
    verifier.update(message)?;
    match verifier.verify(signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(CryptoError::BadSignature(
            "the signature does not match the public key".into(),
        )),
        Err(_) => Err(CryptoError::BadSignature(
            "the signature is malformed or does not match the public key".into(),
        )),
    }
}
