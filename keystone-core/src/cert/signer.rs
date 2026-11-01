//! The signing abstraction for certificates and CRLs.
//!
//! The master signs with a software key ([`SoftwareSigner`]); the main
//! intermediate signs on the YubiKey (`crate::token::TokenCaSigner`, PIN + touch).
//! Both produce sha384WithRSAEncryption (PKCS#1 v1.5) signatures, and every
//! signature is verified independently with OpenSSL before a certificate or CRL is
//! returned (Dependencies doc, YubiKey item 3).
#![forbid(unsafe_code)]

use crate::crypto::{CryptoError, RsaPrivateKey};
use crate::token::TokenError;

/// A failure while signing.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The software key failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The token failed (wrong PIN, removed, touch timeout, ...).
    #[error(transparent)]
    Token(#[from] TokenError),
}

/// Anything that signs with sha384WithRSAEncryption.
///
/// Object-safe; signing takes `&mut self` because a token needs exclusive access.
pub trait Sha384Signer {
    /// The signing key's public key as DER `SubjectPublicKeyInfo`.
    fn signer_public_key_der(&mut self) -> Result<Vec<u8>, SignError>;

    /// Signs `message` (SHA-384, RSA PKCS#1 v1.5).
    fn sign_sha384(&mut self, message: &[u8]) -> Result<Vec<u8>, SignError>;
}

/// Signs with a software RSA key (the master; also used in tests).
#[derive(Debug)]
pub struct SoftwareSigner<'a> {
    key: &'a RsaPrivateKey,
}

impl<'a> SoftwareSigner<'a> {
    /// Wraps `key` for signing.
    pub fn new(key: &'a RsaPrivateKey) -> Self {
        SoftwareSigner { key }
    }
}

impl Sha384Signer for SoftwareSigner<'_> {
    fn signer_public_key_der(&mut self) -> Result<Vec<u8>, SignError> {
        Ok(self.key.public_key_spki_der()?)
    }

    fn sign_sha384(&mut self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(self.key.sign_sha384_pkcs1(message)?)
    }
}
