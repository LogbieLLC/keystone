//! Signing certificates and CRLs with the main intermediate's key on the token
//! (FR-08 AC2, FR-13 AC1).
#![forbid(unsafe_code)]

use std::fmt;

use super::{SIGNING_SLOT, TokenError, TokenSigner};
use crate::cert::{Sha384Signer, SignError};
use crate::crypto::hash::sha384;
use crate::crypto::secret::SecretString;

/// A [`Sha384Signer`] over the token's slot 9C key. Each signature needs the PIN and
/// a touch (PIN and touch policy "always").
pub struct TokenCaSigner<'a> {
    token: &'a mut dyn TokenSigner,
    pin: &'a SecretString,
}

impl<'a> TokenCaSigner<'a> {
    /// Signs with `token`, presenting `pin` for every signature.
    pub fn new(token: &'a mut dyn TokenSigner, pin: &'a SecretString) -> Self {
        TokenCaSigner { token, pin }
    }
}

impl fmt::Debug for TokenCaSigner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenCaSigner([PIN REDACTED])")
    }
}

impl Sha384Signer for TokenCaSigner<'_> {
    fn signer_public_key_der(&mut self) -> Result<Vec<u8>, SignError> {
        let status = self.token.slot_status(SIGNING_SLOT)?;
        let key = status.key.ok_or(TokenError::SlotEmpty)?;
        Ok(key.public_key_der)
    }

    fn sign_sha384(&mut self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let digest = sha384(message);
        Ok(self.token.sign_sha384_digest(self.pin, &digest)?)
    }
}
