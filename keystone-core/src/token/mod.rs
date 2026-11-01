//! The `TokenSigner` trait, YubiKey hardening rules and PIV attestation verification (FR-05, FR-06, FR-07, FR-08, NFR-08).
#![forbid(unsafe_code)]

/// Errors from this module.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// Placeholder until the module is implemented.
    #[error("not implemented yet")]
    NotImplemented,
}
