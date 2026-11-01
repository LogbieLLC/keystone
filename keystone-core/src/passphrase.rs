//! Passphrase generation and confirmation (FR-03, SEC-05, SEC-17). Owned by the crypto/certificate work.
#![forbid(unsafe_code)]

/// Errors from this module.
#[derive(Debug, thiserror::Error)]
pub enum PassphraseError {
    /// Placeholder until the module is implemented.
    #[error("not implemented yet")]
    NotImplemented,
}
