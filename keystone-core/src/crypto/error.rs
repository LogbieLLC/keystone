//! Errors from the crypto module.
#![forbid(unsafe_code)]

/// A failure inside the crypto module.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// OpenSSL reported an error. The text never contains secret material.
    #[error("OpenSSL operation failed: {0}")]
    OpenSsl(String),
    /// The secure random source failed.
    #[error("the operating system's secure random source failed")]
    Random,
    /// Memory for a secret could not be allocated and locked into RAM (SEC-07).
    #[error("could not lock memory for a secret; raise the memory-lock limit (RLIMIT_MEMLOCK)")]
    LockedMemory,
    /// A secret buffer would have to grow beyond its fixed capacity.
    #[error("secret is longer than its fixed buffer allows")]
    SecretCapacity,
}

impl From<openssl::error::ErrorStack> for CryptoError {
    fn from(stack: openssl::error::ErrorStack) -> Self {
        CryptoError::OpenSsl(stack.to_string())
    }
}
