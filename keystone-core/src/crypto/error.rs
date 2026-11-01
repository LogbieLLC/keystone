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
}

impl From<openssl::error::ErrorStack> for CryptoError {
    fn from(stack: openssl::error::ErrorStack) -> Self {
        CryptoError::OpenSsl(stack.to_string())
    }
}
