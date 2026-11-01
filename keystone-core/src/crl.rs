//! CRL building and refresh (FR-13).
#![forbid(unsafe_code)]

/// Errors from this module.
#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    /// Placeholder until the module is implemented.
    #[error("not implemented yet")]
    NotImplemented,
}
