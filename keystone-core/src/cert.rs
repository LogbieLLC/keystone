//! Certificate building, signing and parsing (FR-02, FR-07, FR-08, FR-10, FR-21).
#![forbid(unsafe_code)]

/// Errors from this module.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// Placeholder until the module is implemented.
    #[error("not implemented yet")]
    NotImplemented,
}
