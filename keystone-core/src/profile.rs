//! The fixed certificate profile and operator-editable fields (PRD section 5, FR-02, FR-07, FR-08, FR-10, FR-18, FR-21).
#![forbid(unsafe_code)]

/// Errors from this module.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    /// Placeholder until the module is implemented.
    #[error("not implemented yet")]
    NotImplemented,
}
