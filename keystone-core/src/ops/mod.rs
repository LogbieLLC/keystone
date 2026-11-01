//! Operations for Flows A to E: journaled, cancellable, recoverable (FR-15, FR-16, FR-22).
#![forbid(unsafe_code)]

/// Errors from this module.
#[derive(Debug, thiserror::Error)]
pub enum OpsError {
    /// Placeholder until the module is implemented.
    #[error("not implemented yet")]
    NotImplemented,
}
