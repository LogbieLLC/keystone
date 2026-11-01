//! Production hardening: network refusal, seccomp socket filter, binary self-check, core dumps (FR-01, SEC-03, SEC-07, SEC-19).
#![forbid(unsafe_code)]

/// Errors from this module.
#[derive(Debug, thiserror::Error)]
pub enum HardeningError {
    /// Placeholder until the module is implemented.
    #[error("not implemented yet")]
    NotImplemented,
}
