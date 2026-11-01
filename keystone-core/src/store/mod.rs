//! CA drives: atomic multi-drive writes, issuance record, audit log, operation journal, drive comparison (FR-11, FR-12, FR-14, FR-19, FR-22, SEC-08, SEC-09, SEC-11, SEC-20).
#![forbid(unsafe_code)]

/// Errors from this module.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Placeholder until the module is implemented.
    #[error("not implemented yet")]
    NotImplemented,
}
