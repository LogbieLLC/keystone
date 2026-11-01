//! Strict size limits for every file Keystone reads (SEC-08).
//!
//! Every parser checks the input length against one of these limits *before*
//! parsing, so a malformed or hostile file on a USB drive cannot exhaust memory.
#![forbid(unsafe_code)]

/// Largest PEM file accepted (certificate, chain or encrypted PKCS#8 key).
pub const MAX_PEM_BYTES: usize = 64 * 1024;
/// Largest single DER certificate accepted.
pub const MAX_CERT_DER_BYTES: usize = 16 * 1024;
/// Largest CRL accepted (DER or PEM).
pub const MAX_CRL_BYTES: usize = 4 * 1024 * 1024;
/// Largest audit log file accepted.
pub const MAX_AUDIT_LOG_BYTES: usize = 64 * 1024 * 1024;
/// Largest single audit-log line.
pub const MAX_AUDIT_ENTRY_BYTES: usize = 64 * 1024;
/// Largest single operation-journal file.
pub const MAX_JOURNAL_ENTRY_BYTES: usize = 1024 * 1024;
/// Largest issuance record file.
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
/// Largest small metadata file (drive identity, binary hash record, settings).
pub const MAX_METADATA_BYTES: usize = 64 * 1024;
/// Largest output file of an operation that is hashed and copied between drives.
pub const MAX_OUTPUT_FILE_BYTES: usize = 16 * 1024 * 1024;
