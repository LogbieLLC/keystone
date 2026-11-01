//! Interoperability tests (TESTING.md section 1): Keystone's outputs checked by the
//! Ubuntu OpenSSL command line and by Go's crypto/x509, as separate processes.
//!
//! - `pkcs8_cli`: `openssl pkey` decrypts both key files; `openssl asn1parse`
//!   shows the exact PBES2 parameters (FR-04 AC1, AC2).
//! - `chain_cli`: `openssl verify -CAfile master.crt -untrusted main.crt sub.crt`
//!   (FR-09 AC2).
//! - `crl_cli`: `openssl verify -crl_check_all` with local CRL files rejects a
//!   revoked sub-intermediate at depth 1 and a revoked main intermediate at depth 2
//!   (FR-13 AC5, local part).
//! - `name_constraints`: leaves inside and outside the permitted names, checked by
//!   `openssl verify` and by Go (FR-21 AC5).
//! - `output_scan`: no written file holds a plaintext private key (SEC-04).
//! - `blocked`: the StarnetAuth-dependent tests, reported as BLOCKED (TEST-10).
//!
//! Every file is written to a `tempfile` directory (TEST-12). The tests fail, never
//! skip, when `openssl` or `go` is missing (TEST-07).
#![forbid(unsafe_code)]

mod blocked;
mod chain_cli;
mod crl_cli;
mod name_constraints;
mod output_scan;
mod pkcs8_cli;
mod support;
