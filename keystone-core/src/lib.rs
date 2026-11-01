//! Keystone core library.
//!
//! Every CA rule lives here so it can be tested without a display (PRD section 10).
//! The GUI crate is a thin layer over this crate.
//!
//! Code-safety boundaries (SEC-18, SECP-06):
//! - `unsafe` is denied crate-wide and every module file starts with
//!   `#![forbid(unsafe_code)]`, except the single reviewed FFI module `crypto::ffi`.
//! - Every OpenSSL call is inside the `crypto` module.
//! - `scripts/check-boundaries.sh` enforces both rules in CI.
#![deny(unsafe_code)]

pub mod build_info;
pub mod cert;
pub mod clock;
pub mod crl;
pub mod crypto;
pub mod error;
pub mod hardening;
pub mod limits;
pub mod model;
pub mod ops;
pub mod passphrase;
pub mod profile;
pub mod store;
pub mod token;

pub use error::{Error, Result};
