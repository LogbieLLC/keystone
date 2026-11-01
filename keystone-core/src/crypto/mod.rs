//! The single audited crypto module (SEC-18, SECP-06).
//!
//! Every OpenSSL call in Keystone is in this module or its submodules. The
//! submodule `ffi` is the only place in the whole workspace where `unsafe` code is
//! allowed. This file holds only module declarations and re-exports, so that the
//! `#![forbid(unsafe_code)]` at the top of every other file stays meaningful.
//! `scripts/check-boundaries.sh` enforces this in CI.
//!
//! The operator reviews this whole directory before each release (PRD SEC-18).

mod error;
#[allow(unsafe_code)]
mod ffi;
pub mod hash;
pub mod rand;

pub use error::CryptoError;
