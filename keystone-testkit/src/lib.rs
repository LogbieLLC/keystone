//! Keystone test support (TESTING.md TEST-11, TEST-12; PRD NFR-08).
//!
//! - Test keys come only from this crate (TEST-11): [`keys`].
//! - Test files are written only to temporary directories (TEST-12).
//! - Every test certificate's Common Name contains `KEYSTONE TEST` (TEST-11):
//!   [`names`], [`x509`].
//! - The software YubiKey simulator implements the same `TokenSigner` trait as the
//!   real driver (NFR-08): [`simulator::SimulatedYubiKey`].
//! - Test-only certificates that keystone-core must not be able to make (leaves,
//!   attestation certificates, an issuing system's leaf CRL): [`x509`].
//! - A whole hierarchy built through the core API: [`hierarchy`].
//!
//! This crate is never part of a production build.
#![forbid(unsafe_code)]

pub mod hierarchy;
pub mod keys;
pub mod names;
pub mod simulator;
pub mod x509;

pub use simulator::{SimController, SimulatedYubiKey, SimulatorConfig};

/// Marker that every test certificate's Common Name must contain (TEST-11).
pub const TEST_CN_MARKER: &str = "KEYSTONE TEST";
