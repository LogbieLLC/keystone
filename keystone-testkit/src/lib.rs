//! Keystone test support (TESTING.md TEST-11, TEST-12; PRD NFR-08).
//!
//! - Test keys come only from this crate (TEST-11).
//! - Test files are written only to temporary directories (TEST-12).
//! - Every test certificate's Common Name contains `KEYSTONE TEST` (TEST-11).
//! - The software YubiKey simulator implements the same `TokenSigner` trait as the
//!   real driver (NFR-08).
//!
//! This crate is never part of a production build.
#![forbid(unsafe_code)]

/// Marker that every test certificate's Common Name must contain (TEST-11).
pub const TEST_CN_MARKER: &str = "KEYSTONE TEST";

mod drives;

pub use drives::{
    PLAINTEXT_KEY_TYPES, TestDrives, find_plaintext_private_keys, plaintext_key_markers,
};

mod clock;

pub use clock::TestClock;
