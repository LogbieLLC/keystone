//! Synthetic test keys (TESTING.md TEST-11).
//!
//! Every key is generated at runtime through Keystone's own crypto API the first
//! time a test asks for it, and cached for the rest of the test process
//! (`OnceLock`). No key is ever committed or written to disk. RSA 8,192-bit
//! generation takes tens of seconds, so tests reuse these keys; only the dedicated
//! FR-02 AC1 test generates a fresh master-size key.
//!
//! Key numbering keeps unrelated tests from sharing a key by accident:
//! - `master(0)`, `master(1)`: RSA 8,192 (two independent hierarchies, FR-13 AC5).
//! - `rsa4096(0..RSA4096_COUNT)`: software main/sub-intermediate keys.
//! - `simulator_pool(0..SIMULATOR_POOL_COUNT)`: used only by `SimulatedYubiKey`
//!   for on-device key generation, so a token key never equals a software key.
//! - `rsa2048(0..RSA2048_COUNT)`: test leaves and the simulator's attestation
//!   hierarchy.
#![forbid(unsafe_code)]

use std::sync::OnceLock;

use keystone_core::crypto::{CancelFlag, RsaPrivateKey, generate_rsa};

/// Number of cached RSA 8,192-bit keys.
pub const MASTER_COUNT: usize = 2;
/// Number of cached RSA 4,096-bit software keys.
pub const RSA4096_COUNT: usize = 6;
/// Number of cached RSA 4,096-bit keys reserved for the simulator.
pub const SIMULATOR_POOL_COUNT: usize = 4;
/// Number of cached RSA 2,048-bit keys.
pub const RSA2048_COUNT: usize = 8;

static MASTER: [OnceLock<RsaPrivateKey>; MASTER_COUNT] = [const { OnceLock::new() }; MASTER_COUNT];
static RSA4096: [OnceLock<RsaPrivateKey>; RSA4096_COUNT] =
    [const { OnceLock::new() }; RSA4096_COUNT];
static SIMULATOR: [OnceLock<RsaPrivateKey>; SIMULATOR_POOL_COUNT] =
    [const { OnceLock::new() }; SIMULATOR_POOL_COUNT];
static RSA2048: [OnceLock<RsaPrivateKey>; RSA2048_COUNT] =
    [const { OnceLock::new() }; RSA2048_COUNT];

/// Generates a fresh synthetic key (not cached). Panics on failure: a test cannot
/// continue without its key.
pub fn generate_uncached(bits: u32) -> RsaPrivateKey {
    generate_rsa(bits, &CancelFlag::new(), &|_| {}).expect("test key generation")
}

fn cached(
    cells: &'static [OnceLock<RsaPrivateKey>],
    index: usize,
    bits: u32,
) -> &'static RsaPrivateKey {
    let cell = cells
        .get(index)
        .unwrap_or_else(|| panic!("test key index {index} out of range for {bits}-bit keys"));
    cell.get_or_init(|| generate_uncached(bits))
}

/// Cached RSA 8,192-bit master key number `index` (< [`MASTER_COUNT`]).
pub fn master(index: usize) -> &'static RsaPrivateKey {
    cached(&MASTER, index, 8192)
}

/// Cached RSA 4,096-bit software key number `index` (< [`RSA4096_COUNT`]).
pub fn rsa4096(index: usize) -> &'static RsaPrivateKey {
    cached(&RSA4096, index, 4096)
}

/// Cached RSA 4,096-bit key reserved for the simulator's on-device keygen.
pub fn simulator_pool(index: usize) -> &'static RsaPrivateKey {
    cached(&SIMULATOR, index, 4096)
}

/// Cached RSA 2,048-bit key number `index` (< [`RSA2048_COUNT`]).
pub fn rsa2048(index: usize) -> &'static RsaPrivateKey {
    cached(&RSA2048, index, 2048)
}

/// Starts generating the listed master and 4,096-bit keys on background threads so
/// that tests waiting for them later find them ready. Optional; only saves time.
pub fn warm_up(masters: &[usize], rsa4096_indices: &[usize]) {
    for &index in masters {
        std::thread::spawn(move || {
            let _ = master(index);
        });
    }
    for &index in rsa4096_indices {
        std::thread::spawn(move || {
            let _ = rsa4096(index);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_keys_are_stable_and_distinct() {
        let first = rsa2048(0);
        assert!(std::ptr::eq(first, rsa2048(0)));
        assert_eq!(first.bits(), 2048);
        let other = rsa2048(1);
        assert_ne!(
            first.public_key_spki_der().unwrap(),
            other.public_key_spki_der().unwrap()
        );
    }
}
