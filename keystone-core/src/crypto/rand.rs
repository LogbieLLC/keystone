//! Secure randomness from OpenSSL's DRBG, seeded by the operating system
//! (FR-03 AC1, FR-10 AC2).
#![forbid(unsafe_code)]

use super::CryptoError;
use crate::model::{SERIAL_LEN, Serial};

/// Fills `buffer` with secure random bytes.
///
/// OpenSSL's random generator keeps its seed material in the secure heap, so the
/// heap is set up first (`crypto::secure_heap`, SEC-07).
pub fn fill(buffer: &mut [u8]) -> Result<(), CryptoError> {
    super::secure_heap::init()?;
    openssl::rand::rand_priv_bytes(buffer).map_err(|_| CryptoError::Random)
}

/// A uniformly random integer in `0..bound` (rejection sampling, no modulo bias).
pub fn uniform_below(bound: u32) -> Result<u32, CryptoError> {
    assert!(bound > 0, "bound must be positive");
    // Largest multiple of `bound` that fits in u32 range: values at or above it are rejected.
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let mut bytes = [0u8; 4];
        fill(&mut bytes)?;
        let value = u32::from_be_bytes(bytes);
        if value < zone {
            return Ok(value % bound);
        }
    }
}

/// A new random serial number: 159 random bits, positive, non-zero (FR-10 AC2).
///
/// Uniqueness against every known history is checked by the caller before signing.
pub fn random_serial() -> Result<Serial, CryptoError> {
    loop {
        let mut bytes = [0u8; SERIAL_LEN];
        fill(&mut bytes)?;
        bytes[0] &= 0x7f;
        if let Some(serial) = Serial::from_bytes(bytes) {
            return Ok(serial);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr10_ac2_random_serials_are_positive_and_distinct() {
        // Covers: FR-10 AC2
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let serial = random_serial().expect("random");
            assert_eq!(serial.as_bytes()[0] & 0x80, 0);
            assert!(seen.insert(serial));
        }
    }

    #[test]
    fn uniform_below_stays_in_range() {
        for _ in 0..1000 {
            assert!(uniform_below(7776).expect("random") < 7776);
        }
        assert_eq!(uniform_below(1).expect("random"), 0);
    }
}
