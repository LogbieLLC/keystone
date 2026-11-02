//! OpenSSL's secure heap: locked, no-dump memory for private keys (SEC-07).
//!
//! RSA private numbers live inside OpenSSL, not in Keystone's own secret buffers.
//! OpenSSL allocates them with `BN_secure_new`, which uses its secure heap once that
//! heap exists. [`init`] creates the heap: 1 MiB locked into RAM (never swapped),
//! excluded from core dumps and guarded by inaccessible pages; every block is
//! cleared when freed.
//!
//! [`init`] is idempotent and is called by every path that creates a private key or
//! draws random numbers (`generate_rsa`, `pkcs8::decrypt_key_pem`, `rand::fill`), so
//! no key can exist outside the heap. The GUI's `main` should still call it once at
//! startup, right after `hardening::harden_at_startup`, before any thread starts:
//! OpenSSL's initialisation of the heap is not synchronised with other threads that
//! are already using OpenSSL, and a memory-lock limit that is too small is then
//! reported before the operator starts any work.
//!
//! If the heap cannot be locked (`RLIMIT_MEMLOCK` too small), [`init`] fails with
//! [`CryptoError::SecureHeapUnavailable`] and so does every private-key operation;
//! Keystone never continues with keys in ordinary memory. Ubuntu's default limit of
//! 8 MiB is enough for the heap together with the passphrase and PIN buffers
//! (`crypto::secret`).
#![forbid(unsafe_code)]

use super::CryptoError;
use super::ffi;

/// Size of the secure heap in bytes (1 MiB).
pub const SECURE_HEAP_BYTES: usize = ffi::SECURE_HEAP_BYTES;

/// Creates OpenSSL's secure heap, locked into RAM, once per process. Later calls
/// return the result of the first one.
pub fn init() -> Result<(), CryptoError> {
    ffi::init_secure_heap()
}

/// The state of OpenSSL's secure heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureHeapStatus {
    /// The heap exists (OpenSSL's `CRYPTO_secure_malloc_initialized`).
    pub initialized: bool,
    /// Bytes currently allocated from it (`CRYPTO_secure_used`), process-wide.
    pub used_bytes: usize,
}

/// Reads the state of the secure heap.
pub fn status() -> SecureHeapStatus {
    let (initialized, used_bytes) = ffi::secure_heap_usage();
    SecureHeapStatus {
        initialized,
        used_bytes,
    }
}
