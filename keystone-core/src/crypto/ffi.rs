//! The single reviewed FFI module (SEC-18). The only file in the workspace where
//! `unsafe` code is allowed. Every unsafe block carries a `// SAFETY:` comment, and
//! `scripts/check-boundaries.sh` fails CI if one is missing.
//!
//! Contents:
//! - `LockedRegion`: page-aligned memory that is locked into RAM (never swapped),
//!   excluded from core dumps, and wiped before it is freed (SEC-07).
//! - `init_secure_heap`: OpenSSL's secure heap, so that the private numbers of every
//!   RSA key live in locked, no-dump memory too (SEC-07).
//! - `PrivateKey`: the only owner of a private key (`EVP_PKEY`) in Keystone. The
//!   key never leaves this module as an OpenSSL object, as DER or as PEM; callers
//!   can only sign with it, read its public key, or encrypt it (SEC-04, SEC-07).
//! - `generate_rsa_key`: cancellable RSA key generation with a progress callback
//!   (FR-02 AC1, FR-16, NFR-03).
//! - `encrypt_pkcs8_der` / `decrypt_pkcs8_der`: encrypted PKCS#8 with explicit PBES2
//!   parameters (FR-04 AC1, SEC-04). The passphrase is passed to OpenSSL as a
//!   pointer into its locked buffer with an explicit length; no C-string copy is
//!   made (SEC-07).
//! - `verify_chain`: `X509_verify_cert` with in-memory trusted roots, untrusted
//!   intermediates, CRLs and an explicit verification time.
//!
//! Rules for this file:
//! - Every raw OpenSSL object is owned by a small RAII guard, so it is freed on
//!   every path, including early returns.
//! - Nothing here panics across the FFI boundary: the keygen callback catches
//!   unwinding and turns it into "abort".
//! - A private key is generated, or decoded from its decrypted `PrivateKeyInfo`,
//!   directly into an `EVP_PKEY` owned by `PrivateKey`, with its private numbers in
//!   OpenSSL's secure heap. Decryption does not use `EVP_PKCS82PKEY`, because
//!   OpenSSL 3's decoder behind it leaves an unwiped plaintext copy of the key in
//!   freed heap memory (see `rsa_key_from_pkcs8_info`). The plaintext buffers of
//!   `PKCS8_decrypt` and `PKCS8_PRIV_KEY_INFO` are wiped by OpenSSL; this module
//!   never holds plaintext key bytes in a buffer of its own.
//! - Residual risk, encryption: for a generated (provider) key, `EVP_PKEY2PKCS8`
//!   encodes through OpenSSL 3's encoder, which frees two plaintext DER buffers of
//!   the key without wiping them (`ASN1_item_i2d_bio` and the memory BIO of
//!   `OSSL_ENCODER_to_data`, in 3.0.13 and 3.5.4). The next allocations of the same
//!   size inside the same encryption (`PKCS8_set0_pbe`, which wipes its buffers)
//!   reuse those blocks; `tests/key_residue.rs` checks after every master and
//!   sub-intermediate encryption that no copy is left outside the secure heap.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{self, NonNull};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use openssl_sys as sys;
use zeroize::Zeroize;

use super::CryptoError;

/// Opaque `X509_SIG` (an `EncryptedPrivateKeyInfo`); not declared by openssl-sys.
#[allow(non_camel_case_types)]
#[repr(C)]
struct X509_SIG {
    _opaque: [u8; 0],
}

/// `EVP_PKEY_gen_cb` from `<openssl/evp.h>`.
type EvpPkeyGenCb = unsafe extern "C" fn(ctx: *mut sys::EVP_PKEY_CTX) -> c_int;

// SAFETY: these declarations are missing from openssl-sys 0.9.117. Each signature was
// checked against the OpenSSL 3 headers (evp.h, x509.h, pkcs12.h, x509_vfy.h); libcrypto
// is linked by openssl-sys. `time_t` is `long` on the only target (x86_64 Linux).
unsafe extern "C" {
    fn EVP_PKEY_CTX_set_cb(ctx: *mut sys::EVP_PKEY_CTX, cb: Option<EvpPkeyGenCb>);
    fn EVP_PKEY_CTX_set_app_data(ctx: *mut sys::EVP_PKEY_CTX, data: *mut c_void);
    fn EVP_PKEY_CTX_get_app_data(ctx: *mut sys::EVP_PKEY_CTX) -> *mut c_void;
    fn PKCS5_pbe2_set_iv(
        cipher: *const sys::EVP_CIPHER,
        iter: c_int,
        salt: *mut u8,
        saltlen: c_int,
        aiv: *mut u8,
        prf_nid: c_int,
    ) -> *mut sys::X509_ALGOR;
    fn PKCS5_pbe2_set_scrypt(
        cipher: *const sys::EVP_CIPHER,
        salt: *const u8,
        saltlen: c_int,
        aiv: *mut u8,
        n: u64,
        r: u64,
        p: u64,
    ) -> *mut sys::X509_ALGOR;
    fn PKCS8_set0_pbe(
        pass: *const c_char,
        passlen: c_int,
        p8inf: *mut sys::PKCS8_PRIV_KEY_INFO,
        pbe: *mut sys::X509_ALGOR,
    ) -> *mut X509_SIG;
    fn X509_SIG_free(sig: *mut X509_SIG);
    fn i2d_X509_SIG(sig: *const X509_SIG, out: *mut *mut u8) -> c_int;
    fn d2i_X509_SIG(sig: *mut *mut X509_SIG, input: *mut *const u8, len: c_long) -> *mut X509_SIG;
    fn PKCS8_decrypt(
        p8: *const X509_SIG,
        pass: *const c_char,
        passlen: c_int,
    ) -> *mut sys::PKCS8_PRIV_KEY_INFO;
    fn PKCS8_pkey_get0(
        ppkalg: *mut *const sys::ASN1_OBJECT,
        pk: *mut *const u8,
        ppklen: *mut c_int,
        pa: *mut *const sys::X509_ALGOR,
        p8: *const sys::PKCS8_PRIV_KEY_INFO,
    ) -> c_int;
    fn X509_STORE_add_crl(store: *mut sys::X509_STORE, crl: *mut sys::X509_CRL) -> c_int;
    fn X509_STORE_CTX_set_time(ctx: *mut sys::X509_STORE_CTX, flags: c_ulong, t: c_long);
    fn CRYPTO_secure_malloc_init(size: usize, minsize: usize) -> c_int;
    fn CRYPTO_secure_malloc_done() -> c_int;
    fn CRYPTO_secure_malloc_initialized() -> c_int;
    fn CRYPTO_secure_used() -> usize;
}

// ---------------------------------------------------------------------------
// OpenSSL's secure heap for private keys (SEC-07)
// ---------------------------------------------------------------------------

/// Size of OpenSSL's secure heap: 1 MiB. A power of two, as OpenSSL requires.
///
/// OpenSSL allocates the private numbers of every RSA key (d, p, q, dP, dQ, qInv;
/// `BN_secure_new`) and the temporaries of key generation and private-key operations
/// (`BN_CTX_secure_new`) from this heap once it exists. The pages are locked into RAM
/// (`mlock2`), excluded from core dumps (`MADV_DONTDUMP`), guarded by inaccessible
/// pages, and every block is cleared when freed. An RSA 8,192 key uses about 4 KiB of
/// it; 1 MiB leaves room for the master, a sub-intermediate and generation
/// temporaries, and together with the `LockedRegion`s of the passphrases and PINs
/// stays far below Ubuntu's default 8 MiB `RLIMIT_MEMLOCK`.
pub(crate) const SECURE_HEAP_BYTES: usize = 1 << 20;
/// Smallest block OpenSSL hands out from the secure heap (a power of two).
pub(crate) const SECURE_HEAP_MIN_ALLOCATION: usize = 32;

const _: () = assert!(
    SECURE_HEAP_BYTES.is_power_of_two()
        && SECURE_HEAP_MIN_ALLOCATION.is_power_of_two()
        && SECURE_HEAP_MIN_ALLOCATION < SECURE_HEAP_BYTES
);

/// Outcome of the one initialisation per process: `true` when the heap is locked.
static SECURE_HEAP_LOCKED: OnceLock<bool> = OnceLock::new();

/// Creates OpenSSL's secure heap once per process (later calls return the first
/// result). Fails unless the whole heap is locked into RAM and excluded from core
/// dumps: a heap that is merely allocated would look protected without being so,
/// so it is released again and every private-key operation then fails with
/// [`CryptoError::SecureHeapUnavailable`].
pub(crate) fn init_secure_heap() -> Result<(), CryptoError> {
    let locked = *SECURE_HEAP_LOCKED.get_or_init(|| {
        // SAFETY: plain query of a flag.
        if unsafe { CRYPTO_secure_malloc_initialized() } == 1 {
            // Already set up in this process by another copy of this module. That
            // happens only in keystone-core's own unit tests, which also link the
            // library build through keystone-testkit; nothing else in Keystone creates
            // the heap, and this function keeps a heap only when it is locked (below).
            return true;
        }
        // SAFETY: plain call with constant power-of-two arguments (checked above); the
        // `OnceLock` makes this the only initialisation by this copy of the module.
        let rc =
            unsafe { CRYPTO_secure_malloc_init(SECURE_HEAP_BYTES, SECURE_HEAP_MIN_ALLOCATION) };
        if rc == 2 {
            // 2 = the heap exists but mlock (RLIMIT_MEMLOCK), a guard page or
            // MADV_DONTDUMP failed. Release it so no key is ever placed there.
            // SAFETY: plain call; OpenSSL frees the heap only if nothing is allocated.
            unsafe { CRYPTO_secure_malloc_done() };
        }
        if rc != 1 {
            // SAFETY: clears this thread's error queue.
            unsafe { sys::ERR_clear_error() };
        }
        rc == 1
    });
    if locked {
        Ok(())
    } else {
        Err(CryptoError::SecureHeapUnavailable {
            bytes: SECURE_HEAP_BYTES,
        })
    }
}

/// Whether OpenSSL's secure heap exists, and how many bytes of it are in use.
pub(crate) fn secure_heap_usage() -> (bool, usize) {
    // SAFETY: plain query of a flag.
    let initialized = unsafe { CRYPTO_secure_malloc_initialized() } == 1;
    if !initialized {
        // OpenSSL 3.0's CRYPTO_secure_used takes the heap's lock without checking that
        // it exists, so it must not be called before the heap is set up.
        return (false, 0);
    }
    // SAFETY: the heap and its lock exist (checked above) and are never torn down after
    // a successful setup (`init_secure_heap` releases only a heap that failed).
    let used = unsafe { CRYPTO_secure_used() };
    (initialized, used)
}

/// Collects and clears OpenSSL's thread-local error queue.
fn openssl_error(context: &str) -> CryptoError {
    let stack = openssl::error::ErrorStack::get();
    CryptoError::OpenSsl(format!("{context}: {stack}"))
}

/// Defines an owning guard for one kind of OpenSSL object.
macro_rules! guard {
    ($name:ident, $ty:ty, $free:path) => {
        struct $name(*mut $ty);

        impl $name {
            #[allow(dead_code)]
            fn checked(ptr: *mut $ty, context: &str) -> Result<Self, CryptoError> {
                if ptr.is_null() {
                    Err(openssl_error(context))
                } else {
                    Ok($name(ptr))
                }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: the guard is the only owner of this live object and frees
                    // it exactly once with the matching OpenSSL free function.
                    unsafe { $free(self.0) };
                }
            }
        }
    };
}

guard!(PkeyCtxGuard, sys::EVP_PKEY_CTX, sys::EVP_PKEY_CTX_free);
guard!(PkeyGuard, sys::EVP_PKEY, sys::EVP_PKEY_free);
guard!(BignumGuard, sys::BIGNUM, sys::BN_free);
guard!(RsaGuard, sys::RSA, sys::RSA_free);
guard!(
    P8InfoGuard,
    sys::PKCS8_PRIV_KEY_INFO,
    sys::PKCS8_PRIV_KEY_INFO_free
);
guard!(AlgorGuard, sys::X509_ALGOR, sys::X509_ALGOR_free);
guard!(SigGuard, X509_SIG, X509_SIG_free);
guard!(X509Guard, sys::X509, sys::X509_free);
guard!(CrlGuard, sys::X509_CRL, sys::X509_CRL_free);
guard!(StoreGuard, sys::X509_STORE, sys::X509_STORE_free);
guard!(StoreCtxGuard, sys::X509_STORE_CTX, sys::X509_STORE_CTX_free);
guard!(StackGuard, sys::OPENSSL_STACK, sys::OPENSSL_sk_free);

fn c_len(len: usize, what: &'static str) -> Result<c_int, CryptoError> {
    c_int::try_from(len).map_err(|_| CryptoError::InputTooLarge {
        what,
        limit: c_int::MAX as usize,
        actual: len,
    })
}

// ---------------------------------------------------------------------------
// Cancellable RSA key generation (FR-02 AC1, FR-16, NFR-03)
// ---------------------------------------------------------------------------

/// State shared with the OpenSSL keygen callback through the context's app data.
struct KeygenState<'a> {
    cancel: &'a AtomicBool,
    progress: &'a (dyn Fn(u64) + Sync),
    steps: AtomicU64,
    callbacks: AtomicU64,
    callbacks_after_abort: AtomicU64,
    aborted: AtomicBool,
    callback_failed: AtomicBool,
}

/// Called by OpenSSL during prime generation. Returning 0 makes OpenSSL abort.
///
/// Never unwinds into C: any panic in the progress callback is caught and turns
/// into "abort". Once it has returned 0 it keeps returning 0 without calling the
/// progress callback, and counts any such late call (`KeygenTrace`).
unsafe extern "C" fn keygen_callback(ctx: *mut sys::EVP_PKEY_CTX) -> c_int {
    // SAFETY: OpenSSL passes the context we created; its app data is either null or the
    // `KeygenState` that `generate_with_state` keeps alive for the whole keygen call.
    let state = unsafe { EVP_PKEY_CTX_get_app_data(ctx) }.cast::<KeygenState<'_>>();
    if state.is_null() {
        return 0;
    }
    // SAFETY: non-null and valid for the duration of this call (see above); only shared
    // references and atomics are used.
    let state = unsafe { &*state };
    state.callbacks.fetch_add(1, Ordering::SeqCst);
    if state.aborted.load(Ordering::SeqCst) {
        state.callbacks_after_abort.fetch_add(1, Ordering::SeqCst);
        return 0;
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if state.cancel.load(Ordering::SeqCst) {
            return false;
        }
        let step = state.steps.fetch_add(1, Ordering::Relaxed) + 1;
        (state.progress)(step);
        !state.cancel.load(Ordering::SeqCst)
    }));
    let keep_going = match outcome {
        Ok(keep_going) => keep_going,
        Err(_) => {
            state.callback_failed.store(true, Ordering::SeqCst);
            false
        }
    };
    if keep_going {
        1
    } else {
        state.aborted.store(true, Ordering::SeqCst);
        0
    }
}

// ---------------------------------------------------------------------------
// Private keys (SEC-04, SEC-07, SEC-18)
// ---------------------------------------------------------------------------

/// A private key owned by this module.
///
/// The `EVP_PKEY` is created by key generation or decryption and freed on drop
/// (`EVP_PKEY_free` clears the private numbers, including any copy OpenSSL made
/// for signing). It is never handed out as an
/// OpenSSL object, so only this module can reach the private key; the methods
/// below are the only things anyone can do with it.
pub(crate) struct PrivateKey(PkeyGuard);

// SAFETY: `PrivateKey` exclusively owns its `EVP_PKEY`. Every method takes `&self` and
// only reads the key (public-key encoding, signing through a fresh per-call
// `EVP_PKEY_CTX`, PKCS#8 encoding); OpenSSL 3 documents such read-only use of one
// `EVP_PKEY` from several threads as safe (openssl-threads(7)), and the `openssl` crate
// marks its `PKey` wrapper `Send` and `Sync` for the same reason.
unsafe impl Send for PrivateKey {}
// SAFETY: see `Send` above.
unsafe impl Sync for PrivateKey {}

impl PrivateKey {
    /// True for an RSA key (not RSA-PSS or any other type).
    pub(crate) fn is_rsa(&self) -> bool {
        // SAFETY: `self.0.0` is a live key owned by the guard.
        unsafe { sys::EVP_PKEY_id(self.0.0) == sys::EVP_PKEY_RSA }
    }

    /// Modulus size in bits.
    pub(crate) fn bits(&self) -> u32 {
        // SAFETY: `self.0.0` is a live key owned by the guard.
        let bits = unsafe { sys::EVP_PKEY_bits(self.0.0) };
        u32::try_from(bits).unwrap_or(0)
    }

    /// The public key as DER `SubjectPublicKeyInfo`.
    pub(crate) fn public_key_der(&self) -> Result<Vec<u8>, CryptoError> {
        // SAFETY: `self.0.0` is a live key; a null output pointer asks only for the length.
        let len = unsafe { sys::i2d_PUBKEY(self.0.0, ptr::null_mut()) };
        let len = usize::try_from(len)
            .ok()
            .filter(|len| *len > 0)
            .ok_or_else(|| openssl_error("i2d_PUBKEY (length)"))?;
        let mut out = vec![0u8; len];
        let mut cursor = out.as_mut_ptr();
        // SAFETY: `out` has exactly `len` writable bytes, which is what is written.
        let written = unsafe { sys::i2d_PUBKEY(self.0.0, &mut cursor) };
        if usize::try_from(written).ok() != Some(len) {
            return Err(openssl_error("i2d_PUBKEY"));
        }
        Ok(out)
    }

    /// Signs a SHA-384 digest with RSA PKCS#1 v1.5 (OpenSSL adds the SHA-384
    /// DigestInfo), giving a sha384WithRSAEncryption signature.
    pub(crate) fn sign_sha384_digest(&self, digest: &[u8; 48]) -> Result<Vec<u8>, CryptoError> {
        // SAFETY: `self.0.0` is a live key; the new context holds its own reference.
        let ctx = PkeyCtxGuard::checked(
            unsafe { sys::EVP_PKEY_CTX_new(self.0.0, ptr::null_mut()) },
            "EVP_PKEY_CTX_new",
        )?;
        // SAFETY: `ctx.0` is a live context owned by the guard.
        if unsafe { sys::EVP_PKEY_sign_init(ctx.0) } <= 0 {
            return Err(openssl_error("EVP_PKEY_sign_init"));
        }
        // SAFETY: as above; PKCS#1 v1.5 padding is a plain integer constant.
        if unsafe { sys::EVP_PKEY_CTX_set_rsa_padding(ctx.0, sys::RSA_PKCS1_PADDING) } <= 0 {
            return Err(openssl_error("EVP_PKEY_CTX_set_rsa_padding"));
        }
        // SAFETY: as above; `EVP_sha384` returns a static digest description.
        if unsafe { sys::EVP_PKEY_CTX_set_signature_md(ctx.0, sys::EVP_sha384()) } <= 0 {
            return Err(openssl_error("EVP_PKEY_CTX_set_signature_md"));
        }
        let mut len: usize = 0;
        // SAFETY: a null signature pointer asks only for the maximum length; the digest
        // is 48 readable bytes.
        let rc = unsafe {
            sys::EVP_PKEY_sign(
                ctx.0,
                ptr::null_mut(),
                &mut len,
                digest.as_ptr(),
                digest.len(),
            )
        };
        if rc <= 0 || len == 0 {
            return Err(openssl_error("EVP_PKEY_sign (length)"));
        }
        let mut signature = vec![0u8; len];
        // SAFETY: `signature` has `len` writable bytes; OpenSSL writes at most that many
        // and stores the actual length in `len`.
        let rc = unsafe {
            sys::EVP_PKEY_sign(
                ctx.0,
                signature.as_mut_ptr(),
                &mut len,
                digest.as_ptr(),
                digest.len(),
            )
        };
        if rc <= 0 || len > signature.len() {
            return Err(openssl_error("EVP_PKEY_sign"));
        }
        signature.truncate(len);
        Ok(signature)
    }
}

/// Generates an RSA key with public exponent 65537 using OpenSSL 3's
/// `EVP_PKEY_generate`, with a callback that reports progress and lets the
/// operator cancel (FR-16).
///
/// The key is generated directly into the returned [`PrivateKey`]; no encoded copy
/// of it is ever made.
pub(crate) fn generate_rsa_key(
    bits: u32,
    cancel: &AtomicBool,
    progress: &(dyn Fn(u64) + Sync),
) -> Result<PrivateKey, CryptoError> {
    generate_rsa_key_traced(bits, cancel, progress).0
}

/// What the keygen callback saw; used by tests to prove that OpenSSL really stops
/// after the callback asked it to (FR-16 AC2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KeygenTrace {
    /// Times OpenSSL called the callback.
    pub(crate) callbacks: u64,
    /// Times OpenSSL called the callback again after it had returned 0 ("abort").
    /// OpenSSL 3's FIPS 186-4 prime search ignores the result of its per-candidate
    /// callback and stops at the next callback whose result it checks, so a few such
    /// calls are normal. Each is answered with 0 at once and never reaches the
    /// progress callback.
    pub(crate) callbacks_after_abort: u64,
}

fn generate_rsa_key_traced(
    bits: u32,
    cancel: &AtomicBool,
    progress: &(dyn Fn(u64) + Sync),
) -> (Result<PrivateKey, CryptoError>, KeygenTrace) {
    let state = KeygenState {
        cancel,
        progress,
        steps: AtomicU64::new(0),
        callbacks: AtomicU64::new(0),
        callbacks_after_abort: AtomicU64::new(0),
        aborted: AtomicBool::new(false),
        callback_failed: AtomicBool::new(false),
    };
    let result = generate_with_state(bits, &state);
    let trace = KeygenTrace {
        callbacks: state.callbacks.load(Ordering::SeqCst),
        callbacks_after_abort: state.callbacks_after_abort.load(Ordering::SeqCst),
    };
    (result, trace)
}

fn generate_with_state(bits: u32, state: &KeygenState<'_>) -> Result<PrivateKey, CryptoError> {
    let cancel = state.cancel;
    let bits_c = c_int::try_from(bits).map_err(|_| CryptoError::UnsupportedKeySize { bits })?;
    if cancel.load(Ordering::SeqCst) {
        return Err(CryptoError::Cancelled);
    }
    // The private numbers and generation temporaries go into the locked heap.
    init_secure_heap()?;
    // SAFETY: plain constructor; a null result is handled by `checked`.
    let ctx = PkeyCtxGuard::checked(
        unsafe { sys::EVP_PKEY_CTX_new_id(sys::EVP_PKEY_RSA, ptr::null_mut()) },
        "EVP_PKEY_CTX_new_id",
    )?;
    // SAFETY: `ctx.0` is a live context owned by the guard.
    if unsafe { sys::EVP_PKEY_keygen_init(ctx.0) } <= 0 {
        return Err(openssl_error("EVP_PKEY_keygen_init"));
    }
    // SAFETY: as above; `bits_c` is a plain integer.
    if unsafe { sys::EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.0, bits_c) } <= 0 {
        return Err(openssl_error("EVP_PKEY_CTX_set_rsa_keygen_bits"));
    }
    // SAFETY: plain constructor; a null result is handled by `checked`.
    let exponent = BignumGuard::checked(unsafe { sys::BN_new() }, "BN_new")?;
    // SAFETY: `exponent.0` is a live BIGNUM owned by the guard.
    if unsafe { sys::BN_set_word(exponent.0, 65_537) } != 1 {
        return Err(openssl_error("BN_set_word"));
    }
    // SAFETY: `set1` copies the exponent; our guard still frees its own BIGNUM.
    if unsafe { sys::EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx.0, exponent.0) } <= 0 {
        return Err(openssl_error("EVP_PKEY_CTX_set1_rsa_keygen_pubexp"));
    }
    // SAFETY: `state` is borrowed for the whole of this function, so it outlives the
    // `EVP_PKEY_generate` call below; the app data pointer is cleared again right after
    // that call.
    unsafe {
        EVP_PKEY_CTX_set_app_data(ctx.0, ptr::from_ref(state).cast_mut().cast::<c_void>());
        EVP_PKEY_CTX_set_cb(ctx.0, Some(keygen_callback));
    }
    let mut raw: *mut sys::EVP_PKEY = ptr::null_mut();
    // SAFETY: `ctx.0` is live and initialised for keygen; `raw` receives a new key that
    // the guard below takes ownership of.
    let rc = unsafe { sys::EVP_PKEY_generate(ctx.0, &mut raw) };
    // SAFETY: detaches the callback state before `state` goes out of scope.
    unsafe {
        EVP_PKEY_CTX_set_cb(ctx.0, None);
        EVP_PKEY_CTX_set_app_data(ctx.0, ptr::null_mut());
    }
    // Owns the new key (if any) from here on, so it is freed on every early return.
    let key = PkeyGuard(raw);
    if cancel.load(Ordering::SeqCst) {
        // SAFETY: clears this thread's error queue (the abort leaves entries in it).
        unsafe { sys::ERR_clear_error() };
        return Err(CryptoError::Cancelled);
    }
    if state.callback_failed.load(Ordering::SeqCst) {
        // SAFETY: as above.
        unsafe { sys::ERR_clear_error() };
        return Err(CryptoError::OpenSsl(
            "key generation progress callback failed".to_owned(),
        ));
    }
    if rc <= 0 || key.0.is_null() {
        return Err(openssl_error("EVP_PKEY_generate"));
    }
    Ok(PrivateKey(key))
}

// ---------------------------------------------------------------------------
// Encrypted PKCS#8 with explicit PBES2 parameters (FR-04 AC1, SEC-04)
// ---------------------------------------------------------------------------

/// The PBES2 key-derivation function and its parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pbes2Kdf {
    /// scrypt with cost `n` (a power of two), block size `r` and parallelism `p`.
    Scrypt { n: u64, r: u64, p: u64 },
    /// PBKDF2 with HMAC-SHA256 as the PRF.
    Pbkdf2HmacSha256 { iterations: u32 },
}

/// Encrypts `key` into an `EncryptedPrivateKeyInfo` (DER) using PBES2 with the given
/// KDF and AES-256-CBC, with the caller's salt and IV.
///
/// `EVP_PKEY2PKCS8` puts the key into OpenSSL's `PKCS8_PRIV_KEY_INFO` (wiped when
/// freed), and `PKCS8_set0_pbe` encrypts it there (its plaintext buffer is wiped
/// too); no plaintext copy reaches Rust. For a generated key, `EVP_PKEY2PKCS8` goes
/// through OpenSSL's encoder, which frees two plaintext buffers without wiping them;
/// see the residual risk in the module documentation. The passphrase is passed with
/// its explicit length. The output contains only ciphertext and public parameters.
pub(crate) fn encrypt_pkcs8_der(
    key: &PrivateKey,
    passphrase: &[u8],
    kdf: Pbes2Kdf,
    salt: &[u8; 16],
    iv: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    if passphrase.is_empty() {
        return Err(CryptoError::EmptyPassphrase);
    }
    let pass_len = c_len(passphrase.len(), "passphrase")?;
    // SAFETY: `key.0.0` is a live key; OpenSSL allocates a new object, freed by the guard.
    let p8 = P8InfoGuard::checked(unsafe { sys::EVP_PKEY2PKCS8(key.0.0) }, "EVP_PKEY2PKCS8")?;
    // SAFETY: returns a static cipher description.
    let cipher = unsafe { sys::EVP_aes_256_cbc() };
    let mut salt = *salt;
    let mut iv = *iv;
    let algor = match kdf {
        Pbes2Kdf::Scrypt { n, r, p } => {
            // SAFETY: salt and IV are 16-byte buffers that OpenSSL copies.
            let raw = unsafe {
                PKCS5_pbe2_set_scrypt(cipher, salt.as_ptr(), 16, iv.as_mut_ptr(), n, r, p)
            };
            AlgorGuard::checked(raw, "PKCS5_pbe2_set_scrypt")?
        }
        Pbes2Kdf::Pbkdf2HmacSha256 { iterations } => {
            let iterations = c_int::try_from(iterations)
                .map_err(|_| CryptoError::OpenSsl("PBKDF2 iteration count too large".into()))?;
            // SAFETY: salt and IV are 16-byte buffers that OpenSSL copies.
            let raw = unsafe {
                PKCS5_pbe2_set_iv(
                    cipher,
                    iterations,
                    salt.as_mut_ptr(),
                    16,
                    iv.as_mut_ptr(),
                    sys::NID_hmacWithSHA256,
                )
            };
            AlgorGuard::checked(raw, "PKCS5_pbe2_set_iv")?
        }
    };
    let mut algor = algor;
    // SAFETY: `p8.0` and `algor.0` are live objects; on success `PKCS8_set0_pbe` takes
    // ownership of `algor.0` (handled below), on failure it leaves it with us.
    let sig = unsafe {
        PKCS8_set0_pbe(
            passphrase.as_ptr().cast::<c_char>(),
            pass_len,
            p8.0,
            algor.0,
        )
    };
    let sig = SigGuard::checked(sig, "PKCS8_set0_pbe")?;
    // Ownership of the algorithm moved into `sig`.
    algor.0 = ptr::null_mut();
    // SAFETY: `sig.0` is live; a null output pointer asks only for the length.
    let len = unsafe { i2d_X509_SIG(sig.0, ptr::null_mut()) };
    let len = usize::try_from(len)
        .ok()
        .filter(|len| *len > 0)
        .ok_or_else(|| openssl_error("i2d_X509_SIG (length)"))?;
    let mut out = vec![0u8; len];
    let mut cursor = out.as_mut_ptr();
    // SAFETY: `out` has exactly `len` writable bytes, which is what is written.
    let written = unsafe { i2d_X509_SIG(sig.0, &mut cursor) };
    if usize::try_from(written).ok() != Some(len) {
        return Err(openssl_error("i2d_X509_SIG"));
    }
    Ok(out)
}

/// Decrypts an `EncryptedPrivateKeyInfo` (DER) into a [`PrivateKey`] (FR-04 AC2, AC3).
///
/// The caller checks the encryption parameters first (`pkcs8.rs`, SEC-08). The
/// passphrase is passed to `PKCS8_decrypt` as a pointer into the caller's (locked)
/// buffer with an explicit length, so no copy of it is made on the Rust side and a
/// NUL byte is an ordinary byte. `PKCS8_decrypt` wipes its plaintext buffer before
/// freeing it, and the decrypted `PKCS8_PRIV_KEY_INFO` is wiped by OpenSSL when it
/// is freed. [`rsa_key_from_pkcs8_info`] then decodes the key from that structure
/// into the secure heap without any other copy.
///
/// A malformed structure is [`CryptoError::Der`]; a failed decryption (wrong
/// passphrase or damaged ciphertext) is [`CryptoError::WrongPassphrase`]; a key that
/// is not RSA is [`CryptoError::UnsupportedKey`].
pub(crate) fn decrypt_pkcs8_der(der: &[u8], passphrase: &[u8]) -> Result<PrivateKey, CryptoError> {
    // The decrypted private numbers go into the locked heap.
    init_secure_heap()?;
    let der_len = c_len(der.len(), "key file")?;
    let pass_len = c_len(passphrase.len(), "passphrase")?;
    let start = der.as_ptr();
    let mut cursor = start;
    // SAFETY: `cursor` points to `der_len` readable bytes; OpenSSL allocates a new object.
    let sig = unsafe { d2i_X509_SIG(ptr::null_mut(), &mut cursor, c_long::from(der_len)) };
    if sig.is_null() {
        // SAFETY: clears this thread's error queue.
        unsafe { sys::ERR_clear_error() };
        return Err(CryptoError::Der(
            "the encrypted key structure could not be read".into(),
        ));
    }
    let sig = SigGuard(sig);
    if cursor != start.wrapping_add(der.len()) {
        return Err(CryptoError::Der(
            "trailing data after the encrypted key".into(),
        ));
    }
    // SAFETY: `sig.0` is live; `passphrase` points to `pass_len` readable bytes, and
    // OpenSSL reads exactly that many (an explicit length, not a C string).
    let p8 = unsafe { PKCS8_decrypt(sig.0, passphrase.as_ptr().cast::<c_char>(), pass_len) };
    if p8.is_null() {
        // SAFETY: clears this thread's error queue (bad decrypt leaves entries in it).
        unsafe { sys::ERR_clear_error() };
        return Err(CryptoError::WrongPassphrase);
    }
    let p8 = P8InfoGuard(p8);
    rsa_key_from_pkcs8_info(&p8)
}

/// Fuzzing entry point (SEC-08): reads a plaintext `PrivateKeyInfo` the way
/// `PKCS8_decrypt` does after a successful decryption (`d2i_PKCS8_PRIV_KEY_INFO`,
/// trailing bytes ignored) and decodes it with [`rsa_key_from_pkcs8_info`], so the
/// fuzzer reaches that decoder without a key derivation per input.
///
/// Compiled only by `cargo fuzz` (`--cfg fuzzing`) and never with the `production`
/// feature, so no test, development or production build contains it.
#[cfg(all(fuzzing, not(feature = "production")))]
pub(crate) fn decode_private_key_info_for_fuzzing(der: &[u8]) -> Result<PrivateKey, CryptoError> {
    init_secure_heap()?;
    rsa_key_from_pkcs8_info(&pkcs8_info_from_der(der)?)
}

/// Reads a plaintext `PrivateKeyInfo` as `PKCS8_decrypt` does. Only for the fuzzing
/// entry point and the unit tests below; never in a production build.
#[cfg(any(test, all(fuzzing, not(feature = "production"))))]
fn pkcs8_info_from_der(der: &[u8]) -> Result<P8InfoGuard, CryptoError> {
    let len = c_len(der.len(), "key")?;
    let mut cursor = der.as_ptr();
    // SAFETY: `cursor` points to `len` readable bytes; OpenSSL allocates a new object,
    // owned by the guard below.
    let p8 =
        unsafe { sys::d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &mut cursor, c_long::from(len)) };
    if p8.is_null() {
        // SAFETY: clears this thread's error queue.
        unsafe { sys::ERR_clear_error() };
        return Err(CryptoError::Der("not a PrivateKeyInfo".into()));
    }
    Ok(P8InfoGuard(p8))
}

/// Turns a decrypted `PrivateKeyInfo` into a [`PrivateKey`] without leaving any copy
/// of the private numbers outside OpenSSL's secure heap (SEC-07).
///
/// `EVP_PKCS82PKEY` is not used: in OpenSSL 3 (checked in the 3.0.13 and 3.5.4
/// sources) it re-encodes the structure and runs the `OSSL_DECODER`, whose DER reader
/// (`der2key_decode`) copies the whole plaintext key into a heap buffer and frees it
/// without wiping it. Instead:
/// 1. `PKCS8_pkey_get0` borrows the `RSAPrivateKey` DER inside `p8`; nothing is
///    copied, and `p8` wipes it when freed.
/// 2. `d2i_RSAPrivateKey` decodes straight from that buffer. Its ASN.1 template marks
///    d, p, q, dP, dQ and qInv as `CBIGNUM`, so each is created with `BN_secure_new`
///    in the locked secure heap and filled by `BN_bin2bn` directly from the DER
///    (a primitive INTEGER is never collected into a temporary buffer).
/// 3. `EVP_PKEY_assign` hands that `RSA` to a new `EVP_PKEY` without copying it.
///
/// `d2i_RSAPrivateKey`, `RSA_free` and `EVP_PKEY_assign` are deprecated since
/// OpenSSL 3.0 but are part of every 3.x library built with the deprecated API, which
/// is the default and how Ubuntu builds 3.0 and 3.5; rust-openssl relies on them as
/// well. Without them the program does not link, so the change cannot go unnoticed.
///
/// The result is a "legacy" `EVP_PKEY`. Signing with it makes OpenSSL export the key
/// once to its default provider (`OSSL_PARAM` in the secure heap, wiped when freed);
/// the provider's copy and its Montgomery values are ordinary heap memory while the
/// key lives and are wiped by `BN_clear_free` when it is dropped. Keys from
/// [`generate_rsa_key`] keep such Montgomery values in ordinary memory after their
/// first signature as well.
fn rsa_key_from_pkcs8_info(p8: &P8InfoGuard) -> Result<PrivateKey, CryptoError> {
    let mut algorithm: *const sys::ASN1_OBJECT = ptr::null();
    let mut data: *const u8 = ptr::null();
    let mut len: c_int = 0;
    // SAFETY: `p8.0` is live. The outputs are borrowed pointers into `p8`, used only
    // while `p8` is alive; the `X509_ALGOR` output is not requested (null is allowed).
    let found =
        unsafe { PKCS8_pkey_get0(&mut algorithm, &mut data, &mut len, ptr::null_mut(), p8.0) };
    let Ok(data_len) = usize::try_from(len) else {
        return Err(CryptoError::WrongPassphrase);
    };
    if found != 1 || algorithm.is_null() || data.is_null() || data_len == 0 {
        // SAFETY: clears this thread's error queue.
        unsafe { sys::ERR_clear_error() };
        return Err(CryptoError::WrongPassphrase);
    }
    // SAFETY: `algorithm` points to the live algorithm OID inside `p8`.
    if unsafe { sys::OBJ_obj2nid(algorithm) } != sys::NID_rsaEncryption {
        return Err(CryptoError::UnsupportedKey("not an RSA key".into()));
    }
    let mut cursor = data;
    // SAFETY: `cursor` points to `len` readable bytes inside `p8`, which outlives this
    // call; OpenSSL allocates a new `RSA`, owned by the guard below.
    let rsa = unsafe { sys::d2i_RSAPrivateKey(ptr::null_mut(), &mut cursor, c_long::from(len)) };
    if rsa.is_null() {
        // SAFETY: clears this thread's error queue.
        unsafe { sys::ERR_clear_error() };
        return Err(CryptoError::WrongPassphrase);
    }
    let mut rsa = RsaGuard(rsa);
    if cursor != data.wrapping_add(data_len) {
        return Err(CryptoError::WrongPassphrase);
    }
    // SAFETY: plain constructor; a null result is handled by `checked`.
    let key = PkeyGuard::checked(unsafe { sys::EVP_PKEY_new() }, "EVP_PKEY_new")?;
    // SAFETY: both objects are live. On success the key takes ownership of `rsa.0`
    // without copying it (handled below); on failure it stays with the guard.
    if unsafe { sys::EVP_PKEY_assign(key.0, sys::EVP_PKEY_RSA, rsa.0.cast::<c_void>()) } != 1 {
        return Err(openssl_error("EVP_PKEY_assign"));
    }
    rsa.0 = ptr::null_mut();
    Ok(PrivateKey(key))
}

// ---------------------------------------------------------------------------
// Chain verification with in-memory CRLs
// ---------------------------------------------------------------------------

/// Input for [`verify_chain`]. All values are DER.
pub(crate) struct ChainInput<'a> {
    pub leaf: &'a [u8],
    pub untrusted: &'a [&'a [u8]],
    pub trusted: &'a [&'a [u8]],
    pub crls: &'a [&'a [u8]],
    /// Check CRLs for every certificate in the chain (`-crl_check_all`).
    pub crl_check_all: bool,
    /// RFC 5280 strict mode (`-x509_strict`).
    pub strict: bool,
    /// Verification time, seconds since the Unix epoch.
    pub at_unix: i64,
}

/// Result of a completed verification.
pub(crate) enum ChainOutcome {
    Valid,
    Invalid {
        code: i32,
        depth: i32,
        reason: String,
    },
}

fn parse_x509(der: &[u8]) -> Result<X509Guard, CryptoError> {
    let len = c_len(der.len(), "certificate")?;
    let start = der.as_ptr();
    let mut cursor = start;
    // SAFETY: `cursor` points to `len` readable bytes; OpenSSL allocates a new object.
    let cert = X509Guard::checked(
        unsafe { sys::d2i_X509(ptr::null_mut(), &mut cursor, c_long::from(len)) },
        "d2i_X509",
    )?;
    if cursor != start.wrapping_add(der.len()) {
        return Err(CryptoError::Der("trailing data after certificate".into()));
    }
    Ok(cert)
}

fn parse_crl(der: &[u8]) -> Result<CrlGuard, CryptoError> {
    let len = c_len(der.len(), "CRL")?;
    let start = der.as_ptr();
    let mut cursor = start;
    // SAFETY: `cursor` points to `len` readable bytes; OpenSSL allocates a new object.
    let crl = CrlGuard::checked(
        unsafe { sys::d2i_X509_CRL(ptr::null_mut(), &mut cursor, c_long::from(len)) },
        "d2i_X509_CRL",
    )?;
    if cursor != start.wrapping_add(der.len()) {
        return Err(CryptoError::Der("trailing data after CRL".into()));
    }
    Ok(crl)
}

/// Runs `X509_verify_cert` for `input`.
pub(crate) fn verify_chain(input: &ChainInput<'_>) -> Result<ChainOutcome, CryptoError> {
    // Declaration order matters: locals drop in reverse, so the context is freed first,
    // then the stack, the certificates and CRLs, and the store last.
    // SAFETY: plain constructor; a null result is handled by `checked`.
    let store = StoreGuard::checked(unsafe { sys::X509_STORE_new() }, "X509_STORE_new")?;
    let mut trusted = Vec::with_capacity(input.trusted.len());
    for der in input.trusted {
        let cert = parse_x509(der)?;
        // SAFETY: both objects are live; the store takes its own reference.
        if unsafe { sys::X509_STORE_add_cert(store.0, cert.0) } != 1 {
            return Err(openssl_error("X509_STORE_add_cert"));
        }
        trusted.push(cert);
    }
    let mut crls = Vec::with_capacity(input.crls.len());
    for der in input.crls {
        let crl = parse_crl(der)?;
        // SAFETY: both objects are live; the store takes its own reference.
        if unsafe { X509_STORE_add_crl(store.0, crl.0) } != 1 {
            return Err(openssl_error("X509_STORE_add_crl"));
        }
        crls.push(crl);
    }
    let mut flags: c_ulong = 0;
    if input.crl_check_all {
        flags |= sys::X509_V_FLAG_CRL_CHECK | sys::X509_V_FLAG_CRL_CHECK_ALL;
    }
    if input.strict {
        flags |= sys::X509_V_FLAG_X509_STRICT;
    }
    // SAFETY: `store.0` is live.
    if flags != 0 && unsafe { sys::X509_STORE_set_flags(store.0, flags) } != 1 {
        return Err(openssl_error("X509_STORE_set_flags"));
    }
    let leaf = parse_x509(input.leaf)?;
    let mut untrusted = Vec::with_capacity(input.untrusted.len());
    for der in input.untrusted {
        untrusted.push(parse_x509(der)?);
    }
    // SAFETY: plain constructor; a null result is handled by `checked`.
    let stack = StackGuard::checked(unsafe { sys::OPENSSL_sk_new_null() }, "sk_new_null")?;
    for cert in &untrusted {
        // SAFETY: the stack only borrows the pointer; `untrusted` outlives the stack.
        if unsafe { sys::OPENSSL_sk_push(stack.0, cert.0.cast::<c_void>().cast_const()) } <= 0 {
            return Err(openssl_error("sk_push"));
        }
    }
    // SAFETY: plain constructor; a null result is handled by `checked`.
    let ctx = StoreCtxGuard::checked(unsafe { sys::X509_STORE_CTX_new() }, "X509_STORE_CTX_new")?;
    // SAFETY: all pointers are live and outlive `ctx` (dropped first, see above). A
    // STACK_OF(X509) is an OPENSSL_STACK.
    let init = unsafe {
        sys::X509_STORE_CTX_init(ctx.0, store.0, leaf.0, stack.0.cast::<sys::stack_st_X509>())
    };
    if init != 1 {
        return Err(openssl_error("X509_STORE_CTX_init"));
    }
    let at = c_long::try_from(input.at_unix)
        .map_err(|_| CryptoError::OpenSsl("verification time out of range".into()))?;
    // SAFETY: `ctx.0` is live and initialised.
    unsafe { X509_STORE_CTX_set_time(ctx.0, 0, at) };
    // SAFETY: `ctx.0` is live and initialised.
    let rc = unsafe { sys::X509_verify_cert(ctx.0) };
    if rc == 1 {
        return Ok(ChainOutcome::Valid);
    }
    // SAFETY: `ctx.0` is live.
    let code = unsafe { sys::X509_STORE_CTX_get_error(ctx.0) };
    // SAFETY: `ctx.0` is live.
    let depth = unsafe { sys::X509_STORE_CTX_get_error_depth(ctx.0) };
    // SAFETY: returns a pointer to a static, NUL-terminated string (never null in 3.x).
    let text = unsafe { sys::X509_verify_cert_error_string(c_long::from(code)) };
    let reason = if text.is_null() {
        format!("verification error {code}")
    } else {
        // SAFETY: non-null, NUL-terminated and static (see above).
        unsafe { CStr::from_ptr(text) }
            .to_string_lossy()
            .into_owned()
    };
    // SAFETY: clears this thread's error queue so later calls start clean.
    unsafe { sys::ERR_clear_error() };
    if rc < 0 && code == sys::X509_V_OK {
        return Err(CryptoError::OpenSsl(
            "X509_verify_cert failed internally".into(),
        ));
    }
    Ok(ChainOutcome::Invalid {
        code,
        depth,
        reason,
    })
}

/// Page size of the only supported target (x86_64-unknown-linux-gnu).
const PAGE_SIZE: usize = 4096;

/// Locked, wiped-on-drop memory for secrets (SEC-07).
///
/// Each region owns whole pages, so unlocking one region on drop can never unlock
/// the page of another live secret.
pub(crate) struct LockedRegion {
    ptr: NonNull<u8>,
    size: usize,
}

// SAFETY: `LockedRegion` exclusively owns its allocation (like `Box<[u8]>`), so it can
// move between threads, and shared references only allow reads.
unsafe impl Send for LockedRegion {}
// SAFETY: see `Send` above; `&LockedRegion` exposes only `&[u8]`.
unsafe impl Sync for LockedRegion {}

impl LockedRegion {
    /// Allocates at least `min_len` zeroed bytes, rounded up to whole pages, and
    /// locks them into RAM. Fails if the memory cannot be locked: a secret is never
    /// held in memory that could be swapped to disk.
    pub(crate) fn new(min_len: usize) -> Result<Self, CryptoError> {
        let size = min_len
            .max(1)
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(CryptoError::LockedMemory)?;
        let layout =
            Layout::from_size_align(size, PAGE_SIZE).map_err(|_| CryptoError::LockedMemory)?;
        // SAFETY: `layout` has a non-zero size (at least one page).
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).ok_or(CryptoError::LockedMemory)?;
        // From here on, `Drop` frees the allocation on every early return.
        let region = LockedRegion { ptr, size };
        // SAFETY: `ptr..ptr+size` is a live allocation owned by `region`.
        unsafe { rustix::mm::mlock(region.ptr.as_ptr().cast::<c_void>(), region.size) }
            .map_err(|_| CryptoError::LockedMemory)?;
        // SAFETY: same range as above. MADV_DONTDUMP keeps the pages out of core dumps
        // even if core dumps were re-enabled; failure is not fatal because core dumps
        // are also disabled for the whole process (hardening module).
        let _ = unsafe {
            rustix::mm::madvise(
                region.ptr.as_ptr().cast::<c_void>(),
                region.size,
                rustix::mm::Advice::LinuxDontDump,
            )
        };
        Ok(region)
    }

    /// Total usable bytes (whole pages).
    pub(crate) fn capacity(&self) -> usize {
        self.size
    }

    /// The whole region.
    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is valid for `size` initialised (zeroed at allocation) bytes for
        // the lifetime of `self`, and no mutable reference exists while `&self` is held.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.size) }
    }

    /// The whole region, writable.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as in `as_slice`, and `&mut self` guarantees exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size) }
    }
}

impl Drop for LockedRegion {
    fn drop(&mut self) {
        // Volatile wipe that the compiler cannot remove.
        self.as_mut_slice().zeroize();
        // SAFETY: the range is the live allocation owned by `self`; unlocking pages that
        // were never locked (when `mlock` failed in `new`) is harmless.
        let _ = unsafe { rustix::mm::munlock(self.ptr.as_ptr().cast::<c_void>(), self.size) };
        // SAFETY: allocated in `new` with exactly this size and alignment, freed once.
        unsafe {
            dealloc(
                self.ptr.as_ptr(),
                Layout::from_size_align_unchecked(self.size, PAGE_SIZE),
            )
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec07_locked_region_is_page_sized_zeroed_and_writable() {
        // Covers: SEC-07
        let mut region = LockedRegion::new(10).expect("mlock within RLIMIT_MEMLOCK");
        assert_eq!(region.capacity(), PAGE_SIZE);
        assert!(region.as_slice().iter().all(|b| *b == 0));
        region.as_mut_slice()[0] = 7;
        assert_eq!(region.as_slice()[0], 7);
        let large = LockedRegion::new(PAGE_SIZE + 1).expect("mlock");
        assert_eq!(large.capacity(), 2 * PAGE_SIZE);
    }

    /// DER tag, short-form length and content (contents here stay below 128 bytes).
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let len = u8::try_from(content.len()).ok().filter(|len| *len < 0x80);
        [&[tag, len.expect("short form")][..], content].concat()
    }

    /// rsaEncryption and id-ecPublicKey, as OID contents.
    const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

    /// The textbook RSA example (p = 61, q = 53, e = 17, a 12-bit modulus) as a PKCS#1
    /// `RSAPrivateKey`: synthetic, not a usable key.
    fn textbook_rsa() -> Vec<u8> {
        let numbers: [&[u8]; 9] = [
            &[0],          // version
            &[0x0c, 0xa1], // n = 3233
            &[0x11],       // e = 17
            &[0x0a, 0xc1], // d = 2753
            &[0x3d],       // p = 61
            &[0x35],       // q = 53
            &[0x35],       // dP = 53
            &[0x31],       // dQ = 49
            &[0x26],       // qInv = 38
        ];
        tlv(0x30, &numbers.map(|number| tlv(0x02, number)).concat())
    }

    /// A plaintext `PrivateKeyInfo` with algorithm `oid` around `private_key`.
    fn private_key_info(oid: &[u8], private_key: &[u8]) -> Vec<u8> {
        let algorithm = tlv(0x30, &[tlv(0x06, oid), vec![0x05, 0x00]].concat());
        tlv(
            0x30,
            &[tlv(0x02, &[0]), algorithm, tlv(0x04, private_key)].concat(),
        )
    }

    fn decode(der: &[u8]) -> Result<PrivateKey, CryptoError> {
        init_secure_heap().expect("secure heap");
        rsa_key_from_pkcs8_info(&pkcs8_info_from_der(der).expect("PrivateKeyInfo"))
    }

    #[test]
    fn sec07_decrypted_key_info_is_decoded_as_rsa_only() {
        // Covers: SEC-07, FR-04 AC3
        // The decoder that replaced EVP_PKCS82PKEY: an RSA PrivateKeyInfo becomes a key.
        let key = decode(&private_key_info(RSA_ENCRYPTION, &textbook_rsa())).expect("RSA");
        assert!(key.is_rsa());
        assert_eq!(key.bits(), 12);
        assert!(!key.public_key_der().expect("public key").is_empty());
        // Another algorithm is refused, whatever it contains.
        assert!(matches!(
            decode(&private_key_info(EC_PUBLIC_KEY, &textbook_rsa())),
            Err(CryptoError::UnsupportedKey(_))
        ));
        // A damaged RSAPrivateKey, or one followed by extra bytes, reads as a wrong
        // passphrase or damaged file (FR-04 AC3), never as a key.
        let mut damaged = textbook_rsa();
        damaged[1] += 1;
        let mut trailing = textbook_rsa();
        trailing.push(0);
        for content in [damaged, trailing, Vec::new(), vec![0x30, 0x00]] {
            assert!(
                matches!(
                    decode(&private_key_info(RSA_ENCRYPTION, &content)),
                    Err(CryptoError::WrongPassphrase)
                ),
                "{content:02x?}"
            );
        }
    }

    /// OpenSSL calls back at most this many times after the callback returned 0:
    /// it ignores the result of its per-candidate callback in the FIPS 186-4 prime
    /// search and stops at the next callback whose result it checks (the next
    /// Miller-Rabin round), normally within a few dozen cheap trial divisions.
    const LATE_CALLBACK_LIMIT: u64 = 1_000;

    #[test]
    fn fr16_no_progress_is_reported_after_the_callback_returned_zero() {
        // Covers: FR-16 AC2, NFR-03
        // Cancel at the third progress step of an RSA 8,192 generation. From then on
        // the callback answers 0 without calling the progress callback, and OpenSSL
        // aborts at its next checked callback.
        let cancel = AtomicBool::new(false);
        let progress_after_cancel = AtomicU64::new(0);
        let (result, trace) = generate_rsa_key_traced(8192, &cancel, &|step| {
            if cancel.load(Ordering::SeqCst) {
                progress_after_cancel.fetch_add(1, Ordering::SeqCst);
            }
            if step == 3 {
                cancel.store(true, Ordering::SeqCst);
            }
        });
        assert!(matches!(result, Err(CryptoError::Cancelled)));
        assert_eq!(progress_after_cancel.load(Ordering::SeqCst), 0);
        assert!(trace.callbacks >= 3, "{trace:?}");
        assert_eq!(
            trace.callbacks,
            3 + trace.callbacks_after_abort,
            "every call after the third was answered with 0: {trace:?}"
        );
        assert!(
            trace.callbacks_after_abort < LATE_CALLBACK_LIMIT,
            "{trace:?}"
        );

        // The same when the progress callback panics at its first step: it is
        // called exactly once.
        let progress_calls = AtomicU64::new(0);
        let (result, trace) = generate_rsa_key_traced(2048, &AtomicBool::new(false), &|_| {
            progress_calls.fetch_add(1, Ordering::SeqCst);
            panic!("KEYSTONE TEST progress failure")
        });
        assert!(matches!(result, Err(CryptoError::OpenSsl(_))));
        assert_eq!(progress_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            trace.callbacks,
            1 + trace.callbacks_after_abort,
            "{trace:?}"
        );
        assert!(
            trace.callbacks_after_abort < LATE_CALLBACK_LIMIT,
            "{trace:?}"
        );

        // Without a cancel, generation completes and every callback answered 1.
        let (result, trace) = generate_rsa_key_traced(2048, &AtomicBool::new(false), &|_| {});
        let key = result.expect("RSA 2048");
        assert_eq!(key.bits(), 2048);
        assert!(key.is_rsa());
        assert!(trace.callbacks > 0);
        assert_eq!(trace.callbacks_after_abort, 0);
    }
}
