//! The single reviewed FFI module (SEC-18). The only file in the workspace where
//! `unsafe` code is allowed. Every unsafe block carries a `// SAFETY:` comment, and
//! `scripts/check-boundaries.sh` fails CI if one is missing.
//!
//! Contents:
//! - `LockedRegion`: page-aligned memory that is locked into RAM (never swapped),
//!   excluded from core dumps, and wiped before it is freed (SEC-07).
//! - `generate_rsa_der`: cancellable RSA key generation with a progress callback
//!   (FR-02 AC1, FR-16, NFR-03).
//! - `encrypt_pkcs8_der`: encrypted PKCS#8 with explicit PBES2 parameters
//!   (FR-04 AC1, SEC-04).
//! - `verify_chain`: `X509_verify_cert` with in-memory trusted roots, untrusted
//!   intermediates, CRLs and an explicit verification time.
//!
//! Rules for this file:
//! - Every raw OpenSSL object is owned by a small RAII guard, so it is freed on
//!   every path, including early returns.
//! - Nothing here panics across the FFI boundary: the keygen callback catches
//!   unwinding and turns it into "abort".
//! - Secrets cross into the safe `openssl` crate only as DER inside a
//!   `LockedRegion`, which is wiped on drop.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{self, NonNull};
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
    fn X509_STORE_add_crl(store: *mut sys::X509_STORE, crl: *mut sys::X509_CRL) -> c_int;
    fn X509_STORE_CTX_set_time(ctx: *mut sys::X509_STORE_CTX, flags: c_ulong, t: c_long);
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
    callback_failed: AtomicBool,
}

/// Called by OpenSSL during prime generation. Returning 0 makes OpenSSL abort.
///
/// Never unwinds into C: any panic in the progress callback is caught and turns
/// into "abort".
unsafe extern "C" fn keygen_callback(ctx: *mut sys::EVP_PKEY_CTX) -> c_int {
    // SAFETY: OpenSSL passes the context we created; its app data is either null or the
    // `KeygenState` that `generate_rsa_der` keeps alive for the whole keygen call.
    let state = unsafe { EVP_PKEY_CTX_get_app_data(ctx) }.cast::<KeygenState<'_>>();
    if state.is_null() {
        return 0;
    }
    // SAFETY: non-null and valid for the duration of this call (see above); only shared
    // references and atomics are used.
    let state = unsafe { &*state };
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if state.cancel.load(Ordering::SeqCst) {
            return false;
        }
        let step = state.steps.fetch_add(1, Ordering::Relaxed) + 1;
        (state.progress)(step);
        !state.cancel.load(Ordering::SeqCst)
    }));
    match outcome {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => {
            state.callback_failed.store(true, Ordering::SeqCst);
            0
        }
    }
}

/// Plaintext private-key DER held only in locked, wiped-on-drop memory.
pub(crate) struct LockedDer {
    region: LockedRegion,
    len: usize,
}

impl LockedDer {
    /// The DER bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.region.as_slice()[..self.len]
    }
}

/// Generates an RSA key with public exponent 65537 using OpenSSL 3's
/// `EVP_PKEY_generate`, with a callback that reports progress and lets the
/// operator cancel (FR-16).
///
/// Returns the private key as PKCS#1 DER in locked memory. The raw OpenSSL key is
/// freed before returning (`RSA_free` clears its numbers).
pub(crate) fn generate_rsa_der(
    bits: u32,
    cancel: &AtomicBool,
    progress: &(dyn Fn(u64) + Sync),
) -> Result<LockedDer, CryptoError> {
    let bits_c = c_int::try_from(bits).map_err(|_| CryptoError::UnsupportedKeySize { bits })?;
    if cancel.load(Ordering::SeqCst) {
        return Err(CryptoError::Cancelled);
    }
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
    let state = KeygenState {
        cancel,
        progress,
        steps: AtomicU64::new(0),
        callback_failed: AtomicBool::new(false),
    };
    // SAFETY: `state` outlives the `EVP_PKEY_generate` call below; the app data pointer
    // is cleared again right after it, before `state` is dropped.
    unsafe {
        EVP_PKEY_CTX_set_app_data(ctx.0, ptr::from_ref(&state).cast_mut().cast::<c_void>());
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
    // SAFETY: `key.0` is a live key; a null output pointer asks only for the length.
    let len = unsafe { sys::i2d_PrivateKey(key.0, ptr::null_mut()) };
    let len = usize::try_from(len)
        .ok()
        .filter(|len| *len > 0)
        .ok_or_else(|| openssl_error("i2d_PrivateKey (length)"))?;
    let mut region = LockedRegion::new(len)?;
    let mut out = region.as_mut_slice().as_mut_ptr();
    // SAFETY: `region` has at least `len` writable bytes, which is exactly what
    // `i2d_PrivateKey` writes for this key.
    let written = unsafe { sys::i2d_PrivateKey(key.0, &mut out) };
    if usize::try_from(written).ok() != Some(len) {
        return Err(openssl_error("i2d_PrivateKey"));
    }
    Ok(LockedDer { region, len })
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

/// Encrypts an unencrypted PKCS#8 `PrivateKeyInfo` into an `EncryptedPrivateKeyInfo`
/// (DER) using PBES2 with the given KDF and AES-256-CBC, with the caller's salt and IV.
///
/// The output contains only ciphertext and public parameters.
pub(crate) fn encrypt_pkcs8_der(
    private_key_info: &[u8],
    passphrase: &[u8],
    kdf: Pbes2Kdf,
    salt: &[u8; 16],
    iv: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    if passphrase.is_empty() {
        return Err(CryptoError::EmptyPassphrase);
    }
    let der_len = c_len(private_key_info.len(), "private key")?;
    let pass_len = c_len(passphrase.len(), "passphrase")?;
    let mut input = private_key_info.as_ptr();
    // SAFETY: `input` points to `der_len` readable bytes; OpenSSL allocates a new object.
    let p8 = P8InfoGuard::checked(
        unsafe { sys::d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &mut input, c_long::from(der_len)) },
        "d2i_PKCS8_PRIV_KEY_INFO",
    )?;
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
}
