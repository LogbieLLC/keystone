//! Fuzz target 1 (SEC-08): PEM and encrypted PKCS#8 parsing, including decryption.
#![no_main]
#![forbid(unsafe_code)]

use std::sync::OnceLock;

use keystone_core::crypto::pkcs8::decrypt_key_pem;
use keystone_core::crypto::secret::SecretString;
use keystone_core::crypto::verify::certificates_pem_to_der;
use libfuzzer_sys::fuzz_target;

/// One locked passphrase for the whole run: allocating locked pages per input would
/// only measure the sanitizer's allocator quarantine, not the parser.
fn passphrase() -> &'static SecretString {
    static PASSPHRASE: OnceLock<SecretString> = OnceLock::new();
    PASSPHRASE.get_or_init(|| {
        SecretString::from_str_copy("keystone fuzz passphrase")
            .expect("locked memory for the fuzz passphrase")
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = decrypt_key_pem(data, passphrase());
    let _ = certificates_pem_to_der(data);
});
