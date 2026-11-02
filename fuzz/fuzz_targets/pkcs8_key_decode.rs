//! Fuzz target 5 (SEC-08): the plaintext PKCS#8 `PrivateKeyInfo` that decryption hands
//! to the key decoder (`d2i_RSAPrivateKey` into the secure heap), without the key
//! derivation in front of it (`pem_pkcs8` pays 600,000 PBKDF2 iterations or a 16 MiB
//! scrypt for every input that gets that far).
//!
//! Someone who can write to a drive can choose the first decrypted block by changing
//! the IV (CBC malleability), so once the operator types the right passphrase this
//! decoder sees attacker-shaped input. The decoded key is then read the way Keystone
//! reads it: its type, size and public key.
//!
//! It does not sign: a signature uses RSA blinding, which makes OpenSSL create its
//! random generator, whose context lives in the secure heap. LeakSanitizer does not
//! scan that memory, so it reports everything the generator owns as leaked (seed
//! `lsan-first-signature.der`, fuzz/README.md).
#![no_main]
#![forbid(unsafe_code)]

use keystone_core::crypto::pkcs8::fuzz_decode_private_key_info;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(key) = fuzz_decode_private_key_info(data) {
        let _ = key.bits();
        let _ = key.public_key_spki_der();
        let _ = key.public_exponent();
    }
});
