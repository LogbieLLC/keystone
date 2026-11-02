//! Crypto module tests: key generation, cancel, signatures, encrypted PKCS#8.
//! Test keys come from keystone-testkit (TEST-11); only the FR-02 AC1 test
//! generates a fresh 8,192-bit key.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use keystone_core::crypto::hash::sha384;
use keystone_core::crypto::pem::{LABEL_ENCRYPTED_PRIVATE_KEY, decode_one, encode};
use keystone_core::crypto::pkcs8::{
    contains_plaintext_private_key, decrypt_key_pem, encrypt_master_key_pem, encrypt_sub_key_pem,
};
use keystone_core::crypto::rsa::{inspect_rsa_spki, verify_sha384_pkcs1};
use keystone_core::crypto::secret::SecretString;
use keystone_core::crypto::{CancelFlag, CryptoError, generate_rsa};
use keystone_core::limits::MAX_PEM_BYTES;
use keystone_testkit::keys;

fn passphrase(text: &str) -> SecretString {
    SecretString::from_str_copy(text).expect("locked memory")
}

#[test]
fn fr02_ac1_generates_rsa_8192_with_exponent_65537() {
    // Covers: FR-02 AC1
    let steps = AtomicU64::new(0);
    let key = generate_rsa(8192, &CancelFlag::new(), &|step| {
        steps.store(step, Ordering::Relaxed);
    })
    .expect("RSA 8192 generation");
    assert_eq!(key.bits(), 8192);
    assert_eq!(key.public_exponent().unwrap(), 65_537);
    let info = inspect_rsa_spki(&key.public_key_spki_der().unwrap()).unwrap();
    assert_eq!(info.bits, 8192);
    assert_eq!(info.public_exponent, 65_537);
    assert!(
        steps.load(Ordering::Relaxed) > 0,
        "progress was reported (NFR-03)"
    );
}

#[test]
fn fr16_cancel_before_start_produces_nothing() {
    // Covers: FR-16 AC2
    let cancel = CancelFlag::new();
    cancel.cancel();
    let result = generate_rsa(8192, &cancel, &|_| {});
    assert!(matches!(result, Err(CryptoError::Cancelled)));
}

#[test]
fn fr16_cancel_during_rsa_8192_generation_stops_it() {
    // Covers: FR-16 AC2, NFR-03
    let cancel = CancelFlag::new();
    let worker_cancel = cancel.clone();
    let started = Instant::now();
    let worker = std::thread::spawn(move || {
        // Cancel from inside the progress callback after a few steps, which is the
        // same as the GUI pressing Cancel while generation runs.
        generate_rsa(8192, &worker_cancel, &|step| {
            if step == 3 {
                worker_cancel.cancel();
            }
        })
    });
    let result = worker.join().expect("worker thread");
    assert!(matches!(result, Err(CryptoError::Cancelled)), "{result:?}");
    assert!(cancel.is_cancelled());
    assert!(started.elapsed() < Duration::from_secs(60));
    // The next generation on this thread is not affected by the aborted one.
    let key = generate_rsa(2048, &CancelFlag::new(), &|_| {}).expect("generation after cancel");
    assert_eq!(key.bits(), 2048);
}

#[test]
fn fr16_cancel_from_another_thread() {
    // Covers: FR-16 AC2
    let cancel = CancelFlag::new();
    let worker_cancel = cancel.clone();
    let worker = std::thread::spawn(move || generate_rsa(8192, &worker_cancel, &|_| {}));
    std::thread::sleep(Duration::from_millis(200));
    cancel.cancel();
    let result = worker.join().expect("worker thread");
    assert!(matches!(result, Err(CryptoError::Cancelled)), "{result:?}");
}

#[test]
fn fr16_panicking_progress_callback_never_unwinds_into_openssl() {
    // Covers: FR-16 AC2
    let result = generate_rsa(2048, &CancelFlag::new(), &|_| {
        panic!("KEYSTONE TEST progress failure")
    });
    assert!(matches!(result, Err(CryptoError::OpenSsl(_))), "{result:?}");
    // OpenSSL's state is clean afterwards.
    generate_rsa(2048, &CancelFlag::new(), &|_| {}).expect("generation after a failed callback");
}

#[test]
fn rejects_unsupported_key_sizes() {
    for bits in [0, 1024, 3000, 16384] {
        assert!(matches!(
            generate_rsa(bits, &CancelFlag::new(), &|_| {}),
            Err(CryptoError::UnsupportedKeySize { .. })
        ));
    }
}

#[test]
fn sha384_signatures_verify_and_digest_signing_matches() {
    let key = keys::rsa4096(0);
    let spki = key.public_key_spki_der().unwrap();
    let message = b"KEYSTONE TEST message";
    let signature = key.sign_sha384_pkcs1(message).unwrap();
    assert_eq!(signature.len(), 512);
    verify_sha384_pkcs1(&spki, message, &signature).expect("valid signature");
    // PKCS#1 v1.5 is deterministic: signing the digest gives the same signature.
    let from_digest = key.sign_sha384_digest(&sha384(message)).unwrap();
    assert_eq!(from_digest, signature);
    let mut tampered = signature.clone();
    tampered[10] ^= 1;
    assert!(matches!(
        verify_sha384_pkcs1(&spki, message, &tampered),
        Err(CryptoError::BadSignature(_))
    ));
    let other = keys::rsa4096(1).public_key_spki_der().unwrap();
    assert!(verify_sha384_pkcs1(&other, message, &signature).is_err());
}

#[test]
fn sec07_private_key_debug_is_redacted() {
    // Covers: SEC-07
    let key = keys::rsa2048(0);
    let shown = format!("{key:?}");
    assert!(shown.contains("REDACTED"));
    assert!(
        shown.len() < 64,
        "Debug output must not contain key material: {shown}"
    );
}

#[test]
fn fr04_ac1_master_key_round_trip_with_scrypt() {
    // Covers: FR-04 AC1, SEC-04
    let key = keys::master(0);
    let words = passphrase("KEYSTONE TEST alpha bravo charlie delta echo foxtrot golf hotel");
    let pem = encrypt_master_key_pem(key, &words).unwrap();
    assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"));
    assert!(!contains_plaintext_private_key(pem.as_bytes()));
    let back = decrypt_key_pem(pem.as_bytes(), &words).unwrap();
    assert_eq!(back.bits(), 8192);
    assert_eq!(
        back.public_key_spki_der().unwrap(),
        key.public_key_spki_der().unwrap()
    );
    // A new random salt and IV every time.
    let again = encrypt_master_key_pem(key, &words).unwrap();
    assert_ne!(pem, again);
}

#[test]
fn fr04_ac1_sub_key_round_trip_with_pbkdf2() {
    // Covers: FR-04 AC1, SEC-04, SEC-15
    let key = keys::rsa4096(2);
    let words = passphrase("KEYSTONE TEST india juliet kilo lima mike november oscar papa");
    let pem = encrypt_sub_key_pem(key, &words).unwrap();
    assert!(!contains_plaintext_private_key(pem.as_bytes()));
    let back = decrypt_key_pem(pem.as_bytes(), &words).unwrap();
    assert_eq!(
        back.public_key_spki_der().unwrap(),
        key.public_key_spki_der().unwrap()
    );
}

#[test]
fn fr04_ac3_wrong_passphrase_is_a_clear_error_with_no_output() {
    // Covers: FR-04 AC3
    let key = keys::rsa4096(2);
    let right = passphrase("KEYSTONE TEST right words");
    let wrong = passphrase("KEYSTONE TEST wrong words");
    let pem = encrypt_sub_key_pem(key, &right).unwrap();
    let error = decrypt_key_pem(pem.as_bytes(), &wrong).unwrap_err();
    assert!(matches!(error, CryptoError::WrongPassphrase));
    let message = error.to_string();
    assert!(message.contains("passphrase is wrong"), "{message}");
    assert!(
        !message.contains("wrong words"),
        "the passphrase is never echoed"
    );
    assert!(matches!(
        decrypt_key_pem(pem.as_bytes(), &passphrase("")),
        Err(CryptoError::WrongPassphrase)
    ));
    let master_pem = encrypt_master_key_pem(keys::master(0), &right).unwrap();
    assert!(matches!(
        decrypt_key_pem(master_pem.as_bytes(), &wrong),
        Err(CryptoError::WrongPassphrase)
    ));
}

#[test]
fn sec07_passphrase_reaches_openssl_with_explicit_length_and_a_nul_byte_never_panics() {
    // Covers: SEC-07, FR-04 AC3
    // The passphrase goes from its locked buffer to PKCS8_decrypt as a pointer and an
    // explicit length; no C-string copy is made, so a NUL byte is just another byte
    // (the old path copied it into an unwiped CString and panicked on a NUL).
    let key = keys::rsa2048(1);
    let with_nul = passphrase("KEYSTONE TEST\0words");
    let pem = encrypt_sub_key_pem(key, &with_nul).expect("encrypt and read back");
    let back = decrypt_key_pem(pem.as_bytes(), &with_nul).expect("decrypt");
    assert_eq!(
        back.public_key_spki_der().unwrap(),
        key.public_key_spki_der().unwrap()
    );
    // Everything after the NUL counts: the prefix is a different passphrase.
    assert!(matches!(
        decrypt_key_pem(pem.as_bytes(), &passphrase("KEYSTONE TEST")),
        Err(CryptoError::WrongPassphrase)
    ));
    let plain = encrypt_master_key_pem(keys::rsa2048(1), &passphrase("KEYSTONE TEST words"))
        .expect("encrypt");
    assert!(matches!(
        decrypt_key_pem(plain.as_bytes(), &passphrase("KEYSTONE TEST\0")),
        Err(CryptoError::WrongPassphrase)
    ));
}

/// Re-encrypts with `encrypt` until the byte pattern `from` occurs exactly once in
/// the key file's AlgorithmIdentifier (the random salt and IV could contain it too),
/// then replaces it with `to` (same length) and returns the tampered PEM.
fn with_tampered_parameters(encrypt: &dyn Fn() -> String, from: &[u8], to: &[u8]) -> String {
    assert_eq!(from.len(), to.len());
    for _ in 0..8 {
        let pem = encrypt();
        let mut der =
            decode_one(pem.as_bytes(), LABEL_ENCRYPTED_PRIVATE_KEY, MAX_PEM_BYTES).expect("PEM");
        // EncryptedPrivateKeyInfo ::= SEQUENCE (4-byte header) { AlgorithmIdentifier, .. }
        assert_eq!((der[0], der[1], der[4]), (0x30, 0x82, 0x30));
        let algorithm_end = 6 + usize::from(der[5]);
        let found: Vec<usize> = der[..algorithm_end]
            .windows(from.len())
            .enumerate()
            .filter(|(_, window)| *window == from)
            .map(|(at, _)| at)
            .collect();
        if let [at] = found[..] {
            der[at..at + to.len()].copy_from_slice(to);
            return encode(LABEL_ENCRYPTED_PRIVATE_KEY, &der);
        }
    }
    panic!("pattern {from:02x?} not found exactly once");
}

fn assert_refused_fast(pem: &str, words: &SecretString, expected_detail: &str) {
    let started = Instant::now();
    let error = decrypt_key_pem(pem.as_bytes(), words).unwrap_err();
    let elapsed = started.elapsed();
    assert!(
        matches!(error, CryptoError::UnsupportedKeyEncryption(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(message.contains(expected_detail), "{message}");
    assert!(
        message.contains("PBKDF2-HMAC-SHA256") && message.contains("scrypt"),
        "the error says what Keystone accepts: {message}"
    );
    // Refused before any key derivation: the hostile file would take about 6 s.
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
}

#[test]
fn sec08_tampered_kdf_parameters_are_refused_before_decrypting() {
    // Covers: SEC-08, FR-04 AC1, FR-04 AC3
    // A file whose KDF cost was raised would otherwise hang decryption with no way
    // to cancel (2^31 PBKDF2 iterations take about 25 minutes). Only the exact two
    // parameter sets Keystone writes are accepted.
    let key = keys::rsa2048(1);
    let words = passphrase("KEYSTONE TEST kdf words");
    let sub = || encrypt_sub_key_pem(key, &words).expect("encrypt");
    let master = || encrypt_master_key_pem(key, &words).expect("encrypt");

    // PBKDF2: iteration count 600,000 (0x0927C0) changed to 8,388,607 and to 600,001.
    let hostile = with_tampered_parameters(
        &sub,
        &[0x02, 0x03, 0x09, 0x27, 0xC0],
        &[0x02, 0x03, 0x7F, 0xFF, 0xFF],
    );
    assert_refused_fast(&hostile, &words, "8388607");
    let off_by_one = with_tampered_parameters(
        &sub,
        &[0x02, 0x03, 0x09, 0x27, 0xC0],
        &[0x02, 0x03, 0x09, 0x27, 0xC1],
    );
    assert_refused_fast(&off_by_one, &words, "600001");
    // PBKDF2 PRF hmacWithSHA256 changed to hmacWithSHA512.
    let prf = with_tampered_parameters(
        &sub,
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09],
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B],
    );
    assert_refused_fast(&prf, &words, "PRF");
    // AES-256-CBC changed to AES-128-CBC.
    let aes = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01];
    let cipher = with_tampered_parameters(
        &master,
        &[&aes[..], &[0x2A]].concat(),
        &[&aes[..], &[0x02]].concat(),
    );
    assert_refused_fast(&cipher, &words, "cipher");
    // scrypt: N = 2^14 changed to 2^13; r = 8 changed to 16; p = 1 changed to 2.
    let n = with_tampered_parameters(
        &master,
        &[0x02, 0x02, 0x40, 0x00],
        &[0x02, 0x02, 0x20, 0x00],
    );
    assert_refused_fast(&n, &words, "8192");
    let r = with_tampered_parameters(&master, &[0x02, 0x01, 0x08], &[0x02, 0x01, 0x10]);
    assert_refused_fast(&r, &words, "r = 16");
    let p = with_tampered_parameters(
        &master,
        &[0x02, 0x01, 0x01, 0x30],
        &[0x02, 0x01, 0x02, 0x30],
    );
    assert_refused_fast(&p, &words, "p = 2");
    // The untampered files still decrypt.
    decrypt_key_pem(sub().as_bytes(), &words).expect("Keystone's PBKDF2 parameters");
    decrypt_key_pem(master().as_bytes(), &words).expect("Keystone's scrypt parameters");
}

#[test]
fn sec08_malformed_encryption_structures_are_refused() {
    // Covers: SEC-08, FR-04 AC3
    let words = passphrase("KEYSTONE TEST kdf words");
    let pem = encrypt_sub_key_pem(keys::rsa2048(1), &words).expect("encrypt");
    let der = decode_one(pem.as_bytes(), LABEL_ENCRYPTED_PRIVATE_KEY, MAX_PEM_BYTES).unwrap();
    // Truncated, trailing data, wrong outer tag, and an empty structure.
    let mut trailing = der.clone();
    trailing.push(0);
    let mut wrong_tag = der.clone();
    wrong_tag[0] = 0x31;
    for bad in [
        der[..der.len() - 1].to_vec(),
        trailing,
        wrong_tag,
        vec![0x30, 0x00],
    ] {
        let error = decrypt_key_pem(encode(LABEL_ENCRYPTED_PRIVATE_KEY, &bad).as_bytes(), &words)
            .unwrap_err();
        assert!(matches!(error, CryptoError::Der(_)), "{error:?}");
    }
}

#[test]
fn fr04_refuses_empty_passphrase_plaintext_keys_and_oversized_files() {
    // Covers: FR-04 AC1, SEC-04, SEC-08
    let key = keys::rsa2048(1);
    assert!(matches!(
        encrypt_sub_key_pem(key, &passphrase("")),
        Err(CryptoError::EmptyPassphrase)
    ));
    let plaintext = "-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n";
    assert!(matches!(
        decrypt_key_pem(plaintext.as_bytes(), &passphrase("x")),
        Err(CryptoError::NotEncrypted)
    ));
    let huge = vec![b'A'; MAX_PEM_BYTES + 1];
    assert!(matches!(
        decrypt_key_pem(&huge, &passphrase("x")),
        Err(CryptoError::InputTooLarge { .. })
    ));
    let pem = encrypt_sub_key_pem(key, &passphrase("KEYSTONE TEST words")).unwrap();
    let damaged = pem.replacen("MII", "MIJ", 1);
    assert!(decrypt_key_pem(damaged.as_bytes(), &passphrase("KEYSTONE TEST words")).is_err());
}
