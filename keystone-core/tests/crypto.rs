//! Crypto module tests: key generation, cancel, signatures, encrypted PKCS#8.
//! Test keys come from keystone-testkit (TEST-11); only the FR-02 AC1 test
//! generates a fresh 8,192-bit key.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use keystone_core::crypto::hash::sha384;
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
