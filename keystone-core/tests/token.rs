//! YubiKey rules through the `TokenSigner` trait, run against the simulator
//! (NFR-08): detection, hardening, slot protection, attestation, signing.
#![forbid(unsafe_code)]

use std::time::Duration;

use keystone_core::crypto::hash::sha384;
use keystone_core::crypto::rsa::{inspect_rsa_spki, verify_sha384_pkcs1};
use keystone_core::crypto::secret::SecretString;
use keystone_core::token::{
    AttestationExpectation, AttestationTrust, DEFAULT_PIN, DEFAULT_PUK, FirmwareVersion, KeyOrigin,
    NewPin, NewPuk, PinPolicy, SIGNING_SLOT, SlotAttestation, TokenError, TokenSigner, TouchPolicy,
    WipeConfirmation, check_firmware, check_hardening_report, ensure_hardened, ensure_slot_empty,
    verify_piv_attestation,
};
use keystone_testkit::simulator::{
    FaultKind, SimOp, SlotPreset, TouchBehaviour, attestation_root_der, harden,
};
use keystone_testkit::x509::{
    TestCertSpec, build_test_certificate, cn_name_der, test_ca_extensions,
};
use keystone_testkit::{SimulatedYubiKey, SimulatorConfig};
use time::OffsetDateTime;

const PIN: &str = "Ks#13579";
const PUK: &str = "Ks#86420";

fn s(text: &str) -> SecretString {
    SecretString::from_str_copy(text).unwrap()
}

fn sim(serial: u32) -> SimulatedYubiKey {
    SimulatedYubiKey::new(SimulatorConfig {
        serial,
        ..SimulatorConfig::default()
    })
}

fn hardened_sim(serial: u32) -> SimulatedYubiKey {
    let mut token = sim(serial);
    harden(&mut token, PIN, PUK).unwrap();
    token
}

#[test]
fn fr05_ac3_serial_and_firmware_are_read_first() {
    // Covers: FR-05 AC3, FR-05 AC1
    let mut token = sim(10_000_001);
    let info = token.device_info().unwrap();
    assert_eq!(info.serial, 10_000_001);
    assert_eq!(info.firmware, FirmwareVersion::new(5, 7, 4));
    check_firmware(&info).unwrap();
}

#[test]
fn fr05_ac2_old_firmware_is_refused_with_reason() {
    // Covers: FR-05 AC2
    let mut token = SimulatedYubiKey::new(SimulatorConfig {
        firmware: FirmwareVersion::new(5, 4, 3),
        ..SimulatorConfig::default()
    });
    let error = check_firmware(&token.device_info().unwrap()).unwrap_err();
    assert!(matches!(error, TokenError::FirmwareTooOld { .. }));
    let text = error.to_string();
    assert!(text.contains("5.4.3") && text.contains("5.7.0"), "{text}");
}

#[test]
fn fr06_ac1_factory_defaults_block_progress() {
    // Covers: FR-06 AC1, SEC-06
    let mut token = sim(10_000_002);
    let status = token.credential_status().unwrap();
    assert!(status.pin_is_default && status.puk_is_default && status.management_key_is_default);
    let error = ensure_hardened(&status).unwrap_err().to_string();
    assert!(error.contains("PIN") && error.contains("PUK") && error.contains("management key"));
}

#[test]
fn fr06_ac2_pin_and_puk_change_with_retry_counting() {
    // Covers: FR-06 AC2
    let mut token = sim(10_000_003);
    let new_pin = NewPin::from_entries(&s(PIN), &s(PIN)).unwrap();
    let error = token.change_pin(&s("000000"), &new_pin).unwrap_err();
    assert!(matches!(error, TokenError::WrongPin { retries_left: 2 }));
    token.change_pin(&s(DEFAULT_PIN), &new_pin).unwrap();
    let new_puk = NewPuk::from_entries(&s(PUK), &s(PUK)).unwrap();
    assert!(matches!(
        token.change_puk(&s("00000000"), &new_puk),
        Err(TokenError::WrongPuk { retries_left: 2 })
    ));
    token.change_puk(&s(DEFAULT_PUK), &new_puk).unwrap();
    let status = token.credential_status().unwrap();
    assert!(!status.pin_is_default && !status.puk_is_default);
    assert_eq!(
        status.pin_retries_left, 3,
        "a correct PIN resets the counter"
    );
    // The PIN is entered twice; a mismatch never reaches the token.
    assert!(NewPin::from_entries(&s(PIN), &s("Ks#13578")).is_err());
}

#[test]
fn fr06_pin_blocks_after_three_wrong_attempts() {
    // Covers: FR-06 AC2, SEC-06
    let mut token = hardened_sim(10_000_004);
    let controller = token.controller();
    token.generate_signing_key(&s(PIN)).unwrap();
    for expected in [2u8, 1] {
        assert!(matches!(
            token.sign_sha384_digest(&s("wrong!!"), &[0; 48]),
            Err(TokenError::WrongPin { retries_left }) if retries_left == expected
        ));
        assert_eq!(controller.pin_retries(), expected);
    }
    assert!(matches!(
        token.sign_sha384_digest(&s("wrong!!"), &[0; 48]),
        Err(TokenError::PinBlocked)
    ));
    assert!(matches!(
        token.sign_sha384_digest(&s(PIN), &[0; 48]),
        Err(TokenError::PinBlocked)
    ));
}

#[test]
fn fr06_ac3_random_pin_protected_aes256_management_key_is_reverified() {
    // Covers: FR-06 AC3, SEC-06
    let mut token = hardened_sim(10_000_005);
    let controller = token.controller();
    let status = token.credential_status().unwrap();
    ensure_hardened(&status).unwrap();
    let before = controller.reopen_count();
    let report = token.reopen_and_verify_hardening(&s(PIN)).unwrap();
    assert!(
        controller.reopen_count() > before,
        "verification used a fresh handle"
    );
    check_hardening_report(&report).unwrap();
    assert!(report.management_key_authenticated);
}

#[test]
fn fr06_ac3_silent_partial_management_key_write_is_caught_on_reopen() {
    // Covers: FR-06 AC3
    // Dependencies doc, YubiKey item 5: a setter's success is not proof.
    let mut token = sim(10_000_006);
    token
        .controller()
        .fail_next(SimOp::SetManagementKey, 1, FaultKind::SilentPartialWrite);
    harden(&mut token, PIN, PUK).expect("the setter reports success");
    let report = token.reopen_and_verify_hardening(&s(PIN)).unwrap();
    assert!(matches!(
        check_hardening_report(&report),
        Err(TokenError::HardeningNotConfirmed(_))
    ));
}

#[test]
fn fr06_ac4_fr07_ac1_signing_key_policy_and_size() {
    // Covers: FR-06 AC4, FR-07 AC1
    let mut token = hardened_sim(10_000_007);
    ensure_slot_empty(&token.slot_status(SIGNING_SLOT).unwrap()).unwrap();
    let spki = token.generate_signing_key(&s(PIN)).unwrap();
    let info = inspect_rsa_spki(&spki).unwrap();
    assert_eq!((info.bits, info.public_exponent), (4096, 65_537));
    let key = token.slot_status(SIGNING_SLOT).unwrap().key.unwrap();
    assert_eq!(key.pin_policy, PinPolicy::Always);
    assert_eq!(key.touch_policy, TouchPolicy::Always);
    assert_eq!(key.origin, KeyOrigin::Generated);
    assert_eq!(key.public_key_der, spki);
}

#[test]
fn fr07_ac4_occupied_slot_is_detected_from_key_or_certificate() {
    // Covers: FR-07 AC4, FR-22 AC5
    for (preset, has_key, has_cert) in [
        (SlotPreset::KeyWithoutCertificate, true, false),
        (SlotPreset::KeyAndCertificate, true, true),
        (SlotPreset::CertificateOnly, false, true),
    ] {
        let mut token = SimulatedYubiKey::new(SimulatorConfig {
            slot: preset,
            ..SimulatorConfig::default()
        });
        let status = token.slot_status(SIGNING_SLOT).unwrap();
        assert_eq!(status.key.is_some(), has_key, "{preset:?}");
        assert_eq!(status.certificate_der.is_some(), has_cert, "{preset:?}");
        let error = ensure_slot_empty(&status).unwrap_err();
        assert!(matches!(error, TokenError::SlotOccupied { .. }));
        if has_cert {
            assert!(
                error
                    .to_string()
                    .contains("KEYSTONE TEST previous slot certificate"),
                "{error}"
            );
        }
    }
}

#[test]
fn fr07_ac4_wipe_needs_the_typed_serial() {
    // Covers: FR-07 AC4
    let mut token = SimulatedYubiKey::new(SimulatorConfig {
        serial: 10_000_008,
        slot: SlotPreset::KeyAndCertificate,
        ..SimulatorConfig::default()
    });
    harden(&mut token, PIN, PUK).unwrap();
    let device = token.device_info().unwrap();
    assert!(matches!(
        WipeConfirmation::new("10000009", &device),
        Err(TokenError::WipeConfirmationMismatch)
    ));
    // A confirmation made for another device is refused by the token itself.
    let other = sim(10_000_009).device_info().unwrap();
    let foreign = WipeConfirmation::new("10000009", &other).unwrap();
    assert!(matches!(
        token.wipe_slot(SIGNING_SLOT, &foreign, &s(PIN)),
        Err(TokenError::WipeConfirmationMismatch)
    ));
    assert!(
        !token.slot_status(SIGNING_SLOT).unwrap().is_empty(),
        "nothing wiped"
    );
    let confirmation = WipeConfirmation::new("10000008", &device).unwrap();
    token
        .wipe_slot(SIGNING_SLOT, &confirmation, &s(PIN))
        .unwrap();
    assert!(token.slot_status(SIGNING_SLOT).unwrap().is_empty());
}

fn attested(serial: u32) -> (SimulatedYubiKey, Vec<u8>, SlotAttestation) {
    let mut token = hardened_sim(serial);
    let spki = token.generate_signing_key(&s(PIN)).unwrap();
    let attestation = token.attest_signing_key().unwrap();
    (token, spki, attestation)
}

fn verify(
    token: &mut SimulatedYubiKey,
    spki: &[u8],
    attestation: &SlotAttestation,
) -> Result<keystone_core::token::VerifiedAttestation, TokenError> {
    let device = token.device_info().unwrap();
    verify_piv_attestation(
        &token.attestation_trust(),
        attestation,
        &AttestationExpectation {
            device: &device,
            public_key_der: spki,
        },
        OffsetDateTime::now_utc(),
    )
}

#[test]
fn fr07_ac5_valid_attestation_verifies() {
    // Covers: FR-07 AC5, SEC-23
    let (mut token, spki, attestation) = attested(10_000_010);
    let verified = verify(&mut token, &spki, &attestation).unwrap();
    assert_eq!(verified.serial, 10_000_010);
    assert_eq!(verified.pin_policy, PinPolicy::Always);
    assert_eq!(verified.touch_policy, TouchPolicy::Always);
    assert_eq!(verified.firmware, Some(FirmwareVersion::new(5, 7, 4)));
    assert_eq!(
        verified.slot_certificate_der,
        attestation.slot_certificate_der
    );
}

#[test]
fn fr07_ac5_tampered_attestation_fails() {
    // Covers: FR-07 AC5, SEC-23
    let (mut token, spki, attestation) = attested(10_000_011);
    let mut tampered = attestation.clone();
    let last = tampered.slot_certificate_der.len() - 1;
    tampered.slot_certificate_der[last] ^= 0x01;
    assert!(matches!(
        verify(&mut token, &spki, &tampered),
        Err(TokenError::Attestation(_))
    ));
    let mut garbage = attestation.clone();
    garbage.f9_certificate_der.truncate(20);
    assert!(verify(&mut token, &spki, &garbage).is_err());
}

#[test]
fn fr07_ac5_wrong_serial_fails() {
    // Covers: FR-07 AC5, SEC-23
    let mut token = hardened_sim(10_000_012);
    token.controller().set_attested_serial(99_999_999);
    let spki = token.generate_signing_key(&s(PIN)).unwrap();
    let attestation = token.attest_signing_key().unwrap();
    let error = verify(&mut token, &spki, &attestation).unwrap_err();
    assert!(error.to_string().contains("99999999"), "{error}");
}

#[test]
fn fr07_ac5_wrong_policy_fails() {
    // Covers: FR-07 AC5, FR-06 AC4, SEC-23
    for (pin, touch) in [
        (PinPolicy::Once, TouchPolicy::Always),
        (PinPolicy::Always, TouchPolicy::Cached),
        (PinPolicy::Never, TouchPolicy::Never),
    ] {
        let mut token = hardened_sim(10_000_013);
        token.controller().set_keygen_policy(pin, touch);
        let spki = token.generate_signing_key(&s(PIN)).unwrap();
        let attestation = token.attest_signing_key().unwrap();
        let error = verify(&mut token, &spki, &attestation).unwrap_err();
        assert!(error.to_string().contains("must be Always"), "{error}");
    }
}

#[test]
fn fr07_ac5_mismatched_key_fails() {
    // Covers: FR-07 AC5, SEC-23
    let (mut token, _, attestation) = attested(10_000_014);
    let other = keystone_testkit::keys::rsa4096(5)
        .public_key_spki_der()
        .unwrap();
    let error = verify(&mut token, &other, &attestation).unwrap_err();
    assert!(error.to_string().contains("not the key"), "{error}");
}

#[test]
fn fr07_ac5_other_devices_f9_or_untrusted_root_fails() {
    // Covers: FR-07 AC5, SEC-23
    let (mut token, spki, attestation) = attested(10_000_015);
    let (_, _, other) = attested(10_000_016);
    let mixed = SlotAttestation {
        slot_certificate_der: attestation.slot_certificate_der.clone(),
        f9_certificate_der: other.f9_certificate_der,
    };
    assert!(verify(&mut token, &spki, &mixed).is_err());
    // Trusting a different self-signed root, or the F9 certificate itself.
    let device = token.device_info().unwrap();
    let other_key = keystone_testkit::keys::rsa2048(3);
    let other_spki = other_key.public_key_spki_der().unwrap();
    let now = OffsetDateTime::now_utc();
    let other_root = build_test_certificate(&TestCertSpec {
        subject_der: cn_name_der("KEYSTONE TEST Attestation Root"),
        subject_public_key_der: other_spki.clone(),
        issuer: None,
        self_key: Some(other_key),
        not_before: now - time::Duration::days(1),
        not_after: now + time::Duration::days(365),
        extensions: test_ca_extensions(&other_spki, None),
    });
    assert_ne!(other_root, attestation_root_der());
    for trust in [
        AttestationTrust::new(vec![other_root], vec![]).unwrap(),
        AttestationTrust::new(vec![attestation.f9_certificate_der.clone()], vec![]).unwrap(),
    ] {
        let result = verify_piv_attestation(
            &trust,
            &attestation,
            &AttestationExpectation {
                device: &device,
                public_key_der: &spki,
            },
            now,
        );
        assert!(matches!(result, Err(TokenError::Attestation(_))));
    }
}

#[test]
fn fr07_ac5_imported_key_cannot_be_attested() {
    // Covers: FR-07 AC5
    let mut token = hardened_sim(10_000_017);
    token.controller().import_key_into_slot();
    assert!(token.attest_signing_key().is_err());
}

#[test]
fn fr08_ac2_every_signature_needs_pin_and_touch() {
    // Covers: FR-08 AC2, FR-06 AC4
    let mut token = hardened_sim(10_000_018);
    let controller = token.controller();
    let spki = token.generate_signing_key(&s(PIN)).unwrap();
    let message = b"KEYSTONE TEST tbs";
    let digest = sha384(message);
    let signature = token.sign_sha384_digest(&s(PIN), &digest).unwrap();
    verify_sha384_pkcs1(&spki, message, &signature).unwrap();
    assert_eq!(controller.touch_requests(), 1);
    token.sign_sha384_digest(&s(PIN), &digest).unwrap();
    assert_eq!(controller.touch_requests(), 2, "touch on every signature");
    assert!(matches!(
        token.sign_sha384_digest(&s("Ks#00000"), &digest),
        Err(TokenError::WrongPin { .. })
    ));
    controller.set_touch(TouchBehaviour::NoTouch);
    assert!(matches!(
        token.sign_sha384_digest(&s(PIN), &digest),
        Err(TokenError::TouchTimeout)
    ));
    assert_eq!(controller.signature_count(), 2);
}

#[test]
fn simulator_fault_injection_removal_and_failures() {
    // Covers: NFR-08
    let mut token = hardened_sim(10_000_019);
    let controller = token.controller();
    controller.remove();
    assert!(matches!(token.device_info(), Err(TokenError::NotPresent)));
    controller.reinsert();
    token.device_info().unwrap();

    controller.fail_next(SimOp::GenerateKey, 1, FaultKind::FailBefore);
    assert!(matches!(
        token.generate_signing_key(&s(PIN)),
        Err(TokenError::Communication(_))
    ));
    assert!(
        token.slot_status(SIGNING_SLOT).unwrap().key.is_none(),
        "no effect before"
    );

    controller.fail_next(SimOp::GenerateKey, 1, FaultKind::RemoveAfter);
    assert!(matches!(
        token.generate_signing_key(&s(PIN)),
        Err(TokenError::Removed)
    ));
    assert!(!controller.is_present());
    controller.reinsert();
    assert!(
        token.slot_status(SIGNING_SLOT).unwrap().key.is_some(),
        "the key was generated"
    );

    controller.fail_next(SimOp::Sign, 2, FaultKind::FailAfter);
    assert!(token.sign_sha384_digest(&s(PIN), &[1; 48]).is_err());
    assert!(token.sign_sha384_digest(&s(PIN), &[1; 48]).is_err());
    token.sign_sha384_digest(&s(PIN), &[1; 48]).unwrap();

    // A slow operation during which the device is pulled out.
    controller.set_delay(SimOp::Attest, Duration::from_millis(300));
    let remover = token.controller();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        remover.remove();
    });
    assert!(matches!(
        token.attest_signing_key(),
        Err(TokenError::Removed)
    ));
    handle.join().unwrap();

    // Reopening sees the same device state.
    controller.reinsert();
    let mut second = token.reopen();
    assert_eq!(
        second.slot_status(SIGNING_SLOT).unwrap(),
        token.slot_status(SIGNING_SLOT).unwrap()
    );
}

#[test]
fn sec07_pins_never_appear_in_debug_or_errors() {
    // Covers: SEC-07
    let pin = NewPin::from_entries(&s(PIN), &s(PIN)).unwrap();
    let puk = NewPuk::from_entries(&s(PUK), &s(PUK)).unwrap();
    let mut token = hardened_sim(10_000_021);
    token.generate_signing_key(&s(PIN)).unwrap();
    let wrong = "Zz#99999";
    let error = token.sign_sha384_digest(&s(wrong), &[0; 48]).unwrap_err();
    let pin_secret = s(PIN);
    let signer = keystone_core::token::TokenCaSigner::new(&mut token, &pin_secret);
    let shown = [
        format!("{pin:?}"),
        format!("{puk:?}"),
        format!("{signer:?}"),
        format!("{error:?}"),
        error.to_string(),
        format!("{:?}", s(PIN)),
    ];
    for text in shown {
        assert!(
            !text.contains(PIN) && !text.contains(PUK) && !text.contains(wrong),
            "{text}"
        );
    }
}

#[test]
fn token_is_object_safe_and_send() {
    // Covers: NFR-08
    fn assert_send<T: Send>(_: &T) {}
    let token: Box<dyn TokenSigner> = Box::new(sim(10_000_020));
    assert_send(&token);
    let moved = std::thread::spawn(move || {
        let mut token = token;
        token.device_info().unwrap().serial
    });
    assert_eq!(moved.join().unwrap(), 10_000_020);
}
