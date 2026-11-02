//! Flow B: YubiKey setup and the main intermediate (FR-05, FR-06, FR-07, FR-13 AC6,
//! FR-18, FR-20, FR-22 AC7).
#![forbid(unsafe_code)]

use keystone_core::cert::parse_certificate_pem;
use keystone_core::crl::parse_crl_der;
use keystone_core::crypto::CancelFlag;
use keystone_core::crypto::verify::{VerifyOptions, verify_chain, verify_crl_signature};
use keystone_core::model::CaLevel;
use keystone_core::ops::{
    ExportStatus, MainIntermediateRequest, NoProgress, OpsError, inspect_yubikey,
};
use keystone_core::profile::{CRL_NONE_WARNING, CrlLocation};
use keystone_core::store::{AuditAction, OperationState, YubikeySetupStep};
use keystone_core::token::{
    FirmwareVersion, KeyOrigin, PinPolicy, SIGNING_SLOT, TokenError, TokenSigner, TouchPolicy,
    check_hardening_report, ensure_hardened,
};
use keystone_testkit::names::test_name;
use keystone_testkit::simulator::SlotPreset;
use keystone_testkit::{SimulatedYubiKey, SimulatorConfig};

use crate::support::*;

#[test]
fn flow_b_hardens_the_yubikey_and_creates_the_main_intermediate() {
    // Covers: FR-05 AC3, FR-06 AC1, FR-06 AC2, FR-06 AC3, FR-06 AC4, FR-07 AC1, FR-07 AC2, FR-07 AC3, FR-07 AC5, FR-13 AC6, FR-18 AC1, FR-20 AC1, FR-22 AC7
    let mut test = new_ca("B1");
    let (mut token, controller) = token(20_000_001);
    // FR-05 AC3: serial and firmware shown before any action; defaults detected.
    let inspection = inspect_yubikey(&mut token).unwrap();
    assert_eq!(inspection.device.serial, 20_000_001);
    assert_eq!(inspection.device.firmware, FirmwareVersion::new(5, 7, 4));
    assert!(inspection.firmware_problem.is_none());
    assert!(inspection.needs_new_pin && inspection.needs_new_puk);
    assert!(ensure_hardened(&inspection.credentials).is_err());

    let outcome = run_flow_b(&mut test, &mut token, "B1", true).expect("Flow B");

    // FR-06: hardened, re-verified through a fresh handle.
    let pin = s(PIN);
    let report = token.reopen_and_verify_hardening(&pin).unwrap();
    check_hardening_report(&report).expect("hardened");
    // FR-07 AC1, FR-06 AC4: on-device RSA 4,096 key, PIN and touch "always".
    let slot = token.slot_status(SIGNING_SLOT).unwrap();
    let key = slot.key.expect("key");
    assert_eq!(key.rsa_bits, 4096);
    assert_eq!(key.origin, KeyOrigin::Generated);
    assert_eq!(key.pin_policy, PinPolicy::Always);
    assert_eq!(key.touch_policy, TouchPolicy::Always);

    // FR-07 AC2, AC3: signed by the master, in the slot and on every drive.
    let state = test.ca.state().unwrap();
    let main = state.certificate(outcome.serial).expect("main");
    let master = state.master().unwrap();
    assert_eq!(slot.certificate_der.as_deref(), Some(main.der.as_slice()));
    let pem = same_on_every_drive(&test.drives, &main.certificate_path().to_string());
    assert_eq!(pem, outcome.certificate_pem.as_bytes());
    let (_, info) = parse_certificate_pem(&pem).unwrap();
    assert_eq!(info.ca_level(), Some(CaLevel::MainIntermediate));
    assert_eq!(info.spki_der, key.public_key_der);
    assert_eq!(info.not_after.year() - info.not_before.year(), 10);
    assert_eq!(info.crl_distribution_urls, [MASTER_CRL_URL]);
    verify_chain(
        &main.der,
        &[],
        &[&master.der],
        &[],
        &VerifyOptions::at(test.now),
    )
    .unwrap();
    assert_eq!(
        outcome.fingerprint_text,
        info.fingerprint.to_fingerprint_string()
    );
    // FR-07 AC5: the attestation certificate is stored with the issuance record.
    assert!(
        main.record
            .attestation_pem
            .as_deref()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
    assert_eq!(outcome.yubikey_serial, 20_000_001);

    // FR-13 AC6: the first empty CRL, signed by the YubiKey (one touch), exported.
    assert_eq!(controller.touch_requests(), 1);
    let crl = state.current_crl(outcome.serial).expect("main CRL");
    assert_eq!(crl.info.crl_number, 1);
    assert!(crl.info.revoked.is_empty());
    verify_crl_signature(&crl.der, &key.public_key_der).unwrap();
    let crl_name = format!(
        "main-intermediate-{}-crl-000001.crl",
        &outcome.serial.to_hex()[..16]
    );
    assert_eq!(
        same_on_every_drive(&test.drives, &format!("crls/{crl_name}")),
        crl.der
    );
    match &outcome.export {
        ExportStatus::Written(files) => {
            assert_eq!(files.len(), 1);
            assert_eq!(files[0].name, crl_name);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        (parse_crl_der(
            &std::fs::read(test.export().join("keystone-export").join(&crl_name)).unwrap()
        )
        .unwrap())
        .crl_number,
        1
    );

    // FR-22 AC7: every setup step journaled in order, with the device serial only.
    let journal = test.ca.drive_set().drives()[1]
        .operation_journal(outcome.operation)
        .unwrap()
        .unwrap();
    assert_eq!(journal.state(), OperationState::Completed);
    let steps: Vec<YubikeySetupStep> = journal.yubikey_steps().iter().map(|(s, _)| *s).collect();
    assert_eq!(steps, YubikeySetupStep::ALL);
    assert!(
        journal
            .yubikey_steps()
            .iter()
            .all(|(_, serial)| *serial == 20_000_001)
    );
    // FR-18: the master's CRL address is stored (in the first child) and audited.
    assert_eq!(
        state.crl_location(master.serial()).unwrap(),
        Some(master_crl())
    );
    let log = test.ca.drive_set().audit_log().unwrap();
    let entry = log
        .entries()
        .iter()
        .find(|e| e.action == AuditAction::SetupYubikey)
        .unwrap();
    let note = entry.details.as_ref().unwrap().note.as_deref().unwrap();
    assert!(
        note.contains(MASTER_CRL_URL) && note.contains("20000001"),
        "{note}"
    );
    assert_consistent(&test.ca);
}

#[test]
fn fr05_ac2_old_firmware_is_refused_before_any_change() {
    // Covers: FR-05 AC2
    let mut test = new_ca("B2");
    let mut token = SimulatedYubiKey::new(SimulatorConfig {
        serial: 20_000_002,
        firmware: FirmwareVersion::new(5, 4, 3),
        ..SimulatorConfig::default()
    });
    let time = test.tick();
    let request = MainIntermediateRequest::new(test_name("B2 Main"), Some(master_crl()));
    let error = test
        .ca
        .plan_yubikey_setup(&mut token, &request, time)
        .unwrap_err();
    assert!(
        matches!(error, OpsError::Token(TokenError::FirmwareTooOld { .. })),
        "{error}"
    );
    assert!(error.to_string().contains("5.7.0"));
    assert!(token.credential_status().unwrap().pin_is_default);
}

#[test]
fn fr07_ac4_an_occupied_slot_is_refused_and_only_a_typed_serial_wipes_it() {
    // Covers: FR-07 AC4, SEC-23
    let mut test = new_ca("B3");
    let mut token = SimulatedYubiKey::new(SimulatorConfig {
        serial: 20_000_003,
        slot: SlotPreset::KeyAndCertificate,
        ..SimulatorConfig::default()
    });
    let time = test.tick();
    let request = MainIntermediateRequest::new(test_name("B3 Main"), Some(master_crl()));
    let error = test
        .ca
        .plan_yubikey_setup(&mut token, &request, time)
        .unwrap_err();
    let OpsError::SlotOccupied { description } = &error else {
        panic!("{error}");
    };
    assert!(
        description.contains("device-generated")
            && description.contains("previous slot certificate")
    );
    assert!(error.to_string().contains("serial number"));
    // A wrong typed serial wipes nothing.
    let default_pin = s("123456");
    assert!(
        test.ca
            .wipe_yubikey_slot(&mut token, "20000004", &default_pin)
            .is_err()
    );
    assert!(!token.slot_status(SIGNING_SLOT).unwrap().is_empty());
    test.ca
        .wipe_yubikey_slot(&mut token, "20000003", &default_pin)
        .expect("explicit wipe");
    assert!(token.slot_status(SIGNING_SLOT).unwrap().is_empty());
    let outcome = run_flow_b(&mut test, &mut token, "B3", false).expect("Flow B after wipe");
    // The slot of the active main intermediate is never wiped.
    let error = test
        .ca
        .wipe_yubikey_slot(&mut token, "20000003", &s(PIN))
        .unwrap_err();
    assert!(error.to_string().contains("still valid"), "{error}");
    assert_eq!(
        token.read_signing_certificate().unwrap().as_deref(),
        Some(
            test.ca
                .state()
                .unwrap()
                .certificate(outcome.serial)
                .unwrap()
                .der
                .as_slice()
        )
    );
}

#[test]
fn fr07_ac5_a_failed_attestation_stops_setup_before_the_master_signs() {
    // Covers: FR-07 AC5, SEC-23
    let mut test = new_ca("B4");
    let (mut token, controller) = token(20_000_005);
    controller.set_attested_serial(99_999_999);
    let error = run_flow_b(&mut test, &mut token, "B4", false).unwrap_err();
    let OpsError::Interrupted { operation, cause } = &error else {
        panic!("{error}");
    };
    assert!(
        cause.to_string().contains("setup cannot be completed"),
        "{cause}"
    );
    let state = test.ca.state().unwrap();
    assert!(state.main_intermediates().is_empty());
    assert!(
        state
            .record()
            .certificates()
            .iter()
            .all(|c| c.certificate.level == CaLevel::Master)
    );
    // The key was generated (a persistent change), so the setup stays pending.
    let items = test.ca.recovery_items(Some(&mut token)).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].operation, *operation);
}

#[test]
fn fr04_ac3_a_wrong_master_passphrase_leaves_the_yubikey_unchanged() {
    // Covers: FR-04 AC3, FR-16 AC2
    let mut test = new_ca("B5");
    let (mut token, _) = token(20_000_006);
    let time = test.tick();
    let request = MainIntermediateRequest::new(test_name("B5 Main"), Some(master_crl()));
    let plan = test
        .ca
        .plan_yubikey_setup(&mut token, &request, time)
        .unwrap();
    let (_, wrong) = master_passphrase();
    let wrong = entered(&wrong);
    let trust = token.attestation_trust();
    let error = plan
        .execute(
            &test.ca,
            &mut token,
            &fresh_secrets(&wrong),
            &trust,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("passphrase is wrong"), "{error}");
    let status = token.credential_status().unwrap();
    assert!(status.pin_is_default && status.puk_is_default && status.management_key_is_default);
    assert!(token.slot_status(SIGNING_SLOT).unwrap().is_empty());
    assert_eq!(test.ca.drive_set().drives()[0].journal().unwrap().len(), 1);
    assert_consistent(&test.ca);
}

#[test]
fn fr18_ac1_the_master_crl_address_is_asked_once_and_none_needs_an_explicit_choice() {
    // Covers: FR-18 AC1
    let mut test = new_ca("B6");
    let (mut token, _) = token(20_000_007);
    let time = test.tick();
    let request = MainIntermediateRequest::new(test_name("B6 Main"), None);
    let error = test
        .ca
        .plan_yubikey_setup(&mut token, &request, time)
        .unwrap_err();
    assert!(error.to_string().contains("CRL will be hosted"), "{error}");
    let request =
        MainIntermediateRequest::new(test_name("B6 Main"), Some(CrlLocation::ExplicitlyNone));
    let plan = test
        .ca
        .plan_yubikey_setup(&mut token, &request, time)
        .unwrap();
    assert_eq!(plan.review().warnings, [CRL_NONE_WARNING]);
    assert!(
        plan.review()
            .value("Master CRL address")
            .unwrap()
            .contains("none")
    );
    let master = test.master_entered();
    let trust = token.attestation_trust();
    let outcome = plan
        .execute(
            &test.ca,
            &mut token,
            &fresh_secrets(&master),
            &trust,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    let state = test.ca.state().unwrap();
    let main = state.certificate(outcome.serial).unwrap();
    assert!(!main.info.has_crl_distribution_points);
    assert_eq!(
        state.crl_location(test.master.serial).unwrap(),
        Some(CrlLocation::ExplicitlyNone)
    );
}

#[test]
fn flow_b_is_refused_while_a_main_intermediate_is_active() {
    // Covers: FR-15 AC1 (only Flow E replaces an active main intermediate)
    let (mut test, _token, _) = ca_with_main("B7", 20_000_008);
    let (mut other, _) = token(20_000_009);
    let time = test.tick();
    let request = MainIntermediateRequest::new(test_name("B7 Second"), None);
    let error = test
        .ca
        .plan_yubikey_setup(&mut other, &request, time)
        .unwrap_err();
    assert!(error.to_string().contains("already active"), "{error}");
}

#[test]
fn flow_b_on_a_yubikey_that_was_already_hardened_asks_for_its_current_pin() {
    // Covers: FR-06 AC1, FR-22 AC7
    let mut test = new_ca("B8");
    let (mut token, _) = token(20_000_010);
    keystone_testkit::simulator::harden(&mut token, PIN, PUK).unwrap();
    let inspection = inspect_yubikey(&mut token).unwrap();
    assert!(!inspection.needs_new_pin && !inspection.needs_new_puk);
    let time = test.tick();
    let request = MainIntermediateRequest::new(test_name("B8 Main"), Some(master_crl()));
    let plan = test
        .ca
        .plan_yubikey_setup(&mut token, &request, time)
        .unwrap();
    assert_eq!(
        plan.review().value("YubiKey hardening"),
        Some("already hardened")
    );
    let master = test.master_entered();
    let trust = token.attestation_trust();
    // Offering a new PIN for a YubiKey whose PIN was changed is refused, nothing changes.
    let error = test
        .ca
        .plan_yubikey_setup(&mut token, &request, time)
        .unwrap()
        .execute(
            &test.ca,
            &mut token,
            &fresh_secrets(&master),
            &trust,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err();
    assert!(matches!(error, OpsError::Stopped { .. }), "{error}");
    assert!(error.to_string().contains("current PIN"));
    let outcome = plan
        .execute(
            &test.ca,
            &mut token,
            &current_secrets(Some(&master)),
            &trust,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .expect("Flow B");
    let journal = test.ca.drive_set().drives()[0]
        .operation_journal(outcome.operation)
        .unwrap()
        .unwrap();
    let steps: Vec<YubikeySetupStep> = journal.yubikey_steps().iter().map(|(s, _)| *s).collect();
    assert_eq!(
        steps,
        [
            YubikeySetupStep::KeyGenerated,
            YubikeySetupStep::CertificateWritten
        ]
    );
    assert_consistent(&test.ca);
}

#[test]
fn fr06_ac3_a_management_key_not_stored_pin_protected_stops_setup_before_key_generation() {
    // Covers: FR-06 AC3, SEC-06
    let mut test = new_ca("B9");
    let (mut token, controller) = token(20_000_011);
    controller.fail_next(
        keystone_testkit::simulator::SimOp::SetManagementKey,
        1,
        keystone_testkit::simulator::FaultKind::SilentPartialWrite,
    );
    let error = run_flow_b(&mut test, &mut token, "B9", false).unwrap_err();
    assert!(matches!(error, OpsError::Interrupted { .. }), "{error}");
    assert!(
        error.to_string().contains("could not be confirmed"),
        "{error}"
    );
    assert!(token.slot_status(SIGNING_SLOT).unwrap().is_empty());
    assert!(test.ca.state().unwrap().main_intermediates().is_empty());
}
