//! Recovery after an interruption (FR-22 AC2 to AC5, AC7, AC8, FR-16 AC2).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use keystone_core::crypto::CancelFlag;
use keystone_core::crypto::pkcs8::decrypt_key_pem;
use keystone_core::model::RevocationReason;
use keystone_core::ops::testing::{self, FaultPoint};
use keystone_core::ops::{
    Blocker, Ca, CrlPlanKind, IssuerUnlock, MainIntermediateRequest, NoProgress, OpsError,
    RecoveryAction, RecoverySecrets,
};
use keystone_core::store::{CertStatus, RecordSource, YubikeySetupStep};
use keystone_core::token::{SIGNING_SLOT, TokenSigner, check_hardening_report};
use keystone_testkit::SimulatedYubiKey;
use keystone_testkit::TestDrives;
use keystone_testkit::keys;
use keystone_testkit::names::test_name;
use keystone_testkit::simulator::{FaultKind, SimOp};

use crate::support::*;

fn injected(error: OpsError) {
    assert!(matches!(error, OpsError::InjectedFault(_)), "{error}");
}

#[test]
fn regression_the_recovery_screen_opens_with_an_absent_yubikey() {
    // Covers: FR-22 AC8, FR-15 AC1
    // Regression: recovery_items failed with "no YubiKey found" when the connected
    // YubiKey handle was removed, which blocked recovery during Flow E.
    let (mut test, mut token, controller) = ca_with_main("R0", 70_000_000);
    crash_flow_c(&mut test, &mut token, FaultPoint::BeforeSigning);
    controller.remove();
    let items = test.ca.recovery_items(Some(&mut token)).unwrap();
    assert_eq!(items.len(), 1);
    assert!(items[0].yubikey.is_none());
    assert_eq!(items[0].actions[0].action, RecoveryAction::Abandon);
}

/// Flow C stopped at `point`; returns the sub passphrase words.
fn crash_flow_c(test: &mut TestCa, token: &mut SimulatedYubiKey, point: FaultPoint) -> String {
    let (plan, passphrase, words) = plan_flow_c(test, "R").unwrap();
    testing::supply_generated_key(keys::rsa4096(1));
    testing::arm_fault(point);
    injected(
        plan.execute(
            &test.ca,
            token,
            &s(PIN),
            &passphrase,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err(),
    );
    test.reopen();
    words
}

fn only_action(test: &mut TestCa, token: Option<&mut SimulatedYubiKey>) -> RecoveryAction {
    let items = test
        .ca
        .recovery_items(token.map(|t| t as &mut dyn TokenSigner))
        .unwrap();
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0].actions.len(), 1, "{:?}", items[0]);
    items[0].actions[0].action.clone()
}

#[test]
fn fr22_ac4_an_operation_stopped_before_signing_is_abandoned_and_its_serial_kept() {
    // Covers: FR-22 AC4, FR-22 AC6, FR-10 AC2
    let (mut test, mut token, _) = ca_with_main("R1", 70_000_001);
    crash_flow_c(&mut test, &mut token, FaultPoint::BeforeSigning);
    let items = test.ca.recovery_items(None).unwrap();
    let item = &items[0];
    assert_eq!(item.actions.len(), 1);
    assert_eq!(item.actions[0].action, RecoveryAction::Abandon);
    assert!(
        item.actions[0]
            .description
            .contains("serial number reserved")
    );
    assert_eq!(item.drives.len(), 2);
    let reserved = item.planned_serials[0];
    assert_eq!(
        recover_all(&mut test, None, "R1"),
        [RecoveryAction::Abandon]
    );
    assert_no_lost_record(&test.ca);
    assert!(
        test.ca
            .drive_set()
            .known_serials()
            .unwrap()
            .contains(&reserved)
    );
    assert!(test.ca.state().unwrap().certificate(reserved).is_none());
    // The CA signs again afterwards.
    run_flow_c(&mut test, &mut token, "R1 after", 2, false).unwrap();
}

#[test]
fn fr22_ac3_a_certificate_signed_but_never_staged_is_rebuilt_from_the_journal() {
    // Covers: FR-22 AC3, FR-22 AC4, FR-22 AC2, FR-09 AC1
    let (mut test, mut token, _) = ca_with_main("R2", 70_000_002);
    let words = crash_flow_c(&mut test, &mut token, FaultPoint::AfterSignedRecorded);
    // FR-22 AC3: the signed certificate is in the record even though the operation
    // never finished.
    let record = test.ca.drive_set().issuance_record().unwrap();
    let journal_only: Vec<_> = record
        .certificates()
        .iter()
        .filter(|c| c.source == RecordSource::JournalOnly)
        .collect();
    assert_eq!(journal_only.len(), 1);
    let serial = journal_only[0].certificate.serial;
    let operation = test.ca.recovery_items(None).unwrap()[0].operation;
    // FR-22 AC2: nothing of it can be exported before its completed entry exists.
    test.now += time::Duration::minutes(1);
    let time = confirmed(&test.ca, test.now);
    assert!(
        test.ca
            .export_operation(operation, test.export(), time)
            .is_err()
    );
    let action = only_action(&mut test, None);
    assert_eq!(
        action,
        RecoveryAction::RebuildFromJournal {
            needs_master_passphrase: false
        }
    );
    recover_all(&mut test, None, "R2");
    assert_no_lost_record(&test.ca);
    let state = test.ca.state().unwrap();
    let sub = state
        .certificate(serial)
        .expect("sub recorded from its record file");
    let stem = keystone_core::ops::StoredCert::certificate_path(sub).to_string();
    let stem = stem
        .trim_start_matches("certs/")
        .trim_end_matches(".crt")
        .to_owned();
    let key = same_on_every_drive(&test.drives, &format!("keys/{stem}.key"));
    let decrypted = decrypt_key_pem(&key, entered(&words).secret()).unwrap();
    assert_eq!(decrypted.public_key_spki_der().unwrap(), sub.info.spki_der);
    same_on_every_drive(&test.drives, &format!("certs/{stem}-chain.pem"));
    // Exported only now.
    test.now += time::Duration::minutes(1);
    let time = confirmed(&test.ca, test.now);
    assert_eq!(
        test.ca
            .export_operation(operation, test.export(), time)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn fr22_ac4_a_signed_revocation_crl_is_rebuilt_with_its_record_change() {
    // Covers: FR-22 AC3, FR-22 AC4, FR-13 AC1
    let (mut test, mut token, _) = ca_with_main("R3", 70_000_003);
    let (sub, _) = run_flow_c(&mut test, &mut token, "R3", 2, false).unwrap();
    let time = test.tick();
    let plan = test
        .ca
        .plan_revoke(sub.serial, RevocationReason::Superseded, time)
        .unwrap();
    testing::arm_fault(FaultPoint::AfterSignedRecorded);
    let pin = s(PIN);
    injected(
        plan.execute(
            &test.ca,
            IssuerUnlock::YubiKey {
                token: &mut token,
                pin: &pin,
            },
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err(),
    );
    test.reopen();
    recover_all(&mut test, None, "R3");
    assert_no_lost_record(&test.ca);
    let state = test.ca.state().unwrap();
    assert!(matches!(
        state.record().get(sub.serial).unwrap().status,
        CertStatus::Revoked {
            reason: RevocationReason::Superseded,
            ..
        }
    ));
    let main = state.active_main(test.now).unwrap().serial();
    assert_eq!(state.current_crl(main).unwrap().info.crl_number, 2);
}

#[test]
fn fr22_ac4_flow_a_without_its_first_crl_needs_the_master_passphrase_to_finish() {
    // Covers: FR-22 AC4, FR-13 AC6
    let drives = TestDrives::new(2);
    let now = base_time();
    let (passphrase, words) = master_passphrase();
    testing::arm_fault(FaultPoint::AfterSignedRecorded);
    injected(run_flow_a(&drives, "R4", now, &passphrase, None).unwrap_err());
    testing::reset();
    let roots: Vec<&Path> = drives.ca_drives().iter().map(PathBuf::as_path).collect();
    let ca = Ca::open(&roots).unwrap();
    let items = ca.recovery_items(None).unwrap();
    let action = items[0].actions[0].action.clone();
    assert_eq!(
        action,
        RecoveryAction::RebuildFromJournal {
            needs_master_passphrase: true
        }
    );
    assert!(items[0].actions[0].description.contains("passphrase"));
    let time = confirmed(&ca, now + time::Duration::minutes(1));
    // FR-13 AC6: the master is signed but its first CRL does not exist yet, so it
    // cannot sign its first child: Flow B is refused (the unfinished Flow A blocks
    // every signing action) and nothing reaches the YubiKey.
    let before = ca.state().unwrap();
    if let Some(master) = before.master() {
        assert!(before.current_crl(master.serial()).is_none());
    }
    let (mut yubikey, controller) = token(70_000_401);
    let flow_b_request = MainIntermediateRequest::new(test_name("R4 Main"), Some(master_crl()));
    let refused = ca
        .plan_yubikey_setup(&mut yubikey, &flow_b_request, time)
        .unwrap_err();
    assert!(
        matches!(&refused, OpsError::Blocked(blockers)
            if blockers.iter().any(|b| matches!(b, Blocker::PendingOperation { .. }))),
        "{refused}"
    );
    assert_eq!(controller.signature_count(), 0);
    assert_eq!(controller.reopen_count(), 0);
    let error = ca
        .run_recovery(
            items[0].operation,
            &action,
            &RecoverySecrets::default(),
            time,
        )
        .unwrap_err();
    assert!(error.to_string().contains("master passphrase"), "{error}");
    let master = entered(&words);
    ca.run_recovery(
        items[0].operation,
        &action,
        &RecoverySecrets {
            master_passphrase: Some(&master),
        },
        time,
    )
    .unwrap();
    assert_no_lost_record(&ca);
    // Once the first CRL exists, Flow B can be planned (with its own confirmed time:
    // the recovery used `time`, SEC-16).
    let later = confirmed(&ca, now + time::Duration::minutes(2));
    ca.plan_yubikey_setup(&mut yubikey, &flow_b_request, later)
        .expect("Flow B after the master's first CRL exists");
    let state = ca.state().unwrap();
    let master_cert = state.master().unwrap();
    assert_eq!(
        state
            .current_crl(master_cert.serial())
            .unwrap()
            .info
            .crl_number,
        1
    );
    same_on_every_drive(&drives, "crls/master-crl-000001.crl");
    same_on_every_drive(&drives, "keys/master.key");
}

#[test]
fn fr22_ac4_staged_outputs_are_finished_from_a_drive_holding_them() {
    // Covers: FR-22 AC4, FR-22 AC2, FR-12 AC2
    for point in [
        FaultPoint::AfterStaged,
        FaultPoint::AfterCommit,
        FaultPoint::AfterAudit,
    ] {
        let (mut test, mut token, _) = ca_with_main("R5", 70_000_005);
        crash_flow_c(&mut test, &mut token, point);
        let action = only_action(&mut test, None);
        assert!(
            matches!(action, RecoveryAction::FinishFrom { drive_index: 0, .. }),
            "{point:?}: {action:?}"
        );
        recover_all(&mut test, None, "R5");
        assert_no_lost_record(&test.ca);
        assert_eq!(
            test.ca.state().unwrap().sub_intermediates().len(),
            1,
            "{point:?}"
        );
    }
}

/// Flow B stopped at `point`, then recovered with the same YubiKey after a restart.
fn yubikey_setup_interrupted_at(point: FaultPoint, serial: u32) -> Vec<RecoveryAction> {
    let mut test = new_ca("R6");
    let (mut token, _) = token(serial);
    testing::arm_fault(point);
    injected(run_flow_b(&mut test, &mut token, "R6", false).unwrap_err());
    test.reopen();
    let taken = recover_all(&mut test, Some(&mut token), "R6");
    if test.ca.state().unwrap().main_intermediates().is_empty() {
        // Nothing was journaled: the setup was abandoned. A new setup reads the
        // YubiKey's real state and asks for the PIN that was already set.
        let master = test.master_entered();
        let time = test.tick();
        let request = main_request(&test, "R6");
        let plan = test
            .ca
            .plan_yubikey_setup(&mut token, &request, time)
            .unwrap();
        let secrets = secrets_for(&mut token, Some(&master));
        let trust = token.attestation_trust();
        plan.execute(
            &test.ca,
            &mut token,
            &secrets,
            &trust,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    }
    // A correctly hardened YubiKey holding the main intermediate.
    let report = token.reopen_and_verify_hardening(&s(PIN)).unwrap();
    check_hardening_report(&report).unwrap();
    let state = test.ca.state().unwrap();
    let main = state.active_main(test.now).expect("main intermediate");
    assert_eq!(
        token.read_signing_certificate().unwrap().as_deref(),
        Some(main.der.as_slice())
    );
    assert!(state.current_crl(main.serial()).is_some());
    assert_no_lost_record(&test.ca);
    taken
}

#[test]
fn fr22_ac7_yubikey_setup_resumes_after_an_interruption_between_every_pair_of_steps() {
    // Covers: FR-22 AC7, FR-22 AC6, FR-22 AC5, FR-06 AC1
    let mut serial = 70_000_100;
    for step in YubikeySetupStep::ALL {
        for point in [
            FaultPoint::AfterTokenStep(step),
            FaultPoint::AfterTokenStepRecorded(step),
        ] {
            serial += 1;
            let taken = yubikey_setup_interrupted_at(point, serial);
            // With the YubiKey connected the setup is always resumed from its real
            // state, even when the interruption came before the first journaled step
            // (review finding 10: abandoning there ignored what the YubiKey holds).
            let expected = match point {
                FaultPoint::AfterTokenStep(YubikeySetupStep::KeyGenerated)
                | FaultPoint::AfterTokenStepRecorded(YubikeySetupStep::KeyGenerated) => {
                    RecoveryAction::CompleteSetupWithExistingKey
                }
                _ => RecoveryAction::ResumeYubikeySetup { next_step: None },
            };
            match (&taken[0], &expected) {
                (
                    RecoveryAction::ResumeYubikeySetup { .. },
                    RecoveryAction::ResumeYubikeySetup { .. },
                ) => {}
                (actual, expected) => assert_eq!(actual, expected, "{point:?}"),
            }
        }
    }
}

#[test]
fn fr22_ac7_resume_offers_the_first_incomplete_step_and_asks_the_pin_again() {
    // Covers: FR-22 AC7, FR-22 AC8
    let mut test = new_ca("R7");
    let (mut token, _) = token(70_000_201);
    testing::arm_fault(FaultPoint::AfterTokenStepRecorded(
        YubikeySetupStep::PukChanged,
    ));
    injected(run_flow_b(&mut test, &mut token, "R7", false).unwrap_err());
    test.reopen();
    let items = test.ca.recovery_items(Some(&mut token)).unwrap();
    let item = &items[0];
    assert_eq!(
        item.actions[0].action,
        RecoveryAction::ResumeYubikeySetup {
            next_step: Some(YubikeySetupStep::ManagementKeySet)
        }
    );
    assert!(item.actions[0].description.contains("nothing is wiped"));
    let column = item.yubikey.as_ref().expect("YubiKey column");
    assert_eq!(column.device.serial, 70_000_201);
    assert!(!column.credentials.pin_is_default && !column.credentials.puk_is_default);
    assert!(column.is_this_operations_yubikey);
    // The PIN set before the interruption is asked again (as the current PIN).
    let master = test.master_entered();
    let secrets = secrets_for(&mut token, Some(&master));
    assert!(matches!(
        secrets.pin,
        keystone_core::ops::PinEntry::Current(_)
    ));
    assert!(secrets.new_puk.is_none());
    // Without the name again, the unsigned main intermediate cannot be finished.
    let time = test.tick();
    let trust = token.attestation_trust();
    let error = test
        .ca
        .resume_yubikey_setup(
            item.operation,
            &mut token,
            None,
            &secrets,
            &trust,
            time,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("name and validity"), "{error}");
    // A different name is refused.
    let wrong = main_request(&test, "R7 other");
    let error = test
        .ca
        .resume_yubikey_setup(
            item.operation,
            &mut token,
            Some(&wrong),
            &secrets,
            &trust,
            time,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("differs"), "{error}");
    let request = main_request(&test, "R7");
    let outcome = test
        .ca
        .resume_yubikey_setup(
            item.operation,
            &mut token,
            Some(&request),
            &secrets,
            &trust,
            time,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    assert_eq!(outcome.operation, item.operation);
    assert_eq!(outcome.serial, item.planned_serials[0]);
    assert_no_lost_record(&test.ca);
}

#[test]
fn fr22_ac5_a_key_without_certificate_is_completed_only_after_its_attestation_verifies() {
    // Covers: FR-22 AC5, FR-07 AC5, FR-22 AC8
    let mut test = new_ca("R8");
    let (mut token, controller) = token(70_000_301);
    testing::arm_fault(FaultPoint::AfterTokenStepRecorded(
        YubikeySetupStep::KeyGenerated,
    ));
    injected(run_flow_b(&mut test, &mut token, "R8", false).unwrap_err());
    test.reopen();
    let key = token
        .slot_status(SIGNING_SLOT)
        .unwrap()
        .key
        .unwrap()
        .public_key_der;
    let items = test.ca.recovery_items(Some(&mut token)).unwrap();
    assert_eq!(items[0].actions.len(), 1);
    assert_eq!(
        items[0].actions[0].action,
        RecoveryAction::CompleteSetupWithExistingKey
    );
    assert!(items[0].actions[0].description.contains("not replaced"));
    assert!(items[0].yubikey.as_ref().unwrap().key_without_certificate);
    // A failed attestation: setup cannot be completed with this key; nothing signed.
    controller.set_attested_serial(1);
    let master = test.master_entered();
    let secrets = secrets_for(&mut token, Some(&master));
    let request = main_request(&test, "R8");
    let trust = token.attestation_trust();
    let time = test.tick();
    let error = test
        .ca
        .resume_yubikey_setup(
            items[0].operation,
            &mut token,
            Some(&request),
            &secrets,
            &trust,
            time,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cannot be completed with this key"),
        "{error}"
    );
    assert!(test.ca.state().unwrap().main_intermediates().is_empty());
    assert!(!test.ca.recovery_items(None).unwrap().is_empty());
    // With a genuine attestation the existing key is certified (never replaced).
    controller.set_attested_serial(70_000_301);
    let time = test.tick();
    let outcome = test
        .ca
        .resume_yubikey_setup(
            items[0].operation,
            &mut token,
            Some(&request),
            &secrets,
            &trust,
            time,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    let state = test.ca.state().unwrap();
    assert_eq!(
        state.certificate(outcome.serial).unwrap().info.spki_der,
        key
    );
    assert_no_lost_record(&test.ca);
}

#[test]
fn regression_a_yubikey_setup_whose_yubikey_is_lost_can_be_abandoned() {
    // Covers: FR-22 AC4, FR-22 AC7, FR-22 AC8, FR-10 AC2
    // Review finding 10 and the ops open point: with the setup's YubiKey connected only
    // the resume is offered; when it is absent (lost, or to be replaced) abandoning is
    // offered as well, because nothing was signed. Never more than two actions.
    let mut test = new_ca("R12");
    let (mut token, _) = token(70_000_701);
    testing::arm_fault(FaultPoint::AfterTokenStepRecorded(
        YubikeySetupStep::PukChanged,
    ));
    injected(run_flow_b(&mut test, &mut token, "R12", false).unwrap_err());
    test.reopen();
    let present = test.ca.recovery_items(Some(&mut token)).unwrap();
    assert_eq!(
        present[0]
            .actions
            .iter()
            .map(|c| c.action.clone())
            .collect::<Vec<_>>(),
        [RecoveryAction::ResumeYubikeySetup {
            next_step: Some(YubikeySetupStep::ManagementKeySet)
        }]
    );
    // Another YubiKey is not the setup's: abandoning is offered too.
    let (mut other, _) = crate::support::token(70_000_702);
    let with_other = test.ca.recovery_items(Some(&mut other)).unwrap();
    assert!(
        !with_other[0]
            .yubikey
            .as_ref()
            .unwrap()
            .is_this_operations_yubikey
    );
    let absent = test.ca.recovery_items(None).unwrap();
    for item in [&with_other[0], &absent[0]] {
        let actions: Vec<_> = item.actions.iter().map(|c| c.action.clone()).collect();
        assert_eq!(
            actions,
            [
                RecoveryAction::ResumeYubikeySetup {
                    next_step: Some(YubikeySetupStep::ManagementKeySet)
                },
                RecoveryAction::Abandon
            ]
        );
        let sentence = &item.actions[1].description;
        assert!(sentence.contains("lost or will be replaced"), "{sentence}");
        assert!(
            sentence.contains("serial number stays reserved"),
            "{sentence}"
        );
    }
    let operation = absent[0].operation;
    let reserved = absent[0].planned_serials[0];
    let time = test.tick();
    test.ca
        .run_recovery(
            operation,
            &RecoveryAction::Abandon,
            &RecoverySecrets::default(),
            time,
        )
        .unwrap();
    assert_no_lost_record(&test.ca);
    assert!(
        test.ca
            .drive_set()
            .known_serials()
            .unwrap()
            .contains(&reserved)
    );
    // A new YubiKey is set up afterwards.
    let (mut replacement, _) = crate::support::token(70_000_703);
    run_flow_b(&mut test, &mut replacement, "R12", false).expect("Flow B on a new YubiKey");
    assert!(test.ca.state().unwrap().active_main(test.now).is_some());
    assert_no_lost_record(&test.ca);
}

#[test]
fn fr22_ac5_a_key_that_fails_attestation_is_never_completed_but_its_setup_can_be_left() {
    // Covers: FR-22 AC5, FR-07 AC5, FR-22 AC4
    let mut test = new_ca("R13");
    let (mut token, controller) = token(70_000_801);
    testing::arm_fault(FaultPoint::AfterTokenStepRecorded(
        YubikeySetupStep::KeyGenerated,
    ));
    injected(run_flow_b(&mut test, &mut token, "R13", false).unwrap_err());
    test.reopen();
    controller.set_attested_serial(1);
    let items = test.ca.recovery_items(Some(&mut token)).unwrap();
    assert_eq!(items[0].actions.len(), 1);
    assert_eq!(
        items[0].actions[0].action,
        RecoveryAction::CompleteSetupWithExistingKey
    );
    let master = test.master_entered();
    let secrets = secrets_for(&mut token, Some(&master));
    let request = main_request(&test, "R13");
    let trust = token.attestation_trust();
    let time = test.tick();
    let error = test
        .ca
        .resume_yubikey_setup(
            items[0].operation,
            &mut token,
            Some(&request),
            &secrets,
            &trust,
            time,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cannot be completed with this key"),
        "{error}"
    );
    assert!(test.ca.state().unwrap().main_intermediates().is_empty());
    // The operator sets that YubiKey aside: the setup can then be abandoned.
    controller.remove();
    let items = test.ca.recovery_items(Some(&mut token)).unwrap();
    assert!(items[0].yubikey.is_none());
    assert_eq!(items[0].actions.len(), 2);
    assert_eq!(items[0].actions[1].action, RecoveryAction::Abandon);
    let time = test.tick();
    test.ca
        .run_recovery(
            items[0].operation,
            &RecoveryAction::Abandon,
            &RecoverySecrets::default(),
            time,
        )
        .unwrap();
    assert_no_lost_record(&test.ca);
    let (mut replacement, _) = crate::support::token(70_000_802);
    run_flow_b(&mut test, &mut replacement, "R13", false).expect("Flow B on another YubiKey");
    assert!(test.ca.state().unwrap().active_main(test.now).is_some());
}

#[test]
fn regression_a_signed_main_intermediate_whose_yubikey_is_lost_is_recorded_then_replaced() {
    // Covers: FR-22 AC3, FR-22 AC4, FR-15 AC1, FR-22 AC8
    // Review finding 5: the master signed the main intermediate, then the YubiKey was
    // lost before it signed its first CRL. Resuming needs that YubiKey, so the CA was
    // blocked for ever. With the YubiKey absent the certificate is now recorded and the
    // operation finished without that CRL; Flow E then revokes it.
    let mut test = new_ca("R14");
    let (mut lost, _) = token(70_000_901);
    testing::arm_fault(FaultPoint::AfterSignedRecorded);
    injected(run_flow_b(&mut test, &mut lost, "R14", false).unwrap_err());
    test.reopen();
    // With the YubiKey connected only the resume is offered.
    let present = test.ca.recovery_items(Some(&mut lost)).unwrap();
    assert_eq!(present[0].actions.len(), 1, "{:?}", present[0].actions);
    let items = test.ca.recovery_items(None).unwrap();
    let actions: Vec<_> = items[0].actions.iter().map(|c| c.action.clone()).collect();
    assert!(matches!(
        actions.as_slice(),
        [
            RecoveryAction::ResumeYubikeySetup { .. },
            RecoveryAction::FinishWithoutYubikey
        ]
    ));
    let sentence = &items[0].actions[1].description;
    assert!(sentence.contains("Replace lost YubiKey"), "{sentence}");
    let serial = items[0].planned_serials[0];
    let time = test.tick();
    test.ca
        .run_recovery(
            items[0].operation,
            &RecoveryAction::FinishWithoutYubikey,
            &RecoverySecrets::default(),
            time,
        )
        .unwrap();
    assert_no_lost_record(&test.ca);
    let state = test.ca.state().unwrap();
    assert_eq!(state.active_main(test.now).unwrap().serial(), serial);
    assert!(state.current_crl(serial).is_none());
    // Flow E revokes it with the master; a new YubiKey is then set up.
    let time = test.tick();
    let master = test.master_entered();
    test.ca
        .plan_replace_yubikey(RevocationReason::KeyCompromise, time)
        .unwrap()
        .execute(
            &test.ca,
            IssuerUnlock::Master(&master),
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    let (mut replacement, _) = crate::support::token(70_000_902);
    run_flow_b(&mut test, &mut replacement, "R14", false).expect("Flow B on a new YubiKey");
    let state = test.ca.state().unwrap();
    assert!(matches!(
        state.record().get(serial).unwrap().status,
        CertStatus::Revoked { .. }
    ));
    assert_ne!(state.active_main(test.now).unwrap().serial(), serial);
    assert_no_lost_record(&test.ca);
}

#[test]
fn fr14_ac1_an_operation_finished_through_recovery_has_a_complete_audit_entry() {
    // Covers: FR-14 AC1, FR-21 AC6, FR-22 AC4
    // Review test gap: FR-14 AC1 for operations finished through recovery, both by
    // finishing from a drive and by rebuilding from the journal.
    use keystone_core::store::{AuditAction, AuditResult};
    for (point, expected) in [
        (FaultPoint::AfterStaged, AuditAction::RecoveryFinish),
        (
            FaultPoint::AfterSignedRecorded,
            AuditAction::CreateSubIntermediate,
        ),
    ] {
        let (mut test, mut token, _) = ca_with_main("R15", 70_001_001);
        crash_flow_c(&mut test, &mut token, point);
        let operation = test.ca.recovery_items(None).unwrap()[0].operation;
        recover_all(&mut test, None, "R15");
        assert_no_lost_record(&test.ca);
        let state = test.ca.state().unwrap();
        let sub = &state.sub_intermediates()[0];
        let log = test.ca.drive_set().audit_log().unwrap();
        let entry = log
            .entries()
            .iter()
            .rev()
            .find(|e| e.operation == Some(operation))
            .expect("an audit entry for the operation");
        assert_eq!(entry.action, expected, "{point:?}");
        assert!(entry.time.get() <= test.now, "{point:?}");
        assert_eq!(entry.subject, sub.record.subject.display(), "{point:?}");
        assert_eq!(entry.serial, Some(sub.serial()), "{point:?}");
        assert_eq!(entry.fingerprint, Some(sub.record.fingerprint), "{point:?}");
        assert_eq!(entry.result, AuditResult::Success, "{point:?}");
        let details = entry.details.as_ref().expect("details");
        assert_eq!(
            details.permitted_dns.as_deref(),
            Some(&["starnet".to_string()][..]),
            "{point:?}"
        );
        if expected == AuditAction::RecoveryFinish {
            assert_eq!(
                details.original_action,
                Some(AuditAction::CreateSubIntermediate)
            );
        }
    }
}

#[test]
fn boundary_the_yubikey_removed_right_after_on_device_key_generation() {
    // Covers: FR-22 AC5, FR-22 AC7, FR-22 AC6
    let mut test = new_ca("R9");
    let (mut token, controller) = token(70_000_401);
    controller.fail_next(SimOp::GenerateKey, 1, FaultKind::RemoveAfter);
    let error = run_flow_b(&mut test, &mut token, "R9", false).unwrap_err();
    assert!(matches!(error, OpsError::Interrupted { .. }), "{error}");
    controller.reinsert();
    test.reopen();
    let taken = recover_all(&mut test, Some(&mut token), "R9");
    assert_eq!(taken, [RecoveryAction::CompleteSetupWithExistingKey]);
    assert_no_lost_record(&test.ca);
    assert!(test.ca.state().unwrap().active_main(test.now).is_some());
}

#[test]
fn fr22_ac8_recovery_offers_at_most_two_plain_actions_and_never_destroys() {
    // Covers: FR-22 AC8
    let (mut test, mut token, _) = ca_with_main("R10", 70_000_501);
    crash_flow_c(&mut test, &mut token, FaultPoint::AfterSignedRecorded);
    let items = test.ca.recovery_items(Some(&mut token)).unwrap();
    for item in &items {
        assert!(item.actions.len() <= 2);
        assert!(item.yubikey.is_some());
        assert_eq!(item.drives.len(), 2);
        for choice in &item.actions {
            let text = choice.description.to_lowercase();
            assert!(text.ends_with('.') && text.contains("; "), "{text}");
            for forbidden in ["format", "will delete", "overwrite the", "wipe the"] {
                assert!(!text.contains(forbidden), "{text}");
            }
        }
    }
    // An action that is not offered is refused.
    let time = test.tick();
    let error = test
        .ca
        .run_recovery(
            items[0].operation,
            &RecoveryAction::Abandon,
            &RecoverySecrets::default(),
            time,
        )
        .unwrap_err();
    assert!(error.to_string().contains("not offered"), "{error}");
    let error = test
        .ca
        .run_recovery(
            items[0].operation,
            &RecoveryAction::CompleteSetupWithExistingKey,
            &RecoverySecrets::default(),
            time,
        )
        .unwrap_err();
    assert!(error.to_string().contains("not offered"), "{error}");
}

#[test]
fn flow_e_interrupted_after_the_master_signed_finishes_and_marks_every_sub() {
    // Covers: FR-15 AC1, FR-22 AC4
    let (mut test, mut token, controller) = ca_with_main("R11", 70_000_601);
    let (sub, _) = run_flow_c(&mut test, &mut token, "R11", 3, false).unwrap();
    controller.remove();
    let time = test.tick();
    let plan = test
        .ca
        .plan_replace_yubikey(RevocationReason::KeyCompromise, time)
        .unwrap();
    assert!(matches!(plan.kind(), CrlPlanKind::ReplaceYubikey { .. }));
    let master = test.master_entered();
    testing::arm_fault(FaultPoint::AfterSigning);
    injected(
        plan.execute(
            &test.ca,
            IssuerUnlock::Master(&master),
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err(),
    );
    test.reopen();
    // The CRL never left memory: nothing signed was journaled, so it is abandoned.
    assert_eq!(
        recover_all(&mut test, None, "R11"),
        [RecoveryAction::Abandon]
    );
    let time = test.tick();
    let plan = test
        .ca
        .plan_replace_yubikey(RevocationReason::KeyCompromise, time)
        .unwrap();
    testing::arm_fault(FaultPoint::AfterSignedRecorded);
    injected(
        plan.execute(
            &test.ca,
            IssuerUnlock::Master(&master),
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err(),
    );
    test.reopen();
    assert_eq!(
        recover_all(&mut test, None, "R11"),
        [RecoveryAction::RebuildFromJournal {
            needs_master_passphrase: false
        }]
    );
    assert_no_lost_record(&test.ca);
    assert!(matches!(
        test.ca
            .state()
            .unwrap()
            .record()
            .get(sub.serial)
            .unwrap()
            .status,
        CertStatus::RevokedByAncestor { .. }
    ));
}
