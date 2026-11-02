//! Refusals and edge cases of the operations layer: wrong inputs are refused before
//! anything is written, and stale reviews are refused before anything is signed.
#![forbid(unsafe_code)]

use keystone_core::crypto::CancelFlag;
use keystone_core::model::RevocationReason;
use keystone_core::ops::{
    Blocker, ExportStatus, IssuerUnlock, MainIntermediateRequest, NoProgress, OpsError,
    RecoveryAction, RecoverySecrets, SubIntermediateRequest, testing,
};
use keystone_core::store::{DriveRole, StoreError};
use keystone_core::token::TokenSigner;
use keystone_testkit::keys;
use keystone_testkit::names::test_name;

use crate::support::*;

#[test]
fn every_flow_refuses_to_start_after_cancel_or_with_the_wrong_kind_of_passphrase() {
    // Covers: FR-16 AC2, FR-03 AC2, SEC-15
    let (mut test, mut token, _) = ca_with_main("X1", 90_000_001);
    let cancelled = CancelFlag::new();
    cancelled.cancel();
    // Flow C: a master passphrase is refused; a pressed Cancel writes nothing.
    let (plan, _, _) = plan_flow_c(&mut test, "X1").unwrap();
    let (master_kind, _) = master_passphrase();
    let error = plan
        .execute(
            &test.ca,
            &mut token,
            &s(PIN),
            &master_kind,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("10-word"), "{error}");
    let (plan, passphrase, _) = plan_flow_c(&mut test, "X1").unwrap();
    assert!(matches!(
        plan.execute(
            &test.ca,
            &mut token,
            &s(PIN),
            &passphrase,
            None,
            &NoProgress,
            &cancelled
        )
        .unwrap_err(),
        OpsError::CancelledBeforeStart
    ));
    // CRL operations.
    let time = test.tick();
    let master = test.master_entered();
    let plan = test.ca.plan_refresh_crl(test.master.serial, time).unwrap();
    assert!(matches!(
        plan.execute(
            &test.ca,
            IssuerUnlock::Master(&master),
            None,
            &NoProgress,
            &cancelled
        )
        .unwrap_err(),
        OpsError::CancelledBeforeStart
    ));
    // Flow B: refused without a master passphrase and for another YubiKey.
    let (mut fresh, _) = crate::support::token(90_000_002);
    let mut empty = new_ca("X1b");
    let time = empty.tick();
    let request = MainIntermediateRequest::new(test_name("X1b Main"), Some(master_crl()));
    let plan = empty
        .ca
        .plan_yubikey_setup(&mut fresh, &request, time)
        .unwrap();
    assert_eq!(plan.device().serial, 90_000_002);
    let trust = fresh.attestation_trust();
    let mut secrets = fresh_secrets(&master);
    secrets.master_passphrase = None;
    let error = plan
        .execute(
            &empty.ca,
            &mut fresh,
            &secrets,
            &trust,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("master passphrase"), "{error}");
    let plan = empty
        .ca
        .plan_yubikey_setup(&mut fresh, &request, time)
        .unwrap();
    let (mut other, _) = crate::support::token(90_000_003);
    let error = plan
        .execute(
            &empty.ca,
            &mut other,
            &fresh_secrets(&master),
            &trust,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("plan was made for YubiKey 90000002"),
        "{error}"
    );
    let plan = empty
        .ca
        .plan_yubikey_setup(&mut fresh, &request, time)
        .unwrap();
    assert!(matches!(
        plan.execute(
            &empty.ca,
            &mut fresh,
            &fresh_secrets(&master),
            &trust,
            None,
            &NoProgress,
            &cancelled
        )
        .unwrap_err(),
        OpsError::CancelledBeforeStart
    ));
    assert!(fresh.credential_status().unwrap().pin_is_default);
    // Flow A: a sub-intermediate passphrase is refused.
    let drives = keystone_testkit::TestDrives::new(2);
    let (sub_kind, _) = sub_passphrase();
    let error = run_flow_a(&drives, "X1c", base_time(), &sub_kind, None).unwrap_err();
    assert!(error.to_string().contains("master passphrase"), "{error}");
    testing::reset();
    let (master_kind, _) = master_passphrase();
    let backups = [drives.ca_drive(1)];
    let plan = keystone_core::ops::plan_create_master(
        keystone_core::ops::CreateMasterRequest::new(
            drives.ca_drive(0),
            &backups,
            test_name("X1c"),
        ),
        confirmed_new(base_time()),
    )
    .unwrap();
    assert!(matches!(
        plan.execute(&master_kind, None, &NoProgress, &cancelled)
            .unwrap_err(),
        OpsError::CancelledBeforeStart
    ));
    assert_eq!(std::fs::read_dir(drives.ca_drive(0)).unwrap().count(), 0);
}

#[test]
fn reviews_that_became_stale_and_impossible_requests_are_refused() {
    // Covers: FR-13 AC1, FR-13 AC4, FR-10 AC2
    let (mut test, mut token, _) = ca_with_main("X2", 90_000_011);
    let (sub, _) = run_flow_c(&mut test, &mut token, "X2", 1, false).unwrap();
    let main = test
        .ca
        .state()
        .unwrap()
        .active_main(test.now)
        .unwrap()
        .serial();
    let time = test.tick();
    // Keystone signs no CRL for a sub-intermediate, and unknown serials are refused.
    assert!(
        test.ca
            .plan_refresh_crl(sub.serial, time)
            .unwrap_err()
            .to_string()
            .contains("issuing systems")
    );
    let unknown = keystone_core::crypto::rand::random_serial().unwrap();
    assert!(
        test.ca
            .plan_revoke(unknown, RevocationReason::Superseded, time)
            .is_err()
    );
    assert!(test.ca.plan_refresh_crl(unknown, time).is_err());
    // A review made before another CRL was published is stale (it carries a later
    // confirmed time of its own, so only the review check can refuse it).
    let own_time = test.tick();
    let stale = test.ca.plan_refresh_crl(main, own_time).unwrap();
    assert_eq!(stale.issuer_serial(), main);
    assert!(!stale.needs_master());
    let pin = s(PIN);
    test.ca
        .plan_refresh_crl(main, time)
        .unwrap()
        .execute(
            &test.ca,
            IssuerUnlock::YubiKey {
                token: &mut token,
                pin: &pin,
            },
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    let error = stale
        .execute(
            &test.ca,
            IssuerUnlock::YubiKey {
                token: &mut token,
                pin: &pin,
            },
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("changed since the review"),
        "{error}"
    );
    // The master's passphrase cannot sign the main intermediate's CRL.
    let master = test.master_entered();
    let unlock = IssuerUnlock::Master(&master);
    assert!(!format!("{unlock:?}").contains(&test.master_words));
    let time = test.tick();
    let error = test
        .ca
        .plan_refresh_crl(main, time)
        .unwrap()
        .execute(&test.ca, unlock, None, &NoProgress, &CancelFlag::new())
        .unwrap_err();
    assert!(error.to_string().contains("YubiKey"), "{error}");
    // No main intermediate to replace before Flow B.
    let mut bare = new_ca("X2b");
    let time = bare.tick();
    assert!(
        bare.ca
            .plan_replace_yubikey(RevocationReason::Superseded, time)
            .is_err()
    );
    let request = SubIntermediateRequest::new(
        test_name("X2b Sub"),
        constrained(&["starnet"]),
        Some(main_crl()),
    );
    let error = bare.ca.plan_sub_intermediate(&request, time).unwrap_err();
    assert!(error.to_string().contains("Flow B"), "{error}");
    assert!(bare.ca.max_sub_intermediate_years(bare.now).is_err());
}

#[test]
fn export_never_overwrites_a_different_file_and_roles_are_listed() {
    // Covers: FR-22 AC2, SEC-20
    let (mut test, mut token, _) = ca_with_main("X3", 90_000_021);
    let (plan, passphrase, _) = plan_flow_c(&mut test, "X3").unwrap();
    let stem = plan.file_stem();
    std::fs::create_dir_all(test.export().join("keystone-export")).unwrap();
    std::fs::write(
        test.export()
            .join("keystone-export")
            .join(format!("{stem}.crt")),
        "KEYSTONE TEST other file",
    )
    .unwrap();
    testing::supply_generated_key(keys::rsa4096(2));
    let outcome = plan
        .execute(
            &test.ca,
            &mut token,
            &s(PIN),
            &passphrase,
            Some(test.export()),
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    let ExportStatus::Failed(reason) = &outcome.export else {
        panic!("{:?}", outcome.export);
    };
    assert!(reason.contains("never overwrites"), "{reason}");
    assert_eq!(
        std::fs::read_to_string(
            test.export()
                .join("keystone-export")
                .join(format!("{stem}.crt"))
        )
        .unwrap(),
        "KEYSTONE TEST other file"
    );
    // A CA drive is never used as the export drive.
    let time = test.tick();
    let error = test
        .ca
        .export_operation(outcome.operation, test.drives.ca_drive(1), time)
        .unwrap_err();
    assert!(
        matches!(error, OpsError::Store(StoreError::DriveSet(_))),
        "{error}"
    );
    let roles = test.ca.drive_roles();
    assert_eq!(
        roles.iter().map(|(_, role)| *role).collect::<Vec<_>>(),
        [DriveRole::Primary, DriveRole::Backup]
    );
    assert!(roles[0].0.contains("primary drive"));
}

#[test]
fn yubikey_recovery_actions_need_the_yubikey_and_damaged_state_blocks_signing() {
    // Covers: FR-22 AC7, FR-19 AC1, FR-22 AC2
    let mut test = new_ca("X4");
    let (mut token, _) = token(90_000_031);
    testing::arm_fault(testing::FaultPoint::AfterTokenStepRecorded(
        keystone_core::store::YubikeySetupStep::PinChanged,
    ));
    assert!(run_flow_b(&mut test, &mut token, "X4", false).is_err());
    test.reopen();
    let items = test.ca.recovery_items(None).unwrap();
    let action = items[0].actions[0].action.clone();
    assert!(matches!(action, RecoveryAction::ResumeYubikeySetup { .. }));
    let time = test.tick();
    let error = test
        .ca
        .run_recovery(
            items[0].operation,
            &action,
            &RecoverySecrets::default(),
            time,
        )
        .unwrap_err();
    assert!(error.to_string().contains("connect the YubiKey"), "{error}");
    let error = test
        .ca
        .run_recovery(
            keystone_core::store::OperationId(99),
            &action,
            &RecoverySecrets::default(),
            time,
        )
        .unwrap_err();
    assert!(error.to_string().contains("not interrupted"), "{error}");
    // Resuming a finished or different kind of operation is refused.
    let secrets = current_secrets(None);
    let trust = token.attestation_trust();
    let error = test
        .ca
        .resume_yubikey_setup(
            keystone_core::store::OperationId(1),
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
    assert!(error.to_string().contains("not interrupted"), "{error}");
    recover_all(&mut test, Some(&mut token), "X4");
    assert_no_lost_record(&test.ca);

    // A changed record file: the drives are damaged and signing is blocked.
    let record = test
        .drives
        .ca_drive(1)
        .join("keystone/record/op-000001.json");
    let text = std::fs::read_to_string(&record).unwrap();
    std::fs::write(&record, text.replacen("X4 Master", "X4 Masked", 1)).unwrap();
    let report = test.ca.startup_report(test.now).unwrap();
    assert!(
        report
            .blockers
            .iter()
            .any(|b| matches!(b, Blocker::DrivesDamaged { .. })),
        "{:?}",
        report.blockers
    );
    let time = test.tick();
    assert!(matches!(
        test.ca
            .plan_refresh_crl(test.master.serial, time)
            .unwrap_err(),
        OpsError::Blocked(_)
    ));
    for blocker in &report.blockers {
        assert!(!blocker.message().is_empty());
    }
}

#[test]
fn a_journaled_certificate_that_no_longer_reads_blocks_every_signing() {
    // Covers: FR-19 AC1, SEC-08
    let mut test = new_ca("X5");
    for drive in test.drives.ca_drives() {
        let path = drive.join("keystone/journal/op-000001/002-signed.json");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("MII"));
        std::fs::write(&path, text.replacen("MII", "MIJ", 1)).unwrap();
    }
    test.reopen();
    test.now += time::Duration::minutes(1);
    let report = test.ca.startup_report(test.now).unwrap();
    assert!(
        report
            .blockers
            .iter()
            .any(|b| matches!(b, Blocker::StateUnreadable(_))),
        "{:?}",
        report.blockers
    );
    let time = confirmed(&test.ca, test.now);
    let (mut token, _) = crate::support::token(90_000_041);
    let request = MainIntermediateRequest::new(test_name("X5 Main"), Some(master_crl()));
    let error = test
        .ca
        .plan_yubikey_setup(&mut token, &request, time)
        .unwrap_err();
    assert!(matches!(error, OpsError::Damaged(_)), "{error}");
}

/// True when `result` was refused because its confirmed time is not later than the
/// newest audit entry.
fn stale<T: std::fmt::Debug>(result: Result<T, OpsError>) -> bool {
    match result {
        Err(OpsError::Blocked(blockers)) => blockers.iter().any(|b| {
            matches!(b, Blocker::ClockConfirmationStale { .. })
                && b.message().contains("confirm the date and time again")
        }),
        _ => false,
    }
}

#[test]
fn regression_one_confirmed_time_never_serves_two_operations() {
    // Covers: SEC-16, FR-17 AC1
    // Regression (final storage review, SEC-16): a ConfirmedTime equal to the newest
    // audit entry passed the signing gate, so one confirmation signed two certificates.
    let (mut test, mut token, _) = ca_with_main("T16", 91_160_001);
    let time = test.tick();
    let request = |label: &str, crl: Option<keystone_core::profile::CrlLocation>| {
        SubIntermediateRequest::new(test_name(label), constrained(&["starnet"]), crl)
    };
    // Two reviews made with the same confirmation, before either is executed.
    let first = test
        .ca
        .plan_sub_intermediate(&request("T16 a", Some(main_crl())), time)
        .unwrap();
    let second = test
        .ca
        .plan_sub_intermediate(&request("T16 b", Some(main_crl())), time)
        .unwrap();
    let (passphrase, _) = sub_passphrase();
    testing::supply_generated_key(keys::rsa4096(1));
    first
        .execute(
            &test.ca,
            &mut token,
            &s(PIN),
            &passphrase,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .expect("the first signing");
    testing::reset();
    let entries = test.ca.drive_set().audit_log().unwrap().len();
    // The second signing with that confirmation is refused, at execute and at plan.
    let (passphrase, _) = sub_passphrase();
    assert!(stale(second.execute(
        &test.ca,
        &mut token,
        &s(PIN),
        &passphrase,
        None,
        &NoProgress,
        &CancelFlag::new(),
    )));
    assert!(stale(
        test.ca.plan_sub_intermediate(&request("T16 c", None), time)
    ));
    // So is every other CA-changing operation.
    assert!(stale(test.ca.plan_refresh_crl(test.master.serial, time)));
    let main = test
        .ca
        .state()
        .unwrap()
        .active_main(test.now)
        .unwrap()
        .serial();
    assert!(stale(test.ca.plan_revoke(
        main,
        RevocationReason::Superseded,
        time
    )));
    let new = test.drives.add_ca_drive();
    assert!(stale(test.ca.plan_replace_drive(&new, time)));
    assert!(stale(test.ca.repair_drives(&[], time)));
    assert_eq!(
        test.ca.drive_set().audit_log().unwrap().len(),
        entries,
        "nothing was written"
    );
    // A new confirmation (a later time) signs again.
    run_flow_c(&mut test, &mut token, "T16 d", 2, false).expect("a new confirmation");
    assert_consistent(&test.ca);
}
