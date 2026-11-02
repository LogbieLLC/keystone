//! Replace a lost drive (SEC-11, T-11; maintainer-approved feature, ADR 0003).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use keystone_core::crypto::CancelFlag;
use keystone_core::model::RevocationReason;
use keystone_core::ops::testing::{self, FaultPoint};
use keystone_core::ops::{Blocker, Ca, IssuerUnlock, NoProgress, OpsError};
use keystone_core::store::{
    AuditAction, CertStatus, DriveClass, DriveComparison, DriveRole, RepairStep, StoreError,
    classify_drive,
};
use time::Duration;

use crate::support::*;

fn open(roots: &[&Path]) -> Ca {
    Ca::open(roots).expect("open")
}

fn blockers(error: OpsError) -> Vec<Blocker> {
    match error {
        OpsError::Blocked(blockers) => blockers,
        other => panic!("expected blockers, got {other}"),
    }
}

fn drive_added_entries(ca: &Ca) -> usize {
    ca.drive_set()
        .audit_log()
        .expect("log")
        .entries()
        .iter()
        .filter(|e| {
            e.action == AuditAction::DriveRepair
                && e.details.as_ref().is_some_and(|d| d.drive_added.is_some())
        })
        .count()
}

#[test]
fn sec11_a_lost_primary_is_replaced_and_revocation_works_afterwards() {
    // Covers: SEC-11, T-11, FR-12 AC1, FR-13 AC1, FR-12 AC3
    let (mut test, mut token, _) = ca_with_main("D1", 90_000_001);
    let (sub, _) = run_flow_c(&mut test, &mut token, "D1", 1, false).unwrap();
    let lost = test.drives.ca_drive(0).to_path_buf();
    let backup = test.drives.ca_drive(1).to_path_buf();
    let new = test.drives.add_ca_drive();
    // The primary is lost: the backup alone can be read, nothing can be signed.
    test.ca = open(&[&backup]);
    test.now += Duration::minutes(1);
    let report = test.ca.startup_report(test.now).unwrap();
    assert!(report.blockers.contains(&Blocker::NotEnoughDrives {
        primaries: 0,
        backups: 1
    }));
    let time = confirmed(&test.ca, test.now);
    assert!(
        blockers(
            test.ca
                .plan_revoke(sub.serial, RevocationReason::KeyCompromise, time)
                .unwrap_err()
        )
        .iter()
        .any(|b| matches!(b, Blocker::NotEnoughDrives { .. }))
    );
    // Plan, review, execute.
    let plan = test.ca.plan_replace_drive(&new, time).unwrap();
    assert!(plan.promotes().is_some());
    let review = plan.review();
    assert!(
        review
            .value("Primary drive")
            .is_some_and(|v| v.contains("becomes the primary")),
        "{review:?}"
    );
    assert!(
        review
            .value("What is not done")
            .is_some_and(|v| v.contains("nothing is signed")),
        "{review:?}"
    );
    assert!(!review.warnings.is_empty());
    let outcome = plan.execute(&test.ca, &NoProgress).unwrap();
    assert!(outcome.promoted.is_some());
    assert_eq!(outcome.operations_copied, 3);
    test.ca = outcome.ca;
    let roles = test.ca.drive_roles();
    assert_eq!(roles.len(), 2);
    assert_eq!(roles[0].1, DriveRole::Primary);
    assert_eq!(roles[1].1, DriveRole::Backup);
    assert_eq!(drive_added_entries(&test.ca), 1);
    let report = test.ca.startup_report(test.now).unwrap();
    assert!(report.signing_allowed(), "{:?}", report.blockers);
    // Flow D: the compromised sub-intermediate is revoked on the new drive set.
    let time = test.tick();
    let pin = s(PIN);
    test.ca
        .plan_revoke(sub.serial, RevocationReason::KeyCompromise, time)
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
    assert_no_lost_record(&test.ca);
    assert!(matches!(
        test.ca
            .state()
            .unwrap()
            .record()
            .get(sub.serial)
            .unwrap()
            .status,
        CertStatus::Revoked { .. }
    ));
    // The lost primary found again is only a (behind) backup; it is repaired, never a
    // second primary.
    let all = open(&[&lost, &backup, &new]);
    let primaries = all
        .drive_roles()
        .iter()
        .filter(|(_, role)| *role == DriveRole::Primary)
        .count();
    assert_eq!(primaries, 1);
    let plans = match all.drive_set().compare().unwrap() {
        DriveComparison::Behind { plans } => plans,
        other => panic!("expected the found drive behind, got {other:?}"),
    };
    test.now += Duration::minutes(1);
    all.repair_drives(&plans, confirmed(&all, test.now))
        .unwrap();
    assert_consistent(&all);
}

#[test]
fn sec11_a_lost_only_backup_is_replaced_and_is_the_only_action_meanwhile() {
    // Covers: SEC-11, T-11, FR-12 AC1
    let (mut test, mut token, _) = ca_with_main("D2", 90_000_002);
    let primary = test.drives.ca_drive(0).to_path_buf();
    let new = test.drives.add_ca_drive();
    test.ca = open(&[&primary]);
    let time = test.tick();
    // Every action that writes or signs needs a backup.
    let request = keystone_core::ops::SubIntermediateRequest::new(
        keystone_testkit::names::test_name("D2 Sub"),
        constrained(&["starnet"]),
        Some(main_crl()),
    );
    assert!(matches!(
        test.ca.plan_sub_intermediate(&request, time),
        Err(OpsError::Blocked(_))
    ));
    assert!(matches!(
        test.ca.plan_refresh_crl(test.master.serial, time),
        Err(OpsError::Blocked(_))
    ));
    assert!(test.ca.correct_clock_baseline(test.now).is_err());
    let export_root = test.drives.export_drive().to_path_buf();
    assert!(
        test.ca
            .export_operation(keystone_core::store::OperationId(1), &export_root, time)
            .is_err()
    );
    // Only the replacement runs.
    let plan = test.ca.plan_replace_drive(&new, time).unwrap();
    assert!(plan.promotes().is_none());
    assert_eq!(plan.review().value("Primary drive"), Some("unchanged"));
    let outcome = plan.execute(&test.ca, &NoProgress).unwrap();
    assert!(outcome.promoted.is_none());
    test.ca = outcome.ca;
    run_flow_c(&mut test, &mut token, "D2", 2, false).expect("signing works again");
    assert_consistent(&test.ca);
}

#[test]
fn sec11_a_replacement_interrupted_at_every_drive_change_finishes_when_run_again() {
    // Covers: SEC-11, FR-12 AC2, FR-22 AC6
    let (base, _, _) = ca_with_main("D3", 90_000_003);
    let run = |test: &mut TestCa| -> (PathBuf, PathBuf, Ca) {
        let backup = test.drives.ca_drive(1).to_path_buf();
        let new = test.drives.add_ca_drive();
        (backup.clone(), new, open(&[&backup]))
    };
    let mut probe = clone_ca(&base);
    let (_, new, ca) = run(&mut probe);
    let time = confirmed(&ca, probe.now + Duration::minutes(1));
    let plan = ca.plan_replace_drive(&new, time).unwrap();
    testing::drive_change_count();
    plan.execute(&ca, &NoProgress).unwrap();
    let total = testing::drive_change_count();
    assert!(total > 10, "{total}");
    for crash_at in 0..total {
        let mut test = clone_ca(&base);
        let (backup, new, ca) = run(&mut test);
        let time = confirmed(&ca, test.now + Duration::minutes(1));
        let plan = ca.plan_replace_drive(&new, time).unwrap();
        testing::crash_on_drive_change(crash_at);
        let error = plan.execute(&ca, &NoProgress).unwrap_err();
        assert!(
            matches!(error, OpsError::Store(_)),
            "change {crash_at}: {error}"
        );
        testing::reset();
        // No partial drive ever looks complete: a drive that has its identity holds the
        // whole verified copy (at most the replacement's audit entries differ).
        if let DriveClass::KeystoneCa(_) = classify_drive(&new).unwrap() {
            match open(&[&backup, &new]).drive_set().compare().unwrap() {
                DriveComparison::InSync => {}
                DriveComparison::Behind { plans } => assert!(
                    plans.iter().all(|plan| plan
                        .steps
                        .iter()
                        .all(|step| matches!(step, RepairStep::AuditOnly { .. }))),
                    "change {crash_at}: {plans:?}"
                ),
                other => panic!("change {crash_at}: the copy is not complete: {other:?}"),
            }
        }
        // After a restart the same action finishes it (or, when the replacement's audit
        // entries reached only some drives, the start screen's repair does).
        let later = test.now + Duration::minutes(2);
        let ca = open(&[&backup]);
        match ca.plan_replace_drive(&new, confirmed(&ca, later)) {
            Ok(plan) => {
                plan.execute(&ca, &NoProgress)
                    .unwrap_or_else(|e| panic!("change {crash_at}: {e}"));
            }
            Err(_) => {
                let both = open(&[&backup, &new]);
                let report = both.startup_report(later).unwrap();
                let plans = report
                    .blockers
                    .iter()
                    .find_map(|b| match b {
                        Blocker::DrivesBehind { plans } => Some(plans.clone()),
                        _ => None,
                    })
                    .unwrap_or_else(|| panic!("change {crash_at}: {:?}", report.blockers));
                both.repair_drives(&plans, confirmed(&both, later)).unwrap();
            }
        }
        let done = open(&[&backup, &new]);
        assert!(
            done.startup_report(later).unwrap().signing_allowed(),
            "change {crash_at}"
        );
        assert_consistent(&done);
        assert_eq!(drive_added_entries(&done), 1, "change {crash_at}");
    }
}

#[test]
fn sec11_a_replacement_is_refused_while_unsafe() {
    // Covers: SEC-11, SEC-20, SEC-22, FR-22 AC4, FR-17 AC2
    let (mut test, mut token, _) = ca_with_main("D4", 90_000_004);
    let new = test.drives.add_ca_drive();
    // A confirmed time older than the newest audit entry.
    let stale = test.tick();
    run_flow_c(&mut test, &mut token, "D4", 3, false).unwrap();
    let roots: Vec<PathBuf> = test.drives.ca_drives()[..2].to_vec();
    let ca = open(&[&roots[0], &roots[1]]);
    assert!(matches!(
        ca.plan_replace_drive(&new, stale),
        Err(OpsError::Blocked(_))
    ));
    // A drive that is not empty, or one of the CA's own drives.
    let time = confirmed(&ca, test.now + Duration::minutes(1));
    std::fs::write(new.join("photo.jpg"), b"x").unwrap();
    assert!(matches!(
        ca.plan_replace_drive(&new, time),
        Err(OpsError::Store(StoreError::DriveNotEmpty { .. }))
    ));
    assert!(ca.plan_replace_drive(&roots[1], time).is_err());
    // An interrupted operation.
    let (plan, passphrase, _) = plan_flow_c(&mut test, "D4b").unwrap();
    testing::supply_generated_key(keystone_testkit::keys::rsa4096(4));
    testing::arm_fault(FaultPoint::BeforeSigning);
    assert!(
        plan.execute(
            &test.ca,
            &mut token,
            &s(PIN),
            &passphrase,
            None,
            &NoProgress,
            &CancelFlag::new()
        )
        .is_err()
    );
    testing::reset();
    let empty = test.drives.add_ca_drive();
    let ca = open(&[&roots[0], &roots[1]]);
    let time = confirmed(&ca, test.now + Duration::minutes(2));
    assert!(matches!(
        ca.plan_replace_drive(&empty, time),
        Err(OpsError::Store(StoreError::PendingOperation(_)))
    ));
    assert!(
        std::fs::read_dir(&empty).unwrap().next().is_none(),
        "untouched"
    );
}
