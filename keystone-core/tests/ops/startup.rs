//! Opening an existing CA and the start checks (FR-12 AC1, AC3, FR-14 AC3, FR-17,
//! FR-19 AC1, FR-22 AC4, PRD section 6 preamble).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use keystone_core::clock::{self, ClockError, ClockProblem};
use keystone_core::model::RevocationReason;
use keystone_core::ops::{
    AuditLogStatus, Blocker, Ca, OpsError, StartupWarning, SubIntermediateRequest, testing,
};
use keystone_core::store::{DriveComparison, StatusFilter};
use keystone_testkit::names::test_name;
use time::Duration;

use crate::support::*;

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn roots(paths: &[PathBuf]) -> Vec<&Path> {
    paths.iter().map(PathBuf::as_path).collect()
}

fn blocked(error: OpsError) -> Vec<Blocker> {
    match error {
        OpsError::Blocked(blockers) => blockers,
        other => panic!("not blocked: {other}"),
    }
}

#[test]
fn fr19_ac1_an_existing_ca_opens_with_verified_drives_log_and_state() {
    // Covers: FR-19 AC1, FR-14 AC3, FR-12 AC3, FR-11 AC2
    let (mut test, mut token, _) = ca_with_main("S1", 60_000_001);
    run_flow_c(&mut test, &mut token, "S1", 1, false).unwrap();
    test.reopen();
    let report = test
        .ca
        .startup_report(test.now + Duration::minutes(1))
        .unwrap();
    assert!(report.signing_allowed(), "{:?}", report.blockers);
    assert_eq!(report.comparison, DriveComparison::InSync);
    assert_eq!(report.drives.len(), 2);
    assert!(
        report
            .audit
            .iter()
            .all(|a| matches!(a, AuditLogStatus::Verified { entries, .. } if *entries >= 3))
    );
    assert!(report.recovery.is_empty());
    assert!(!report.clock.is_blocked());
    let hierarchy = &report.hierarchy;
    assert_eq!(
        hierarchy.master.as_ref().unwrap().serial,
        test.master.serial
    );
    assert!(hierarchy.active_main.is_some());
    assert_eq!(hierarchy.valid_sub_intermediates, 1);
    assert_eq!(hierarchy.recorded_certificates, 3);
    // FR-11 AC2: the record filters by issuer and status.
    let state = test.ca.state().unwrap();
    let main = state.active_main(test.now).unwrap().serial();
    assert_eq!(state.filter_record(Some(main), None, test.now).len(), 1);
    assert_eq!(
        state
            .filter_record(None, Some(StatusFilter::Valid), test.now)
            .len(),
        3
    );
    assert_eq!(
        state
            .filter_record(None, Some(StatusFilter::Revoked), test.now)
            .len(),
        0
    );
}

#[test]
fn fr12_ac1_one_drive_alone_can_be_read_but_not_written() {
    // Covers: FR-12 AC1
    let mut test = new_ca("S2");
    let ca = Ca::open(&[test.drives.ca_drive(0)]).unwrap();
    test.now += Duration::minutes(1);
    let report = ca.startup_report(test.now).unwrap();
    assert!(report.blockers.iter().any(|b| matches!(
        b,
        Blocker::NotEnoughDrives {
            primaries: 1,
            backups: 0
        }
    )));
    let (mut token, _) = token(60_000_002);
    let request =
        keystone_core::ops::MainIntermediateRequest::new(test_name("S2 Main"), Some(master_crl()));
    let error = ca
        .plan_yubikey_setup(&mut token, &request, confirmed(&ca, test.now))
        .unwrap_err();
    assert!(
        blocked(error)
            .iter()
            .any(|b| matches!(b, Blocker::NotEnoughDrives { .. }))
    );
}

#[test]
fn fr12_ac3_a_behind_drive_blocks_signing_until_the_operator_confirms_the_repair() {
    // Covers: FR-12 AC3, FR-19 AC1, SEC-22
    let mut test = new_ca_with("S3", 3, false);
    // Flow B with the third drive absent: it falls behind.
    let all: Vec<PathBuf> = test.drives.ca_drives().to_vec();
    test.ca = Ca::open(&roots(&all[..2])).unwrap();
    let (mut token, _) = token(60_000_003);
    run_flow_b(&mut test, &mut token, "S3", false).unwrap();
    test.ca = Ca::open(&roots(&all)).unwrap();
    test.now += Duration::minutes(1);
    let report = test.ca.startup_report(test.now).unwrap();
    let plans = report
        .blockers
        .iter()
        .find_map(|b| match b {
            Blocker::DrivesBehind { plans } => Some(plans.clone()),
            _ => None,
        })
        .expect("behind");
    assert_eq!(plans.len(), 1);
    assert!(!plans[0].steps.is_empty());
    // Signing is blocked until the repair is confirmed.
    let time = confirmed(&test.ca, test.now);
    let request = SubIntermediateRequest::new(
        test_name("S3 Sub"),
        constrained(&["starnet"]),
        Some(main_crl()),
    );
    assert!(
        blocked(test.ca.plan_sub_intermediate(&request, time).unwrap_err())
            .iter()
            .any(|b| matches!(b, Blocker::DrivesBehind { .. }))
    );
    test.ca.repair_drives(&plans, time).unwrap();
    let report = test.ca.startup_report(test.now).unwrap();
    assert!(report.signing_allowed(), "{:?}", report.blockers);
    run_flow_c(&mut test, &mut token, "S3", 1, false).expect("signing after repair");
    assert_consistent(&test.ca);
}

#[test]
fn fr12_ac3_diverged_histories_block_signing_and_every_serial_stays_known() {
    // Covers: FR-12 AC3, FR-10 AC2, SEC-22
    let mut test = new_ca("S4");
    // A second copy of the same CA (both drives), then a different operation on each.
    let mut clone_drives = Vec::new();
    for index in 0..2 {
        let target = test.drives.add_ca_drive();
        copy_dir(
            &test.drives.ca_drive(index).join("keystone"),
            &target.join("keystone"),
        );
        clone_drives.push(target);
    }
    let original: Vec<PathBuf> = test.drives.ca_drives()[..2].to_vec();
    let (mut token_a, _) = token(60_000_004);
    run_flow_b(&mut test, &mut token_a, "S4 A", false).unwrap();
    let serial_a = test.ca.state().unwrap().main_intermediates()[0].serial();
    test.ca = Ca::open(&roots(&clone_drives)).unwrap();
    let (mut token_b, _) = token(60_000_005);
    run_flow_b(&mut test, &mut token_b, "S4 B", false).unwrap();
    let serial_b = test.ca.state().unwrap().main_intermediates()[0].serial();
    // The primary of one history with the backup of the other.
    test.ca = Ca::open(&[original[0].as_path(), clone_drives[1].as_path()]).unwrap();
    test.now += Duration::minutes(1);
    let report = test.ca.startup_report(test.now).unwrap();
    let Some(Blocker::DrivesDiverged { histories, .. }) = report
        .blockers
        .iter()
        .find(|b| matches!(b, Blocker::DrivesDiverged { .. }))
    else {
        panic!("{:?}", report.blockers);
    };
    assert_eq!(histories.len(), 2);
    assert!(matches!(
        report.comparison,
        DriveComparison::Diverged { .. }
    ));
    let time = confirmed(&test.ca, test.now);
    assert!(
        test.ca
            .plan_revoke(serial_a, RevocationReason::Superseded, time)
            .is_err()
    );
    let known = test.ca.drive_set().known_serials().unwrap();
    assert!(known.contains(&serial_a) && known.contains(&serial_b));
}

#[test]
fn fr14_ac3_a_broken_audit_chain_is_a_blocker_naming_the_first_bad_entry() {
    // Covers: FR-14 AC3, SEC-09
    let mut test = new_ca_with("S5", 2, true);
    let log_path = test.drives.ca_drive(1).join("keystone/audit.log");
    let log = std::fs::read_to_string(&log_path).unwrap();
    std::fs::write(&log_path, log.replacen("S5 Master", "S5 Masker", 1)).unwrap();
    test.reopen();
    test.now += Duration::minutes(1);
    let report = test.ca.startup_report(test.now).unwrap();
    assert!(!report.signing_allowed());
    assert!(
        report
            .blockers
            .iter()
            .any(|b| matches!(b, Blocker::AuditLogBroken { entry: 1, .. })),
        "{:?}",
        report.blockers
    );
    assert!(report.audit.iter().any(|a| matches!(
        a,
        AuditLogStatus::Broken {
            first_bad_entry: 1,
            ..
        }
    )));
    let message = report
        .blockers
        .iter()
        .map(Blocker::message)
        .collect::<Vec<_>>()
        .join(" ");
    assert!(message.contains("entry 1"), "{message}");
}

#[test]
fn fr22_ac4_an_interrupted_operation_blocks_signing_and_opens_recovery() {
    // Covers: FR-22 AC4
    let (mut test, mut token, _) = ca_with_main("S6", 60_000_006);
    testing::arm_fault(testing::FaultPoint::AfterSignedRecorded);
    assert!(matches!(
        run_flow_c(&mut test, &mut token, "S6", 1, false).unwrap_err(),
        OpsError::InjectedFault(_)
    ));
    test.reopen();
    test.now += Duration::minutes(1);
    let report = test.ca.startup_report(test.now).unwrap();
    assert!(
        report
            .blockers
            .iter()
            .any(|b| matches!(b, Blocker::PendingOperation { .. }))
    );
    assert_eq!(report.recovery.len(), 1);
    let time = confirmed(&test.ca, test.now);
    let request = SubIntermediateRequest::new(
        test_name("S6 again"),
        constrained(&["starnet"]),
        Some(main_crl()),
    );
    assert!(
        blocked(test.ca.plan_sub_intermediate(&request, time).unwrap_err())
            .iter()
            .any(|b| matches!(b, Blocker::PendingOperation { .. }))
    );
}

#[test]
fn fr17_ac2_a_clock_earlier_than_the_newest_entry_blocks_signing() {
    // Covers: FR-17 AC1, FR-17 AC2, SEC-16
    let (mut test, mut token, _) = ca_with_main("S7", 60_000_007);
    let report = test
        .ca
        .startup_report(test.now - Duration::hours(1))
        .unwrap();
    assert!(report.blockers.iter().any(|b| matches!(b, Blocker::ClockBlocked(problems) if matches!(problems[0], ClockProblem::EarlierThanBaseline { .. }))));
    assert!(matches!(
        clock::confirm(&report.clock, false).unwrap_err(),
        ClockError::Blocked(_)
    ));
    // A time confirmed before a later operation is stale and blocks signing.
    let stale = confirmed(&test.ca, test.now + Duration::seconds(30));
    run_flow_c(&mut test, &mut token, "S7", 1, false).unwrap();
    let request = SubIntermediateRequest::new(test_name("S7 b"), constrained(&["starnet"]), None);
    assert!(
        blocked(test.ca.plan_sub_intermediate(&request, stale).unwrap_err())
            .iter()
            .any(|b| matches!(b, Blocker::ClockConfirmationStale { .. }))
    );
    // More than 5 years after the build date needs an explicit confirmation.
    let far = keystone_core::build_info::build_date() + Duration::days(366 * 5 + 2);
    let assessment = test.ca.assess_clock(far);
    assert!(assessment.needs_explicit_confirmation());
    assert!(clock::confirm(&assessment, false).is_err());
    assert!(clock::confirm(&assessment, true).is_ok());
}

#[test]
fn fr17_ac3_a_clock_correction_lets_signing_resume_and_lists_future_certificates() {
    // Covers: FR-17 AC3
    let (mut test, mut token, _) = ca_with_main("S8", 60_000_008);
    let real_now = test.now;
    // An operation recorded with a wrong future date (10 days ahead).
    test.now += Duration::days(10);
    let (future, _) = run_flow_c(&mut test, &mut token, "S8", 1, false).unwrap();
    let back = real_now + Duration::minutes(5);
    let report = test.ca.startup_report(back).unwrap();
    assert!(
        report
            .blockers
            .iter()
            .any(|b| matches!(b, Blocker::ClockBlocked(_)))
    );
    test.ca.correct_clock_baseline(back).unwrap();
    let report = test.ca.startup_report(back).unwrap();
    assert!(report.signing_allowed(), "{:?}", report.blockers);
    assert!(report.warnings.iter().any(|w| matches!(w, StartupWarning::FutureDatedCertificates(list) if list.contains(&future.serial))));
    // Signing resumes at the corrected time.
    test.now = back;
    run_flow_c(&mut test, &mut token, "S8 b", 2, false).expect("signing after the correction");
}
