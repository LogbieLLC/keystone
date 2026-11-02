//! Fault injection (FR-22 AC6, AC7, SEC-22, TESTING.md "Fault injection").
//!
//! Each operation is interrupted at **every** drive change it makes (every atomic
//! write, move and delete on every drive, so also between the writes to two drives),
//! and at every named step (before signing, after signing, after the signature is
//! journaled, after staging, after moving into place, after the audit entry). After each
//! interruption the CA is reopened from its drives, as after a restart, the recovery
//! screen's first action is taken until nothing is pending, and the result must be
//! consistent with no lost record.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use keystone_core::crypto::CancelFlag;
use keystone_core::model::RevocationReason;
use keystone_core::ops::testing::{self, FaultPoint};
use keystone_core::ops::{
    Ca, ExportStatus, IssuerUnlock, NoProgress, OpsError, Progress, RecoveryAction,
    RecoverySecrets, Step,
};
use keystone_core::store::OperationState;
use keystone_testkit::{SimulatedYubiKey, TestDrives};

use crate::support::*;

type Run = dyn Fn(&mut TestCa, &mut SimulatedYubiKey) -> Result<(), OpsError>;

/// Runs `run` once cleanly on a copy of `base` and returns how many drive changes it
/// makes; then, for every change, runs it on a fresh copy crashing at that change,
/// restarts, recovers and checks consistency.
fn sweep_drive_changes(
    base: &TestCa,
    label: &str,
    token_for: &dyn Fn(u32) -> SimulatedYubiKey,
    run: &Run,
) -> u32 {
    let mut probe = clone_ca(base);
    let mut token = token_for(0);
    testing::drive_change_count();
    run(&mut probe, &mut token).expect("clean run");
    let total = testing::drive_change_count();
    assert!(total > 5, "{label}: only {total} drive changes");
    for crash_at in 0..total {
        let mut test = clone_ca(base);
        let mut token = token_for(crash_at + 1);
        testing::drive_change_count();
        testing::crash_on_drive_change(crash_at);
        let error = run(&mut test, &mut token).expect_err("the crash stops the operation");
        assert!(
            matches!(error.root_cause(), OpsError::Store(_)) || matches!(error, OpsError::Store(_)),
            "{label} change {crash_at}: {error}"
        );
        test.reopen();
        recover_all(&mut test, Some(&mut token), label);
        assert_no_lost_record(&test.ca);
    }
    total
}

/// Interrupts `run` at each named step, restarts, recovers and checks consistency.
fn sweep_named_points(
    base: &TestCa,
    label: &str,
    token_for: &dyn Fn(u32) -> SimulatedYubiKey,
    run: &Run,
) {
    for (index, point) in [
        FaultPoint::BeforeSigning,
        FaultPoint::AfterSigning,
        FaultPoint::AfterSignedRecorded,
        FaultPoint::AfterStaged,
        FaultPoint::AfterCommit,
        FaultPoint::AfterAudit,
    ]
    .into_iter()
    .enumerate()
    {
        let mut test = clone_ca(base);
        let mut token = token_for(100 + index as u32);
        testing::arm_fault(point);
        let error = run(&mut test, &mut token).expect_err("the fault stops the operation");
        assert!(
            matches!(error, OpsError::InjectedFault(_)),
            "{label} {point:?}: {error}"
        );
        test.reopen();
        let taken = recover_all(&mut test, Some(&mut token), label);
        assert_eq!(taken.len(), 1, "{label} {point:?}: {taken:?}");
        let expected_done = !matches!(point, FaultPoint::BeforeSigning | FaultPoint::AfterSigning);
        let journal = test.ca.drive_set().drives()[0].journal().unwrap();
        let (_, last) = journal.iter().next_back().unwrap();
        assert_eq!(
            last.state() == OperationState::Completed,
            expected_done,
            "{label} {point:?}: {taken:?}"
        );
        assert_no_lost_record(&test.ca);
    }
}

#[test]
fn fr22_ac6_flow_c_recovers_from_an_interruption_at_every_step() {
    // Covers: FR-22 AC6, FR-22 AC3, FR-12 AC2, SEC-22
    let (base, token, _) = ca_with_main("F1", 80_000_001);
    let token_for = |_| token.reopen();
    let run: &Run = &|test, token| run_flow_c(test, token, "F1", 1, false).map(|_| ());
    let total = sweep_drive_changes(&base, "F1", &token_for, run);
    assert!(total >= 20, "{total}");
    sweep_named_points(&base, "F1", &token_for, run);
}

#[test]
fn fr22_ac6_flow_d_and_refresh_recover_from_an_interruption_at_every_step() {
    // Covers: FR-22 AC6, FR-13 AC1, FR-13 AC4
    let (mut base, mut token, _) = ca_with_main("F2", 80_000_002);
    let (sub, _) = run_flow_c(&mut base, &mut token, "F2", 2, false).unwrap();
    let token_for = |_| token.reopen();
    let revoke: &Run = &move |test, token| {
        let time = test.tick();
        let pin = s(PIN);
        test.ca
            .plan_revoke(sub.serial, RevocationReason::KeyCompromise, time)?
            .execute(
                &test.ca,
                IssuerUnlock::YubiKey { token, pin: &pin },
                None,
                &NoProgress,
                &CancelFlag::new(),
            )
            .map(|_| ())
    };
    sweep_drive_changes(&base, "F2", &token_for, revoke);
    sweep_named_points(&base, "F2", &token_for, revoke);
    let master = base.master.serial;
    let refresh: &Run = &move |test, _| {
        let time = test.tick();
        let words = test.master_entered();
        test.ca
            .plan_refresh_crl(master, time)?
            .execute(
                &test.ca,
                IssuerUnlock::Master(&words),
                None,
                &NoProgress,
                &CancelFlag::new(),
            )
            .map(|_| ())
    };
    sweep_drive_changes(&base, "F2", &token_for, refresh);
}

#[test]
fn fr22_ac6_flow_e_recovers_from_an_interruption_at_every_step() {
    // Covers: FR-22 AC6, FR-15 AC1
    let (mut base, mut token, controller) = ca_with_main("F3", 80_000_003);
    run_flow_c(&mut base, &mut token, "F3", 3, false).unwrap();
    controller.remove();
    let token_for = |_| token.reopen();
    let replace: &Run = &|test, _| {
        let time = test.tick();
        let words = test.master_entered();
        test.ca
            .plan_replace_yubikey(RevocationReason::KeyCompromise, time)?
            .execute(
                &test.ca,
                IssuerUnlock::Master(&words),
                None,
                &NoProgress,
                &CancelFlag::new(),
            )
            .map(|_| ())
    };
    sweep_drive_changes(&base, "F3", &token_for, replace);
    sweep_named_points(&base, "F3", &token_for, replace);
}

#[test]
fn fr22_ac6_ac7_flow_b_recovers_from_an_interruption_at_every_step() {
    // Covers: FR-22 AC6, FR-22 AC7, FR-22 AC5
    let base = new_ca("F4");
    let token_for = |n: u32| token(80_100_000 + n).0;
    let run: &Run = &|test, token| run_flow_b(test, token, "F4", false).map(|_| ());
    let total = sweep_drive_changes(&base, "F4", &token_for, run);
    assert!(total >= 25, "{total}");
}

#[test]
fn fr22_ac6_flow_a_recovers_from_an_interruption_at_every_step_after_drive_setup() {
    // Covers: FR-22 AC6, FR-13 AC6, SEC-20
    // Setting up the empty drives writes two files per drive (audit log, then the drive
    // identity last). An interruption there leaves a drive that is classified as
    // damaged and is never reused automatically (SEC-20); the sweep starts after it.
    const DRIVE_SETUP_CHANGES: u32 = 4;
    let now = base_time();
    let (passphrase, words) = master_passphrase();
    let probe = TestDrives::new(2);
    testing::drive_change_count();
    run_flow_a(&probe, "F5", now, &passphrase, None).expect("clean run");
    let total = testing::drive_change_count();
    let master = entered(&words);
    for crash_at in DRIVE_SETUP_CHANGES..total {
        let drives = TestDrives::new(2);
        testing::drive_change_count();
        testing::crash_on_drive_change(crash_at);
        let error = run_flow_a(&drives, "F5", now, &passphrase, None).unwrap_err();
        assert!(
            matches!(error.root_cause(), OpsError::Store(_)),
            "change {crash_at}: {error}"
        );
        testing::reset();
        let roots: Vec<&Path> = drives.ca_drives().iter().map(PathBuf::as_path).collect();
        let ca = Ca::open(&roots).unwrap();
        let time = confirmed(&ca, now + time::Duration::minutes(1));
        for item in ca.recovery_items(None).unwrap() {
            let action = &item
                .actions
                .first()
                .unwrap_or_else(|| panic!("{item:?}"))
                .action;
            assert!(!matches!(action, RecoveryAction::ResumeYubikeySetup { .. }));
            ca.run_recovery(
                item.operation,
                action,
                &RecoverySecrets {
                    master_passphrase: Some(&master),
                },
                time,
            )
            .unwrap();
        }
        assert_no_lost_record(&ca);
        if ca.state().unwrap().master().is_none() {
            // Abandoned before anything was signed: Flow A runs again on the same drives.
            drop(ca);
            let later = now + time::Duration::minutes(2);
            let outcome =
                run_flow_a(&drives, "F5", later, &passphrase, None).expect("Flow A again");
            assert_no_lost_record(&outcome.ca);
        }
    }
}

/// Flow C cancelled right after its encrypted key was staged; the cancel itself fails
/// at drive change `fail_at` (counted from the start of the cancel), like a pulled
/// drive. Returns the operation's error.
fn cancel_flow_c_failing_at(
    test: &mut TestCa,
    token: &mut SimulatedYubiKey,
    fail_at: Option<u32>,
) -> OpsError {
    let (plan, passphrase, _) = plan_flow_c(test, "FC").unwrap();
    testing::supply_generated_key(keystone_testkit::keys::rsa4096(5));
    let cancel = CancelFlag::new();
    let flag = cancel.clone();
    let progress = move |report: Progress| {
        if let Progress::Step { step, .. } = report {
            match step {
                Step::StagingKey => flag.cancel(),
                Step::Cancelling => {
                    testing::drive_change_count();
                    if let Some(allowed) = fail_at {
                        testing::fail_drive_change(allowed);
                    }
                }
                _ => {}
            }
        }
    };
    plan.execute(
        &test.ca,
        token,
        &s(PIN),
        &passphrase,
        None,
        &progress,
        &cancel,
    )
    .unwrap_err()
}

#[test]
fn fr22_ac6_a_cancel_interrupted_at_every_drive_change_recovers() {
    // Covers: FR-22 AC6, FR-16 AC2, FR-22 AC4, SEC-22
    // Review findings 1 and 2: an interrupted cancel must never corrupt the journals or
    // block the CA; recovery after a restart reaches a consistent state.
    let (base, token, _) = ca_with_main("FC", 80_000_007);
    let mut probe = clone_ca(&base);
    let mut probe_token = token.reopen();
    let error = cancel_flow_c_failing_at(&mut probe, &mut probe_token, None);
    assert!(matches!(error, OpsError::Cancelled { .. }), "{error}");
    let total = testing::drive_change_count();
    assert!(total >= 6, "a cancel makes {total} drive changes");
    assert_no_lost_record(&probe.ca);
    for fail_at in 0..total {
        let mut test = clone_ca(&base);
        let mut token = token.reopen();
        let error = cancel_flow_c_failing_at(&mut test, &mut token, Some(fail_at));
        assert!(
            matches!(error, OpsError::Interrupted { .. }),
            "change {fail_at}: {error}"
        );
        test.reopen();
        let taken = recover_all(&mut test, None, "FC");
        assert_eq!(taken.len(), 1, "change {fail_at}: {taken:?}");
        assert_no_lost_record(&test.ca);
        // The CA signs again afterwards.
        run_flow_c(&mut test, &mut token, "FC after", 4, false)
            .unwrap_or_else(|e| panic!("change {fail_at}: {e}"));
    }
}

#[test]
fn fr22_ac2_an_export_interrupted_after_completion_is_retried() {
    // Covers: FR-22 AC2, FR-09 AC1
    let (mut test, mut token, _) = ca_with_main("F6", 80_000_006);
    testing::arm_fault(FaultPoint::BeforeExport);
    let (outcome, _) = run_flow_c(&mut test, &mut token, "F6", 4, true).unwrap();
    assert!(matches!(&outcome.export, ExportStatus::Failed(reason) if reason.contains("injected")));
    testing::reset();
    assert_consistent(&test.ca);
    let time = test.tick();
    let files = test
        .ca
        .export_operation(outcome.operation, test.export(), time)
        .unwrap();
    assert_eq!(files.len(), 3);
}
