//! Tests for drive comparison and repair (FR-12 AC3, FR-19 AC1, SEC-22).
#![forbid(unsafe_code)]

use std::fs;

use keystone_testkit::TestDrives;

use super::*;
use crate::model::CaLevel;
use crate::store::audit::{AuditLog, ClockCorrectionDetails, parse_audit_log};
use crate::store::fault;
use crate::store::journal::{OperationKind, OperationState};
use crate::store::testutil::{cert, issue, issue_master, new_ca, open_all, open_some, serial, ts};

/// Three drives: operation 1 on all; then (on drives 0 and 1 only) operation 2, a clock
/// correction (audit only) and operation 3. Drive 2 is behind.
fn behind_setup() -> TestDrives {
    let drives = TestDrives::new(3);
    let set = new_ca(&drives);
    issue_master(&set, 1, ts(10));
    let set = open_some(&drives, &[0, 1]);
    issue(
        &set,
        OperationKind::SetupYubikey,
        cert(serial(2), CaLevel::MainIntermediate, serial(1)),
        ts(20),
    );
    let mut correction = AuditDraft::new(AuditAction::ClockCorrection, "", AuditResult::Success);
    correction.details = Some(AuditDetails {
        clock_correction: Some(ClockCorrectionDetails {
            previous_newest: ts(20),
            confirmed: ts(25),
        }),
        ..AuditDetails::default()
    });
    set.append_audit(&[correction], ts(25)).expect("correction");
    issue(
        &set,
        OperationKind::CreateSubIntermediate,
        cert(serial(3), CaLevel::SubIntermediate, serial(2)),
        ts(30),
    );
    drives
}

fn plans(comparison: DriveComparison) -> Vec<RepairPlan> {
    match comparison {
        DriveComparison::Behind { plans } => plans,
        other => panic!("expected behind drives, got {other:?}"),
    }
}

/// The invariant behind "the completed entry is written last": on every drive, every
/// operation with a final journal entry has every listed output verified and its audit
/// entries in the log.
fn assert_finished_operations_are_whole(drives: &TestDrives) {
    let set = open_all(drives);
    for drive in set.drives() {
        let log = drive.audit_log().expect("log verifies");
        for (operation, journal) in drive.journal().expect("journal") {
            if let Some(head) = journal.audit_head() {
                assert_eq!(
                    log.entry_hash(head.seq),
                    Some(head.sha256),
                    "{operation} on {}",
                    drive.label()
                );
            }
            for output in journal.completed_outputs().unwrap_or_default() {
                let data = drive
                    .read_at(
                        output.path.dir().name(),
                        output.path.name(),
                        MAX_OUTPUT_FILE_BYTES,
                    )
                    .expect("read")
                    .unwrap_or_else(|| panic!("{} missing for {operation}", output.path));
                assert_eq!(sha256(&data), output.sha256);
            }
        }
    }
}

#[test]
fn fr19_ac1_in_sync_drives_allow_signing() {
    // Covers: FR-19 AC1, FR-12 AC3, SEC-09
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    assert_eq!(set.compare().expect("compare"), DriveComparison::InSync);
    issue_master(&set, 1, ts(10));
    let set = open_all(&drives);
    let comparison = set.compare().expect("compare");
    assert!(comparison.signing_allowed());
    assert!(set.recovery_report().expect("recovery").is_clean());
}

#[test]
fn fr12_ac3_exact_prefix_lists_missing_operations_and_repairs_them_whole() {
    // Covers: FR-12 AC3, SEC-22, SEC-11
    let drives = behind_setup();
    let set = open_all(&drives);
    let comparison = set.compare().expect("compare");
    assert!(!comparison.signing_allowed());
    let plans = plans(comparison);
    assert_eq!(plans.len(), 1);
    let plan = &plans[0];
    assert_eq!(set.drives()[plan.target].root(), drives.ca_drive(2));
    assert_eq!(plan.steps.len(), 3);
    match &plan.steps[0] {
        RepairStep::Operation {
            operation,
            entries,
            outputs,
            journal_entries,
        } => {
            assert_eq!(*operation, OperationId(2));
            assert_eq!(entries.len(), 1);
            assert_eq!(outputs.len(), 3);
            assert_eq!(*journal_entries, 4);
        }
        other => panic!("expected an operation, got {other:?}"),
    }
    assert!(
        matches!(&plan.steps[1], RepairStep::AuditOnly { entries } if entries[0].action == AuditAction::ClockCorrection)
    );
    assert!(
        matches!(&plan.steps[2], RepairStep::Operation { operation, .. } if *operation == OperationId(3))
    );
    set.repair(&plans, ts(40)).expect("repair");
    // Now every drive holds the same history, files and journals.
    let set = open_all(&drives);
    assert_eq!(set.compare().expect("compare"), DriveComparison::InSync);
    let log = set.audit_log().expect("same log everywhere");
    assert_eq!(
        log.entries().last().expect("entry").action,
        AuditAction::DriveRepair
    );
    assert!(set.ensure_in_sync().is_ok());
    let repaired = &set.drives()[plan.target];
    for op in [OperationId(2), OperationId(3)] {
        let journal = repaired
            .operation_journal(op)
            .expect("read")
            .expect("copied");
        assert_eq!(journal.state(), OperationState::Completed);
    }
    assert_eq!(
        set.issuance_record().expect("record").certificates().len(),
        3
    );
    assert_finished_operations_are_whole(&drives);
}

#[test]
fn fr12_ac3_a_repair_interrupted_at_any_step_never_makes_a_drive_look_repaired() {
    // Covers: FR-12 AC3, FR-22 AC6, SEC-22
    let drives = behind_setup();
    let set = open_all(&drives);
    let plans_all = plans(set.compare().expect("compare"));
    fault::take_count();
    set.repair(&plans_all, ts(40)).expect("repair");
    let total = fault::take_count();
    assert!(total > 10, "{total}");
    for allowed in 0..total {
        let drives = behind_setup();
        let set = open_all(&drives);
        let plan = plans(set.compare().expect("compare"));
        fault::fail_after(allowed);
        let result = set.repair(&plan, ts(40));
        fault::disarm();
        assert!(
            result.is_err(),
            "fault after {allowed} changes must stop the repair"
        );
        assert_finished_operations_are_whole(&drives);
        // The interrupted drive is still behind (or in sync), never diverged or damaged,
        // and a second repair finishes the job.
        let set = open_all(&drives);
        match set.compare().expect("compare") {
            DriveComparison::InSync => {}
            DriveComparison::Behind { plans } => set.repair(&plans, ts(50)).expect("second repair"),
            other => panic!("after a fault at {allowed}: {other:?}"),
        }
        assert_eq!(
            open_all(&drives).compare().expect("compare"),
            DriveComparison::InSync
        );
        assert_finished_operations_are_whole(&drives);
    }
}

#[test]
fn fr12_ac3_divergent_histories_block_signing_and_are_shown_side_by_side() {
    // Covers: FR-12 AC3, SEC-22
    let drives = TestDrives::new(3);
    let set = new_ca(&drives);
    issue_master(&set, 1, ts(10));
    // Drives 0 and 1 get two more entries.
    let pair = open_some(&drives, &[0, 1]);
    for n in 0..2 {
        pair.append_audit(
            &[AuditDraft::new(
                AuditAction::Export,
                format!("A{n}"),
                AuditResult::Success,
            )],
            ts(20),
        )
        .expect("append");
    }
    // Drive 2 gets one different entry after the same common point.
    let path = drives.ca_drive(2).join("keystone/audit.log");
    let log: AuditLog = parse_audit_log(&fs::read(&path).expect("read")).expect("valid");
    let (bytes, _) = log
        .with_appended(
            &[AuditDraft::new(
                AuditAction::Export,
                "B",
                AuditResult::Success,
            )],
            ts(21),
        )
        .expect("append");
    fs::write(&path, bytes).expect("write");
    let set = open_all(&drives);
    match set.compare().expect("compare") {
        DriveComparison::Diverged { common, histories } => {
            assert_eq!(common, 1);
            assert_eq!(histories.len(), 2);
            let longer = histories
                .iter()
                .find(|h| h.drives.len() == 2)
                .expect("pair history");
            assert_eq!(longer.entries.len(), 2);
            let other = histories
                .iter()
                .find(|h| h.drives.len() == 1)
                .expect("single history");
            assert_eq!(other.entries[0].subject, "B");
        }
        other => panic!("expected divergence, got {other:?}"),
    }
    // Signing is blocked: no operation can begin, and nothing is chosen by length.
    assert!(!set.compare().expect("compare").signing_allowed());
    assert!(matches!(
        set.begin_operation(OperationKind::Revoke, "x", &[], ts(30)),
        Err(StoreError::OutOfSync(_))
    ));
    let diverged = set
        .drives()
        .iter()
        .position(|d| d.root() == drives.ca_drive(2))
        .expect("drive 2");
    assert!(set.plan_repair(0, diverged).is_err());
}

#[test]
fn damaged_outputs_block_signing() {
    // Covers: FR-19 AC1, FR-22 AC2
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let op = issue_master(&set, 1, ts(10));
    let journal = set.drives()[1]
        .operation_journal(op)
        .expect("read")
        .expect("journal");
    let output = &journal.completed_outputs().expect("outputs")[0];
    let path = drives
        .ca_drive(1)
        .join("keystone")
        .join(output.path.to_string());
    fs::write(&path, b"changed").expect("damage");
    match open_all(&drives).compare().expect("compare") {
        DriveComparison::Damaged { problems } => {
            assert!(problems[0].contains("was changed"), "{problems:?}");
        }
        other => panic!("expected damage, got {other:?}"),
    }
    fs::remove_file(&path).expect("remove");
    match open_all(&drives).compare().expect("compare") {
        DriveComparison::Damaged { problems } => assert!(problems[0].contains("missing")),
        other => panic!("expected damage, got {other:?}"),
    }
}

#[test]
fn regression_begin_operation_refuses_whenever_compare_reports_damage() {
    // Covers: SEC-22, FR-19 AC1, FR-22 AC2, FR-14 AC3
    // Regression (review finding 4): with a certificate file deleted from the backup,
    // compare() said Damaged but begin_operation still started a new operation.
    let begin = |drives: &TestDrives| {
        open_all(drives)
            .begin_operation(
                OperationKind::CreateSubIntermediate,
                "CN=KEYSTONE TEST sub",
                &[serial(3)],
                ts(20),
            )
            .map(|op| op.id())
    };
    // A completed output missing on the backup.
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let op = issue_master(&set, 1, ts(10));
    let output = set.drives()[1]
        .operation_journal(op)
        .expect("read")
        .expect("journal")
        .completed_outputs()
        .expect("outputs")[0]
        .clone();
    let path = |drives: &TestDrives, drive: usize| {
        drives
            .ca_drive(drive)
            .join("keystone")
            .join(output.path.to_string())
    };
    fs::remove_file(path(&drives, 1)).expect("remove");
    assert!(
        !open_all(&drives)
            .compare()
            .expect("compare")
            .signing_allowed()
    );
    let error = begin(&drives).expect_err("refused while damaged");
    assert!(error.to_string().contains("missing"), "{error}");
    // A changed output on the primary.
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    issue_master(&set, 1, ts(10));
    fs::write(path(&drives, 0), b"changed").expect("damage");
    let error = begin(&drives).expect_err("refused while damaged");
    assert!(error.to_string().contains("was changed"), "{error}");
    // The same last audit entry changed on both drives: the logs agree and the chain
    // still verifies, but the journal's recorded audit head no longer matches.
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    issue_master(&set, 1, ts(10));
    for drive in 0..2 {
        let log = drives.ca_drive(drive).join("keystone/audit.log");
        let text = fs::read_to_string(&log).expect("read");
        fs::write(&log, text.replace("Master", "Mister")).expect("write");
    }
    assert!(
        !open_all(&drives)
            .compare()
            .expect("compare")
            .signing_allowed()
    );
    let error = begin(&drives).expect_err("refused while damaged");
    assert!(error.to_string().contains("audit entry 1"), "{error}");
}

#[test]
fn fr12_ac3_a_behind_drive_holding_a_different_file_is_never_overwritten() {
    // Covers: FR-12 AC3, SEC-20
    let drives = behind_setup();
    let set = open_all(&drives);
    let plan = plans(set.compare().expect("compare"));
    let RepairStep::Operation { outputs, .. } = &plan[0].steps[0] else {
        panic!("expected an operation step");
    };
    let conflicting = drives
        .ca_drive(2)
        .join("keystone")
        .join(outputs[0].path.to_string());
    fs::write(&conflicting, b"KEYSTONE TEST different").expect("write");
    match open_all(&drives).compare().expect("compare") {
        DriveComparison::Damaged { problems } => {
            assert!(problems[0].contains("never overwritten"), "{problems:?}");
        }
        other => panic!("expected a blocking problem, got {other:?}"),
    }
    assert!(matches!(
        open_all(&drives).repair(&plan, ts(40)),
        Err(StoreError::Unsafe(_))
    ));
    assert_eq!(
        fs::read(&conflicting).expect("read"),
        b"KEYSTONE TEST different"
    );
}

#[test]
fn fr12_ac3_a_plan_is_refused_when_the_drives_changed_after_it_was_shown() {
    // Covers: FR-12 AC3
    let drives = behind_setup();
    let shown = plans(open_all(&drives).compare().expect("compare"));
    open_some(&drives, &[0, 1])
        .append_audit(
            &[AuditDraft::new(
                AuditAction::Export,
                "late",
                AuditResult::Success,
            )],
            ts(35),
        )
        .expect("append");
    assert!(matches!(
        open_all(&drives).repair(&shown, ts(40)),
        Err(StoreError::Unsafe(_))
    ));
}

#[test]
fn fr12_ac3_an_unfinished_operation_on_the_source_is_not_copied() {
    // Covers: FR-12 AC3, FR-22 AC4
    let drives = TestDrives::new(3);
    let set = new_ca(&drives);
    issue_master(&set, 1, ts(10));
    let pair = open_some(&drives, &[0, 1]);
    let mut op = pair
        .begin_operation(OperationKind::Revoke, "CN=KEYSTONE TEST", &[], ts(20))
        .expect("begin");
    op.append_audit(
        &[AuditDraft::new(
            AuditAction::Revoke,
            "CN=KEYSTONE TEST",
            AuditResult::Success,
        )],
        ts(20),
    )
    .expect("audit");
    drop(op); // interrupted before its completed entry
    match open_all(&drives).compare().expect("compare") {
        DriveComparison::Damaged { problems } => {
            assert!(problems[0].contains("recovery"), "{problems:?}");
        }
        other => panic!("expected a blocking problem, got {other:?}"),
    }
}

fn audit_only(action: AuditAction) -> AuditDraft {
    AuditDraft::new(action, "", AuditResult::Success)
}

/// Repairs every behind drive (the plans shown by `compare`) and checks the result.
fn repair_all_and_check(drives: &TestDrives, context: &str) {
    let set = open_all(drives);
    let shown = plans(set.compare().unwrap_or_else(|e| panic!("{context}: {e}")));
    set.repair(&shown, ts(90))
        .unwrap_or_else(|e| panic!("{context}: {e}"));
    let set = open_all(drives);
    assert_eq!(
        set.compare().expect("compare"),
        DriveComparison::InSync,
        "{context}"
    );
    assert_finished_operations_are_whole(drives);
}

#[test]
fn regression_an_audit_only_entry_while_an_operation_is_pending_keeps_drives_repairable() {
    // Covers: FR-12 AC3, FR-22 AC4, FR-17 AC3, SEC-22
    // Regression (review finding 6): a clock correction (or binary-hash record, drive
    // repair, export) appended while an operation was pending made the completed entry
    // record the log head instead of the operation's own last entry, and every behind
    // drive became unrepairable ("operation 1 is not finished on primary").
    let drives = TestDrives::new(3);
    new_ca(&drives);
    let pair = open_some(&drives, &[0, 1]);
    let record = cert(serial(1), CaLevel::Master, serial(1));
    let mut op = pair
        .begin_operation(OperationKind::CreateMaster, "m", &[serial(1)], ts(5))
        .expect("begin");
    let id = op.id();
    op.record_signed(
        crate::store::journal::SignedObject::Certificate {
            record: Box::new(record),
            pem: crate::store::testutil::cert_pem(serial(1)),
        },
        ts(5),
    )
    .expect("signed");
    op.stage(
        crate::store::OutputPath::new(crate::store::OutputDir::Certs, "m.crt").expect("path"),
        crate::store::testutil::cert_pem(serial(1)).as_bytes(),
    )
    .expect("stage");
    op.seal_staging(ts(5)).expect("seal");
    op.commit().expect("commit");
    op.append_audit(&[audit_only(AuditAction::CreateMaster)], ts(5))
        .expect("audit");
    drop(op); // interrupted before its completed entry
    for action in [
        AuditAction::ClockCorrection,
        AuditAction::BinaryHashRecorded,
    ] {
        let mut draft = audit_only(action);
        if action == AuditAction::ClockCorrection {
            draft.details = Some(AuditDetails {
                clock_correction: Some(ClockCorrectionDetails {
                    previous_newest: ts(5),
                    confirmed: ts(6),
                }),
                ..AuditDetails::default()
            });
        }
        open_some(&drives, &[0, 1])
            .append_audit(&[draft], ts(6))
            .expect("audit-only append while pending");
    }
    let pair = open_some(&drives, &[0, 1]);
    pair.finish_operation(id, 0, ts(7)).expect("finish");
    let journal = pair.drives()[0]
        .operation_journal(id)
        .expect("read")
        .expect("journal");
    assert_eq!(journal.state(), OperationState::Completed);
    // The completed entry records the operation's own last entry (seq 1), not the head.
    assert_eq!(journal.audit_head().expect("head").seq, 1);
    // Drive 2 missed everything: it is behind and repairable.
    repair_all_and_check(&drives, "audit-only entries after the operation's own");
}

#[test]
fn regression_audit_only_entries_between_an_operations_entries_keep_drives_repairable() {
    // Covers: FR-12 AC3, FR-22 AC4, FR-16 AC2
    // An interrupted cancel wrote its audit entry; a clock correction followed while the
    // operation was pending; then it was abandoned. Its own entries are not adjacent, and
    // a drive that missed all of it must still be repairable.
    let drives = TestDrives::new(3);
    new_ca(&drives);
    let pair = open_some(&drives, &[0, 1]);
    let op = pair
        .begin_operation(
            OperationKind::Revoke,
            "CN=KEYSTONE TEST",
            &[serial(4)],
            ts(5),
        )
        .expect("begin");
    // cancel: audit primary, audit backup, cancelled primary -> stop before that.
    fault::fail_after(2);
    assert!(op.cancel(ts(6)).is_err());
    fault::disarm();
    open_some(&drives, &[0, 1])
        .append_audit(&[audit_only(AuditAction::Export)], ts(7))
        .expect("audit-only append while pending");
    let pair = open_some(&drives, &[0, 1]);
    pair.abandon_operation(OperationId(1), ts(8))
        .expect("abandon");
    let log = pair.audit_log().expect("log");
    let own: Vec<u64> = log
        .entries()
        .iter()
        .filter(|e| e.operation == Some(OperationId(1)))
        .map(|e| e.seq)
        .collect();
    assert_eq!(own, vec![1, 3], "the operation's entries are not adjacent");
    repair_all_and_check(&drives, "entries of no operation between its own");
}
