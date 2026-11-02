//! Tests for "Replace a lost drive" (SEC-11, T-11, FR-12 AC1, SEC-20).
#![forbid(unsafe_code)]

use std::fs;

use keystone_testkit::TestDrives;

use super::*;
use crate::model::CaLevel;
use crate::store::fault;
use crate::store::journal::OperationKind;
use crate::store::testutil::{cert, issue, issue_master, new_ca, open_some, serial, ts};

/// A CA on `count` drives with a master, a main intermediate and an export entry.
fn ca(count: usize) -> TestDrives {
    let drives = TestDrives::new(count);
    let set = new_ca(&drives);
    issue_master(&set, 1, ts(10));
    issue(
        &set,
        OperationKind::SetupYubikey,
        cert(serial(2), CaLevel::MainIntermediate, serial(1)),
        ts(20),
    );
    set.append_audit(
        &[AuditDraft::new(
            AuditAction::Export,
            "CN=KEYSTONE TEST",
            AuditResult::Success,
        )],
        ts(21),
    )
    .expect("export entry");
    drives
}

fn added_entries(set: &DriveSet) -> Vec<AuditDetails> {
    set.audit_log()
        .expect("log")
        .entries()
        .iter()
        .filter(|e| e.action == AuditAction::DriveRepair)
        .filter_map(|e| e.details.clone())
        .collect()
}

#[test]
fn sec11_a_lost_primary_is_replaced_and_a_backup_promoted() {
    // Covers: SEC-11, FR-12 AC1, FR-12 AC2
    let mut drives = ca(2);
    let new = drives.add_ca_drive();
    // The primary (drive 0) is lost: only the backup is connected.
    let backup = open_some(&drives, &[1]);
    assert!(matches!(
        backup.ensure_writable(),
        Err(StoreError::NotEnoughDrives {
            primaries: 0,
            backups: 1
        })
    ));
    assert!(
        backup
            .begin_operation(OperationKind::Revoke, "x", &[], ts(30))
            .is_err()
    );
    let plan = backup.plan_add_drive(&new).expect("plan");
    assert_eq!(plan.state, NewDriveState::Empty);
    assert_eq!(plan.operations, 2);
    assert_eq!(plan.files, 6);
    assert_eq!(plan.audit_entries, 3);
    let promoted = backup.drives()[0].identity().drive_id;
    assert_eq!(plan.promote, Some(promoted));
    let set = backup.add_drive(&plan, ts(30)).expect("add");
    set.ensure_writable().expect("a primary and a backup again");
    assert_eq!(set.drives()[0].identity().drive_id, promoted);
    assert_eq!(set.drives()[0].role(), DriveRole::Primary);
    assert_eq!(
        set.drives()[0].identity().role,
        DriveRole::Backup,
        "never rewritten"
    );
    assert_eq!(set.compare().expect("compare"), DriveComparison::InSync);
    let details = added_entries(&set);
    assert_eq!(details.len(), 2);
    let new_id = set.drives()[1].identity().drive_id;
    assert_eq!(details[0].drive_added, Some(new_id));
    assert_eq!(details[1].primary_promoted, Some(promoted));
    // The CA writes again.
    set.begin_operation(OperationKind::Revoke, "CN=KEYSTONE TEST", &[], ts(31))
        .expect("begin")
        .cancel(ts(31))
        .expect("cancel");
    // The lost primary found again is a (behind) backup now, never a second primary.
    let all = open_some(&drives, &[0, 1, 2]);
    assert_eq!(
        all.drives()
            .iter()
            .filter(|d| d.role() == DriveRole::Primary)
            .count(),
        1
    );
    match all.compare().expect("compare") {
        DriveComparison::Behind { plans } => {
            all.repair(&plans, ts(40)).expect("repair");
        }
        other => panic!("expected the old primary behind, got {other:?}"),
    }
    assert_eq!(
        open_some(&drives, &[0, 1, 2]).compare().expect("compare"),
        DriveComparison::InSync
    );
}

#[test]
fn sec11_a_lost_only_backup_is_replaced_from_the_primary_alone() {
    // Covers: SEC-11, FR-12 AC1
    let mut drives = ca(2);
    let new = drives.add_ca_drive();
    let primary = open_some(&drives, &[0]);
    assert!(
        primary.ensure_writable().is_err(),
        "no signing without a backup"
    );
    let plan = primary.plan_add_drive(&new).expect("plan");
    assert_eq!(plan.promote, None);
    let set = primary.add_drive(&plan, ts(30)).expect("add");
    set.ensure_writable().expect("writable");
    assert_eq!(set.drives()[1].role(), DriveRole::Backup);
    assert_eq!(added_entries(&set).len(), 1);
    assert_eq!(set.compare().expect("compare"), DriveComparison::InSync);
}

#[test]
fn sec20_replacement_targets_are_refused_unless_empty() {
    // Covers: SEC-20, SEC-11
    let mut drives = ca(2);
    let set = open_some(&drives, &[0, 1]);
    // A connected drive.
    assert!(matches!(
        set.plan_add_drive(drives.ca_drive(1)),
        Err(StoreError::DriveSet(_))
    ));
    // Other files.
    let other = drives.add_ca_drive();
    fs::write(other.join("notes.txt"), b"x").expect("write");
    assert!(matches!(
        set.plan_add_drive(&other),
        Err(StoreError::DriveNotEmpty { .. })
    ));
    // A drive of another CA.
    let foreign = ca(2);
    assert!(matches!(
        set.plan_add_drive(foreign.ca_drive(1)),
        Err(StoreError::DriveHoldsCa { .. })
    ));
    // A keystone folder that is not a copy of this CA.
    let damaged = drives.add_ca_drive();
    fs::create_dir_all(damaged.join("keystone/certs")).expect("mkdir");
    fs::write(damaged.join("keystone/certs/x.crt"), b"KEYSTONE TEST other").expect("write");
    assert!(matches!(
        set.plan_add_drive(&damaged),
        Err(StoreError::DriveHoldsCa { .. })
    ));
    // The export drive.
    crate::store::ExportDrive::open(drives.export_drive()).expect("export");
    assert!(set.plan_add_drive(drives.export_drive()).is_err());
    // Nothing was written to any refused target.
    assert_eq!(fs::read(other.join("notes.txt")).expect("kept"), b"x");
    assert!(!damaged.join("keystone/drive.json").exists());
}

/// A same-device refusal naming the connected drive.
fn refused_as_same_device(result: Result<AddDrivePlan, StoreError>, drive: &CaDrive) {
    match result {
        Err(StoreError::DriveSet(message)) => assert!(
            message.contains("on the same device as") && message.contains(&drive.label()),
            "{message}"
        ),
        other => panic!("expected a same-device refusal, got {other:?}"),
    }
}

#[test]
fn regression_a_replacement_target_on_a_connected_drives_device_is_refused() {
    // Covers: SEC-11, FR-12 AC1
    // Regression (final storage review N3): a folder inside a connected drive (even its
    // own staging folder) was accepted as the "new" drive, so the CA was "replaced" onto
    // the device it already used.
    fault::clear_devices();
    let mut drives = ca(2);
    let pair = open_some(&drives, &[0, 1]);
    let primary = open_some(&drives, &[0]);
    // A sub-folder of the backup, the primary's own folder tree and the staging folder.
    let in_backup = drives.ca_drive(1).join("second-copy");
    fs::create_dir(&in_backup).expect("mkdir");
    refused_as_same_device(pair.plan_add_drive(&in_backup), &pair.drives()[1]);
    let in_primary = drives.ca_drive(0).join("copy");
    fs::create_dir(&in_primary).expect("mkdir");
    refused_as_same_device(primary.plan_add_drive(&in_primary), &primary.drives()[0]);
    let staging = drives.ca_drive(1).join("keystone/staging");
    refused_as_same_device(pair.plan_add_drive(&staging), &pair.drives()[1]);
    // A separate folder that the operating system reports on the primary's device.
    let new = drives.add_ca_drive();
    fault::put_on_device(drives.ca_drive(0), 41);
    fault::put_on_device(drives.ca_drive(1), 42);
    fault::put_on_device(&new, 41);
    refused_as_same_device(primary.plan_add_drive(&new), &primary.drives()[0]);
    refused_as_same_device(pair.plan_add_drive(&new), &pair.drives()[0]);
    // Nothing was written to any refused target.
    for target in [&in_backup, &in_primary, &staging, &new] {
        assert_eq!(fs::read_dir(target).expect("list").count(), 0, "{target:?}");
    }
    // On its own device, a folder on the new drive is accepted: it need not be the
    // drive's mount point.
    fault::put_on_device(&new, 43);
    let folder = new.join("keystone-ca");
    fs::create_dir(&folder).expect("mkdir");
    let plan = primary.plan_add_drive(&folder).expect("plan");
    assert_eq!(plan.state, NewDriveState::Empty);
    let set = primary.add_drive(&plan, ts(30)).expect("add");
    set.ensure_writable().expect("writable");
    fault::clear_devices();
}

#[test]
fn sec11_no_drive_is_added_while_drives_differ_or_an_operation_is_pending() {
    // Covers: SEC-11, SEC-22, FR-22 AC4
    let mut drives = ca(3);
    let new = drives.add_ca_drive();
    // Drive 2 falls behind.
    open_some(&drives, &[0, 1])
        .append_audit(
            &[AuditDraft::new(
                AuditAction::Export,
                "late",
                AuditResult::Success,
            )],
            ts(25),
        )
        .expect("append");
    assert!(matches!(
        open_some(&drives, &[0, 1, 2]).plan_add_drive(&new),
        Err(StoreError::OutOfSync(_))
    ));
    // An interrupted operation.
    let pair = open_some(&drives, &[0, 1]);
    drop(
        pair.begin_operation(OperationKind::Revoke, "CN=KEYSTONE TEST", &[], ts(26))
            .expect("begin"),
    );
    assert!(matches!(
        open_some(&drives, &[0, 1]).plan_add_drive(&new),
        Err(StoreError::PendingOperation(_))
    ));
    assert!(
        fs::read_dir(&new).expect("list").next().is_none(),
        "untouched"
    );
}

#[test]
fn sec11_an_interrupted_copy_never_looks_complete_and_is_continued() {
    // Covers: SEC-11, FR-12 AC2, FR-22 AC6
    let mut probe = ca(2);
    let new = probe.add_ca_drive();
    let backup = open_some(&probe, &[1]);
    let plan = backup.plan_add_drive(&new).expect("plan");
    fault::take_count();
    backup.add_drive(&plan, ts(30)).expect("add");
    let total = fault::take_count();
    assert!(total > 10, "{total}");
    for allowed in 0..total {
        let mut drives = ca(2);
        let new = drives.add_ca_drive();
        let backup = open_some(&drives, &[1]);
        let plan = backup.plan_add_drive(&new).expect("plan");
        fault::fail_after(allowed);
        assert!(backup.add_drive(&plan, ts(30)).is_err(), "fault {allowed}");
        fault::disarm();
        // A drive that looks like a CA drive holds a complete, verified copy: next to the
        // source it is in sync, or one of the two only lacks the replacement entries.
        if let DriveClass::KeystoneCa(_) = classify_drive(&new).expect("classify") {
            let both = DriveSet::open(&[drives.ca_drive(1), new.as_path()]).expect("open");
            match both.compare().expect("compare") {
                DriveComparison::InSync => {}
                DriveComparison::Behind { plans } => assert!(
                    plans.iter().all(|plan| plan
                        .steps
                        .iter()
                        .all(|step| matches!(step, crate::store::RepairStep::AuditOnly { .. }))),
                    "fault {allowed}: {plans:?}"
                ),
                other => panic!("fault {allowed}: the copy is not complete: {other:?}"),
            }
        }
        // Running it again finishes it (after repairing a partly written audit entry).
        let backup = open_some(&drives, &[1]);
        let set = match backup.plan_add_drive(&new) {
            Ok(plan) => {
                assert_ne!(plan.state, NewDriveState::Empty, "fault {allowed}");
                backup.add_drive(&plan, ts(31)).expect("add again")
            }
            Err(_) => {
                let both = DriveSet::open(&[drives.ca_drive(1), new.as_path()]).expect("open");
                match both.compare().expect("compare") {
                    DriveComparison::Behind { plans } => {
                        both.repair(&plans, ts(31)).expect("repair")
                    }
                    other => panic!("fault {allowed}: {other:?}"),
                }
                DriveSet::open(&[drives.ca_drive(1), new.as_path()]).expect("open")
            }
        };
        set.ensure_writable()
            .unwrap_or_else(|e| panic!("fault {allowed}: {e}"));
        assert_eq!(
            set.compare().expect("compare"),
            DriveComparison::InSync,
            "fault {allowed}"
        );
        let details = added_entries(&set);
        assert_eq!(
            details.iter().filter(|d| d.drive_added.is_some()).count(),
            1,
            "fault {allowed}: {details:?}"
        );
    }
}
