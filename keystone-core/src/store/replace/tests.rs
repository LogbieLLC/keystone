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
        // source one of the two only lacks the replacement entries, or neither has them
        // and the new drive is reported as not recorded yet, so nothing is signed with it
        // (final storage review N4).
        if let DriveClass::KeystoneCa(_) = classify_drive(&new).expect("classify") {
            let both = DriveSet::open(&[drives.ca_drive(1), new.as_path()]).expect("open");
            match both.compare().expect("compare") {
                DriveComparison::Behind { plans } => assert!(
                    plans.iter().all(|plan| plan
                        .steps
                        .iter()
                        .all(|step| matches!(step, crate::store::RepairStep::AuditOnly { .. }))),
                    "fault {allowed}: {plans:?}"
                ),
                DriveComparison::Damaged { problems } => assert!(
                    problems.len() == 1
                        && problems[0].contains("its addition was recorded in the audit log"),
                    "fault {allowed}: {problems:?}"
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

/// A fresh `ca(2)` whose lost drive is replaced from the drives `sources`, interrupted
/// right after the new drive's identity was written and before any audit entry.
fn interrupted_after_identity(sources: &[usize]) -> (TestDrives, std::path::PathBuf) {
    let mut probe = ca(2);
    let new = probe.add_ca_drive();
    let set = open_some(&probe, sources);
    let plan = set.plan_add_drive(&new).expect("plan");
    fault::take_count();
    let added = set.add_drive(&plan, ts(30)).expect("add");
    let total = fault::take_count();
    // The last changes are the audit-log writes, one per drive of the new set.
    let audit_writes = u32::try_from(added.drives().len()).expect("count");
    drop(probe);
    let mut drives = ca(2);
    let new = drives.add_ca_drive();
    let set = open_some(&drives, sources);
    let plan = set.plan_add_drive(&new).expect("plan");
    fault::fail_after(total - audit_writes);
    assert!(set.add_drive(&plan, ts(30)).is_err());
    fault::disarm();
    assert!(matches!(
        classify_drive(&new).expect("classify"),
        DriveClass::KeystoneCa(_)
    ));
    (drives, new)
}

/// A refusal of a drive that already holds this CA as the "new" drive.
fn refused_as_existing_drive(result: Result<AddDrivePlan, StoreError>) {
    match result {
        Err(StoreError::DriveSet(message)) => {
            assert!(message.contains("already holds this CA"), "{message}");
        }
        other => panic!("expected the drive to be refused as a CA drive, got {other:?}"),
    }
}

#[test]
fn regression_an_existing_backup_is_never_recorded_as_a_new_drive() {
    // Covers: SEC-11, FR-14 AC1, SEC-20
    // Regression (final storage review N5): an original, in-sync backup offered as the
    // "new" drive was taken for an interrupted replacement, and a false "new backup drive
    // added" entry (plus a promotion) was written to the audit log.
    let mut drives = ca(3);
    let b1 = open_some(&drives, &[1]);
    let before = b1.audit_log().expect("log");
    refused_as_existing_drive(b1.plan_add_drive(drives.ca_drive(2)));
    // The original primary too.
    refused_as_existing_drive(b1.plan_add_drive(drives.ca_drive(0)));
    assert_eq!(b1.audit_log().expect("log"), before, "nothing was recorded");
    assert_eq!(
        open_some(&drives, &[0, 1, 2]).compare().expect("compare"),
        DriveComparison::InSync
    );
    // A drive added by an earlier, finished replacement is a CA drive, not a new drive.
    let new = drives.add_ca_drive();
    let pair = open_some(&drives, &[0, 1]);
    let plan = pair.plan_add_drive(&new).expect("plan");
    pair.add_drive(&plan, ts(30)).expect("add");
    let pair = open_some(&drives, &[0, 1]);
    refused_as_existing_drive(pair.plan_add_drive(&new));
    // A complete copy is an interrupted replacement only while it carries the
    // replacement marker naming it.
    let (copied, copy) = interrupted_after_identity(&[0]);
    let primary = open_some(&copied, &[0]);
    let marker = copy.join("keystone").join(REPLACEMENT_FILE);
    let moved = copied.root().join("marker-moved-away");
    fs::rename(&marker, &moved).expect("move the marker away");
    refused_as_existing_drive(primary.plan_add_drive(&copy));
    // A keystone folder whose marker names another CA is a foreign CA's.
    let foreign = drives.add_ca_drive();
    fs::create_dir(foreign.join("keystone")).expect("mkdir");
    fs::rename(&moved, foreign.join("keystone").join(REPLACEMENT_FILE)).expect("plant");
    assert!(matches!(
        pair.plan_add_drive(&foreign),
        Err(StoreError::DriveHoldsCa { .. })
    ));
}

#[test]
fn regression_a_drive_whose_addition_is_not_recorded_is_never_used() {
    // Covers: SEC-11, FR-14 AC1, FR-12 AC3, FR-22 AC6, SEC-22
    // Regression (final storage review N4): interrupted after the new drive's identity
    // and before the audit entries (the review's fault 9 of 11; the replacement marker
    // written first adds one change), the new drive was used with the primary, signing
    // was allowed and its addition was never audited.
    let mut probe = TestDrives::new(2);
    issue_master(&new_ca(&probe), 1, ts(10));
    let new = probe.add_ca_drive();
    let primary = open_some(&probe, &[0]);
    let plan = primary.plan_add_drive(&new).expect("plan");
    fault::take_count();
    primary.add_drive(&plan, ts(30)).expect("add");
    let total = fault::take_count();
    assert_eq!(total, 12, "the review's 11 changes, plus the marker");
    drop(probe);
    let mut drives = TestDrives::new(2);
    issue_master(&new_ca(&drives), 1, ts(10));
    let new = drives.add_ca_drive();
    let primary = open_some(&drives, &[0]);
    let plan = primary.plan_add_drive(&new).expect("plan");
    // Fault 10 of 12: the first audit write (the primary's) fails after the identity.
    fault::fail_after(total - 2);
    assert!(primary.add_drive(&plan, ts(30)).is_err());
    fault::disarm();
    let DriveClass::KeystoneCa(identity) = classify_drive(&new).expect("classify") else {
        panic!("the new drive's identity was written");
    };
    let both = DriveSet::open(&[drives.ca_drive(0), new.as_path()]).expect("open");
    both.ensure_writable().expect("a primary and a backup");
    assert!(added_entries(&both).is_empty(), "nothing was recorded");
    // Signing is impossible with it: compare reports it and no operation begins.
    match both.compare().expect("compare") {
        DriveComparison::Damaged { problems } => {
            assert!(
                problems.iter().any(|p| p.contains("Replace a lost drive")
                    && p.contains(&identity.drive_id.short())),
                "{problems:?}"
            )
        }
        other => panic!("expected the unrecorded drive to be reported, got {other:?}"),
    }
    assert!(matches!(
        both.begin_operation(OperationKind::Revoke, "CN=KEYSTONE TEST", &[], ts(40)),
        Err(StoreError::Damaged(_))
    ));
    // Running the replacement again records it (only the audit entries are written).
    let primary = open_some(&drives, &[0]);
    let plan = primary.plan_add_drive(&new).expect("plan again");
    assert_eq!(
        plan.state,
        NewDriveState::CopiedNotRecorded(identity.drive_id)
    );
    let set = primary.add_drive(&plan, ts(31)).expect("record");
    assert_eq!(set.compare().expect("compare"), DriveComparison::InSync);
    let details = added_entries(&set);
    assert_eq!(details.len(), 1, "{details:?}");
    assert_eq!(details[0].drive_added, Some(identity.drive_id));
    set.begin_operation(OperationKind::Revoke, "CN=KEYSTONE TEST", &[], ts(40))
        .expect("begin")
        .cancel(ts(40))
        .expect("cancel");
}

#[test]
fn sec11_no_drive_is_copied_from_damaged_drives() {
    // Covers: SEC-11, FR-22 AC2, SEC-22
    // Mutation-found gap (M9): removing the refusal of damaged drives broke no test.
    let mut drives = ca(2);
    let new = drives.add_ca_drive();
    // The only healthy drive left lost a completed output: copying it would spread an
    // incomplete CA.
    let backup = open_some(&drives, &[1]);
    let log_before = backup.audit_log().expect("log");
    let cert = drives
        .ca_drive(1)
        .join(format!("keystone/certs/{}.crt", serial(2).to_hex()));
    fs::remove_file(&cert).expect("remove a certificate");
    match backup.plan_add_drive(&new) {
        Err(StoreError::Damaged(problems)) => assert!(
            problems.iter().any(|p| p.contains("is missing")),
            "{problems:?}"
        ),
        other => panic!("expected damage to be refused, got {other:?}"),
    }
    assert_eq!(fs::read_dir(&new).expect("list").count(), 0, "untouched");
    assert_eq!(backup.audit_log().expect("log"), log_before);
}

#[test]
fn sec11_no_drive_is_copied_while_the_connected_drives_diverge() {
    // Covers: SEC-11, FR-12 AC3, SEC-22
    // Mutation-found gap (M10): removing the refusal of diverged drives broke no test.
    let mut drives = crate::store::testutil::diverged_ca();
    let new = drives.add_ca_drive();
    let diverged = open_some(&drives, &[0, 3]);
    assert!(matches!(
        diverged.compare().expect("compare"),
        DriveComparison::Diverged { .. }
    ));
    match diverged.plan_add_drive(&new) {
        Err(StoreError::OutOfSync(message)) => {
            assert!(message.contains("different histories"), "{message}");
        }
        other => panic!("expected diverged drives to be refused, got {other:?}"),
    }
    assert_eq!(fs::read_dir(&new).expect("list").count(), 0, "untouched");
}

#[test]
fn sec11_a_copy_that_differs_from_its_source_never_gets_an_identity() {
    // Covers: SEC-11, FR-12 AC2, SEC-20
    // Mutation-found gap (M6): removing the whole-copy check before the identity write
    // broke no test. Here the interrupted copy holds a binary-hash record that the
    // source drive does not have; every file the copy writes verifies, but the copy as a
    // whole does not equal the source, so it must never become a CA drive.
    let mut drives = ca(2);
    let new = drives.add_ca_drive();
    let primary = open_some(&drives, &[0]);
    let keystone = new.join("keystone");
    fs::create_dir(&keystone).expect("mkdir");
    let marker = DriveIdentity {
        format: IDENTITY_FORMAT,
        ca_id: primary.ca_id(),
        drive_id: DriveId::random().expect("id"),
        role: DriveRole::Backup,
        created: ts(30),
    };
    fs::write(
        keystone.join(REPLACEMENT_FILE),
        crate::store::drive::to_json_file(&marker),
    )
    .expect("marker");
    fs::write(
        keystone.join(BINARY_HASH_FILE),
        crate::store::binhash::format_binary_hash_record(crate::model::Sha256Digest([5; 32])),
    )
    .expect("binary hash record");
    let plan = primary.plan_add_drive(&new).expect("plan");
    assert_eq!(plan.state, NewDriveState::PartialCopy);
    let error = primary.add_drive(&plan, ts(31)).expect_err("refused");
    assert!(
        error.to_string().contains("the binary hash record differs"),
        "{error}"
    );
    assert!(
        !keystone.join(IDENTITY_FILE).exists(),
        "no identity was written"
    );
    assert!(matches!(
        classify_drive(&new).expect("classify"),
        DriveClass::DamagedKeystone(_)
    ));
    assert!(
        added_entries(&open_some(&drives, &[0])).is_empty(),
        "nothing was recorded"
    );
}
