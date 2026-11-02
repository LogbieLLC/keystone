//! Tests for drive identity, classification, drive sets and the export drive.
#![forbid(unsafe_code)]

use std::fs;

use keystone_testkit::TestDrives;

use super::*;
use crate::store::testutil::{copy_folder, new_ca, open_all, open_some, ts};

#[test]
fn classify_empty_ca_damaged_export_and_other_drives() {
    let mut drives = TestDrives::new(2);
    assert_eq!(
        classify_drive(drives.ca_drive(0)).expect("classify"),
        DriveClass::Empty
    );
    // ext4's lost+found folder does not make a drive non-empty.
    fs::create_dir(drives.ca_drive(0).join("lost+found")).expect("mkdir");
    assert_eq!(
        classify_drive(drives.ca_drive(0)).expect("classify"),
        DriveClass::Empty
    );
    fs::write(drives.ca_drive(1).join("holiday.jpg"), b"x").expect("write");
    assert_eq!(
        classify_drive(drives.ca_drive(1)).expect("classify"),
        DriveClass::Other
    );
    let damaged = drives.add_ca_drive();
    fs::create_dir(damaged.join(KEYSTONE_DIR)).expect("mkdir");
    assert!(matches!(
        classify_drive(&damaged).expect("classify"),
        DriveClass::DamagedKeystone(_)
    ));
    let export = drives.add_ca_drive();
    fs::create_dir(export.join(EXPORT_DIR)).expect("mkdir");
    assert_eq!(
        classify_drive(&export).expect("classify"),
        DriveClass::KeystoneExport
    );
    let ca_drives = TestDrives::new(2);
    let set = new_ca(&ca_drives);
    match classify_drive(ca_drives.ca_drive(0)).expect("classify") {
        DriveClass::KeystoneCa(identity) => {
            assert_eq!(identity.role, DriveRole::Primary);
            assert_eq!(identity.ca_id, set.ca_id());
        }
        other => panic!("expected a CA drive, got {other:?}"),
    }
}

#[test]
fn sec20_refuses_to_create_a_ca_on_a_drive_that_holds_one() {
    // Covers: SEC-20
    let mut drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let original = fs::read(drives.ca_drive(0).join("keystone/drive.json")).expect("read");
    let fresh = drives.add_ca_drive();
    let error = DriveSet::create(drives.ca_drive(0), &[&fresh], ts(10)).expect_err("refused");
    assert!(matches!(error, StoreError::DriveHoldsCa { .. }), "{error}");
    // As backup too, and the existing CA and the fresh drive are untouched.
    let error = DriveSet::create(&fresh, &[drives.ca_drive(1)], ts(10)).expect_err("refused");
    assert!(matches!(error, StoreError::DriveHoldsCa { .. }));
    assert_eq!(
        fs::read(drives.ca_drive(0).join("keystone/drive.json")).expect("read"),
        original
    );
    assert_eq!(fs::read_dir(&fresh).expect("list").count(), 0);
    // A damaged keystone folder counts as a CA: never created over.
    let damaged = drives.add_ca_drive();
    fs::create_dir(damaged.join(KEYSTONE_DIR)).expect("mkdir");
    let other = drives.add_ca_drive();
    assert!(matches!(
        DriveSet::create(&damaged, &[&other], ts(10)),
        Err(StoreError::DriveHoldsCa { .. })
    ));
    drop(set);
}

#[test]
fn new_ca_needs_empty_distinct_drives_and_a_backup() {
    // Covers: FR-12 AC1, SEC-20
    let drives = TestDrives::new(2);
    assert!(matches!(
        DriveSet::create(drives.ca_drive(0), &[], ts(0)),
        Err(StoreError::NotEnoughDrives {
            primaries: 1,
            backups: 0
        })
    ));
    assert!(matches!(
        DriveSet::create(drives.ca_drive(0), &[drives.ca_drive(0)], ts(0)),
        Err(StoreError::DriveSet(_))
    ));
    fs::write(drives.ca_drive(1).join("notes.txt"), b"x").expect("write");
    assert!(matches!(
        DriveSet::create(drives.ca_drive(0), &[drives.ca_drive(1)], ts(0)),
        Err(StoreError::DriveNotEmpty { .. })
    ));
    // Nothing was written to the empty drive.
    assert_eq!(fs::read_dir(drives.ca_drive(0)).expect("list").count(), 0);
}

#[test]
fn fr19_ac1_opens_an_existing_ca_and_rejects_mixed_drives() {
    // Covers: FR-19 AC1
    let drives = TestDrives::new(3);
    let created = new_ca(&drives);
    let opened = open_all(&drives);
    assert_eq!(opened.ca_id(), created.ca_id());
    assert_eq!(opened.drives().len(), 3);
    assert_eq!(opened.drives()[0].identity().role, DriveRole::Primary);
    assert!(
        opened.drives()[1..]
            .iter()
            .all(|d| d.identity().role == DriveRole::Backup)
    );
    let layout = drives.ca_drive(1).join(KEYSTONE_DIR);
    for name in [
        "journal",
        "staging",
        "certs",
        "keys",
        "crls",
        "record",
        "audit.log",
        "drive.json",
    ] {
        assert!(layout.join(name).exists(), "{name}");
    }
    let other = TestDrives::new(2);
    new_ca(&other);
    assert!(matches!(
        DriveSet::open(&[drives.ca_drive(0), other.ca_drive(1)]),
        Err(StoreError::DriveSet(_))
    ));
    assert!(matches!(
        DriveSet::open(&[drives.ca_drive(0), drives.ca_drive(0)]),
        Err(StoreError::DriveSet(_))
    ));
    assert!(matches!(
        DriveSet::open(&[other.export_drive()]),
        Err(StoreError::NotACaDrive { .. })
    ));
}

/// The message every same-device refusal gives, and that nothing was written.
fn refused_as_one_device(result: Result<DriveSet, StoreError>) {
    match result {
        Err(StoreError::DriveSet(message)) => {
            assert!(message.contains("on the same device"), "{message}");
        }
        other => panic!("expected a same-device refusal, got {other:?}"),
    }
}

#[test]
fn regression_two_ca_drives_on_one_device_are_refused() {
    // Covers: SEC-11, FR-12 AC1, SEC-20
    // Regression (final storage review N3): a CA could be created on, or opened from,
    // two folders of one USB drive, so a single drive failure lost every copy.
    crate::store::fault::clear_devices();
    let drives = TestDrives::new(3);
    // Create: two folders on one simulated device are refused before anything is written.
    crate::store::fault::put_on_device(drives.ca_drive(0), 7);
    crate::store::fault::put_on_device(drives.ca_drive(1), 7);
    crate::store::fault::put_on_device(drives.ca_drive(2), 8);
    refused_as_one_device(DriveSet::create(
        drives.ca_drive(0),
        &[drives.ca_drive(2), drives.ca_drive(1)],
        ts(0),
    ));
    for root in drives.ca_drives() {
        assert_eq!(fs::read_dir(root).expect("list").count(), 0, "untouched");
    }
    // Two folders on one USB drive: everything inside a drive is on its device.
    let (first, second) = (
        drives.ca_drive(2).join("first"),
        drives.ca_drive(2).join("second"),
    );
    fs::create_dir(&first).expect("mkdir");
    fs::create_dir(&second).expect("mkdir");
    refused_as_one_device(DriveSet::create(&first, &[&second], ts(0)));
    assert_eq!(fs::read_dir(&first).expect("list").count(), 0, "untouched");
    fs::remove_dir(&first).expect("rmdir");
    fs::remove_dir(&second).expect("rmdir");
    // Separate devices: accepted.
    let set = DriveSet::create(drives.ca_drive(0), &[drives.ca_drive(2)], ts(0)).expect("create");
    assert_eq!(set.drives().len(), 2);
    // Open: two CA drives found on one device are refused, whichever order.
    crate::store::fault::put_on_device(drives.ca_drive(2), 7);
    refused_as_one_device(DriveSet::open(&[drives.ca_drive(0), drives.ca_drive(2)]));
    refused_as_one_device(DriveSet::open(&[drives.ca_drive(2), drives.ca_drive(0)]));
    // A copy of a CA drive's folder nested inside another drive is refused too.
    crate::store::fault::clear_devices();
    let nested = drives.ca_drive(0).join("old-backup");
    fs::create_dir(&nested).expect("mkdir");
    copy_folder(
        &drives.ca_drive(2).join(KEYSTONE_DIR),
        &nested.join(KEYSTONE_DIR),
    );
    refused_as_one_device(DriveSet::open(&[drives.ca_drive(0), &nested]));
    // Drives on separate devices open as before.
    DriveSet::open(&[drives.ca_drive(0), drives.ca_drive(2)]).expect("open");
    // Finishing an interrupted setup checks the devices before writing too.
    let unfinished = TestDrives::new(2);
    fs::create_dir(unfinished.ca_drive(0).join(KEYSTONE_DIR)).expect("mkdir");
    crate::store::fault::put_on_device(unfinished.ca_drive(0), 3);
    crate::store::fault::put_on_device(unfinished.ca_drive(1), 3);
    refused_as_one_device(DriveSet::finish_setup(
        unfinished.ca_drive(0),
        &[unfinished.ca_drive(1)],
        ts(0),
    ));
    assert_eq!(
        fs::read_dir(unfinished.ca_drive(1)).expect("list").count(),
        0,
        "untouched"
    );
    crate::store::fault::clear_devices();
}

#[test]
fn fr12_ac1_every_change_goes_to_the_primary_and_a_backup() {
    // Covers: FR-12 AC1, SEC-11
    let drives = TestDrives::new(3);
    let set = new_ca(&drives);
    let digest = set
        .write_verified("certs", "a.crt", b"KEYSTONE TEST", WriteMode::CreateOnly)
        .expect("write");
    assert_eq!(digest, sha256(b"KEYSTONE TEST"));
    for root in drives.ca_drives() {
        assert_eq!(
            fs::read(root.join("keystone/certs/a.crt")).expect("read"),
            b"KEYSTONE TEST"
        );
    }
    // The primary alone, or backups alone, cannot be written to.
    for indexes in [&[0usize][..], &[1, 2][..]] {
        let partial = open_some(&drives, indexes);
        assert!(matches!(
            partial.write_verified("certs", "b.crt", b"x", WriteMode::CreateOnly),
            Err(StoreError::NotEnoughDrives { .. })
        ));
    }
    assert!(!drives.ca_drive(0).join("keystone/certs/b.crt").exists());
}

#[test]
fn fr12_ac2_read_back_mismatch_is_an_error() {
    // Covers: FR-12 AC2, SEC-11
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let copies = set
        .write_copies("crls", "m.crl", b"KEYSTONE TEST CRL", WriteMode::CreateOnly)
        .expect("write");
    // The backup's copy does not match what was written (a failing medium).
    fs::write(
        drives.ca_drive(1).join("keystone/crls/m.crl"),
        b"KEYSTONE TEST CRX",
    )
    .expect("corrupt");
    let error = set.verify_copies(&copies).expect_err("mismatch must fail");
    match error {
        StoreError::ReadBackMismatch {
            expected,
            actual,
            ref drive,
            ..
        } => {
            assert_eq!(expected, sha256(b"KEYSTONE TEST CRL"));
            assert_eq!(actual, sha256(b"KEYSTONE TEST CRX"));
            assert!(drive.contains("backup"));
        }
        other => panic!("expected a read-back mismatch, got {other}"),
    }
    // A shorter copy is caught too.
    let copies = set
        .write_copies("crls", "n.crl", b"KEYSTONE TEST CRL", WriteMode::CreateOnly)
        .expect("write");
    fs::write(drives.ca_drive(0).join("keystone/crls/n.crl"), b"KEYSTONE").expect("truncate");
    assert!(matches!(
        set.verify_copies(&copies),
        Err(StoreError::ReadBackMismatch { .. })
    ));
}

#[test]
fn sec20_drive_set_never_overwrites_create_only_files() {
    // Covers: SEC-20
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    set.write_verified("keys", "m.key", b"first", WriteMode::CreateOnly)
        .expect("write");
    assert!(matches!(
        set.write_verified("keys", "m.key", b"second", WriteMode::CreateOnly),
        Err(StoreError::AlreadyExists { .. })
    ));
    for root in drives.ca_drives() {
        assert_eq!(
            fs::read(root.join("keystone/keys/m.key")).expect("read"),
            b"first"
        );
    }
}

/// Every file under `root` with its content.
fn snapshot(root: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir).expect("list") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                out.push((path.clone(), fs::read(&path).expect("read")));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn regression_an_interrupted_ca_setup_is_recognised_and_finished() {
    // Covers: SEC-20, FR-12 AC1, FR-22 AC6
    // Regression (review finding 11): an interruption while new drives were set up left
    // them classified as damaged, refused for ever, and only removable by hand.
    let probe = TestDrives::new(2);
    let backups = [probe.ca_drive(1)];
    crate::store::fault::take_count();
    DriveSet::create(probe.ca_drive(0), &backups, ts(0)).expect("create");
    let total = crate::store::fault::take_count();
    assert_eq!(total, 4, "audit log and identity on each drive");
    for allowed in 0..total {
        let drives = TestDrives::new(2);
        let (primary, backup) = (drives.ca_drive(0), drives.ca_drive(1));
        crate::store::fault::fail_after(allowed);
        assert!(DriveSet::create(primary, &[backup], ts(0)).is_err());
        crate::store::fault::disarm();
        // Not a CA that can be opened, and a new CA is still refused over it...
        assert!(
            DriveSet::open(&[primary, backup]).is_err(),
            "fault {allowed}"
        );
        assert!(matches!(
            DriveSet::create(primary, &[backup], ts(1)),
            Err(StoreError::DriveHoldsCa { .. })
        ));
        // ...but it is recognised as an unfinished setup and finished without touching
        // anything already written.
        let setup = unfinished_setup(primary, &[backup])
            .expect("inspect")
            .unwrap_or_else(|| panic!("fault {allowed}: not recognised"));
        assert_eq!(setup.drives.len(), 2);
        let before: Vec<_> = snapshot(primary)
            .into_iter()
            .chain(snapshot(backup))
            .collect();
        let set = DriveSet::finish_setup(primary, &[backup], ts(1)).expect("finish");
        assert!(set.ensure_writable().is_ok());
        assert_eq!(
            set.compare().expect("compare"),
            crate::store::DriveComparison::InSync
        );
        let after: Vec<_> = snapshot(primary)
            .into_iter()
            .chain(snapshot(backup))
            .collect();
        for (path, content) in &before {
            if path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            {
                continue;
            }
            assert!(
                after.contains(&(path.clone(), content.clone())),
                "fault {allowed}: {} was changed or deleted",
                path.display()
            );
        }
        if let Some(ca) = setup.ca_id {
            assert_eq!(set.ca_id(), ca, "the CA started before is kept");
        }
        // Finished: nothing left to finish.
        assert!(
            unfinished_setup(primary, &[backup])
                .expect("inspect")
                .is_none()
        );
    }
}

#[test]
fn sec20_an_unfinished_setup_is_never_combined_with_another_ca_or_a_used_drive() {
    // Covers: SEC-20
    let started = |label: u8| {
        let drives = TestDrives::new(2);
        crate::store::fault::fail_after(2);
        assert!(DriveSet::create(drives.ca_drive(0), &[drives.ca_drive(1)], ts(0)).is_err());
        crate::store::fault::disarm();
        let _ = label;
        drives
    };
    // Two primaries of two different unfinished setups.
    let one = started(1);
    let two = started(2);
    // Primary of setup one as primary, primary of setup two as backup: different CAs (and
    // the wrong role).
    assert!(matches!(
        unfinished_setup(one.ca_drive(0), &[two.ca_drive(1)]),
        Ok(Some(_))
    ));
    assert!(unfinished_setup(one.ca_drive(0), &[two.ca_drive(0)]).is_err());
    // A drive set up as primary chosen as a backup.
    let fresh = TestDrives::new(1);
    let error = unfinished_setup(fresh.ca_drive(0), &[one.ca_drive(0)]).expect_err("role");
    assert!(error.to_string().contains("primary"), "{error}");
    // A drive of a CA in use is never part of an unfinished setup.
    let used = TestDrives::new(2);
    let set = new_ca(&used);
    crate::store::testutil::issue_master(&set, 1, ts(5));
    assert_eq!(
        unfinished_setup(one.ca_drive(0), &[used.ca_drive(1)]).expect("inspect"),
        None
    );
    assert!(DriveSet::finish_setup(one.ca_drive(0), &[used.ca_drive(1)], ts(6)).is_err());
    // Other content on a started drive: not an unfinished setup, never touched.
    let other = started(3);
    fs::write(other.ca_drive(1).join("keystone/notes.txt"), b"x").expect("write");
    assert_eq!(
        unfinished_setup(other.ca_drive(0), &[other.ca_drive(1)]).expect("inspect"),
        None
    );
    assert!(DriveSet::finish_setup(other.ca_drive(0), &[other.ca_drive(1)], ts(6)).is_err());
    assert_eq!(
        fs::read(other.ca_drive(1).join("keystone/notes.txt")).expect("kept"),
        b"x"
    );
    // Plain empty drives are not an unfinished setup (a normal new CA).
    let empty = TestDrives::new(2);
    assert_eq!(
        unfinished_setup(empty.ca_drive(0), &[empty.ca_drive(1)]).expect("inspect"),
        None
    );
}

#[test]
fn identity_parser_is_strict() {
    // Covers: SEC-08
    let drives = TestDrives::new(2);
    new_ca(&drives);
    let good = fs::read(drives.ca_drive(0).join("keystone/drive.json")).expect("read");
    assert!(parse_drive_identity(&good).is_ok());
    let text = String::from_utf8(good).expect("utf8");
    let extra = text.replacen('{', "{\"extra\": 1,", 1);
    assert!(parse_drive_identity(extra.as_bytes()).is_err());
    let wrong_format = text.replacen("\"format\": 1", "\"format\": 2", 1);
    assert!(parse_drive_identity(wrong_format.as_bytes()).is_err());
    let wrong_role = text.replacen("primary", "boss", 1);
    assert!(parse_drive_identity(wrong_role.as_bytes()).is_err());
    let local_time = text.replacen("T00:00:00Z", "T01:00:00+01:00", 1);
    assert!(parse_drive_identity(local_time.as_bytes()).is_err());
    assert!(matches!(
        parse_drive_identity(&vec![b' '; MAX_METADATA_BYTES + 1]),
        Err(ParseError::TooLarge { .. })
    ));
}

#[test]
fn export_drive_refuses_ca_drives_and_never_overwrites() {
    // Covers: SEC-20, FR-22 AC2
    let drives = TestDrives::new(2);
    new_ca(&drives);
    assert!(ExportDrive::open(drives.ca_drive(0)).is_err());
    let export = ExportDrive::open(drives.export_drive()).expect("export");
    export
        .write_file("sub.crt", b"KEYSTONE TEST")
        .expect("write");
    assert!(matches!(
        export.write_file("sub.crt", b"other"),
        Err(StoreError::AlreadyExists { .. })
    ));
    assert!(export.write_file("../escape", b"x").is_err());
    assert_eq!(
        export.read_file("sub.crt", 100).expect("read"),
        b"KEYSTONE TEST"
    );
    assert_eq!(
        classify_drive(drives.export_drive()).expect("classify"),
        DriveClass::KeystoneExport
    );
}

#[test]
fn damaged_drives_are_never_opened_or_used_for_export() {
    // Covers: SEC-20, SEC-08
    let drives = TestDrives::new(3);
    fs::write(drives.ca_drive(0).join(KEYSTONE_DIR), b"not a folder").expect("write");
    assert!(matches!(
        classify_drive(drives.ca_drive(0)).expect("classify"),
        DriveClass::DamagedKeystone(_)
    ));
    assert!(matches!(
        CaDrive::open(drives.ca_drive(0)),
        Err(StoreError::NotACaDrive { .. })
    ));
    assert!(ExportDrive::open(drives.ca_drive(0)).is_err());
    let set = DriveSet::create(drives.ca_drive(1), &[drives.ca_drive(2)], ts(0)).expect("create");
    let primary = &set.drives()[0];
    assert!(primary.label().starts_with("primary drive "));
    assert_eq!(primary.root(), drives.ca_drive(1));
    assert!(matches!(
        primary.dir_at("../x", false),
        Err(StoreError::Unsafe(_))
    ));
    assert!(
        primary
            .dir_at("certs/missing", false)
            .expect("ok")
            .is_none()
    );
    // Damaged identity: the drive is not opened.
    fs::write(drives.ca_drive(2).join("keystone/drive.json"), b"{}").expect("write");
    assert!(matches!(
        CaDrive::open(drives.ca_drive(2)),
        Err(StoreError::NotACaDrive { .. })
    ));
}

proptest::proptest! {
    #[test]
    fn sec08_identity_parser_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)) {
        // Covers: SEC-08
        let _ = parse_drive_identity(&bytes);
    }
}
