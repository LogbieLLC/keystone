//! Tests for drive identity, classification, drive sets and the export drive.
#![forbid(unsafe_code)]

use std::fs;

use keystone_testkit::TestDrives;

use super::*;
use crate::store::testutil::{new_ca, open_all, open_some, ts};

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
