//! The test seams (fault points, cached test keys, serial candidates, simulated devices)
//! exist only in non-production builds. This test links the library as a normal build,
//! so it sees exactly what a development or a production build gets. CI also runs it
//! with `--features production`, where it proves that a seam the tests rely on is
//! absent: test drives are folders on one file system, which a development build may
//! use as separate drives, and a production build refuses them as one device (SEC-11).
#![forbid(unsafe_code)]

use std::path::Path;

use keystone_core::model::Timestamp;
use keystone_core::store::{DriveSet, StoreError};
use time::OffsetDateTime;

/// Two empty sibling folders in one temporary folder (one file system).
fn two_folders() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("keystone-ops-seams-")
        .tempdir()
        .expect("temporary folder");
    let (primary, backup) = (dir.path().join("primary"), dir.path().join("backup"));
    std::fs::create_dir(&primary).expect("mkdir");
    std::fs::create_dir(&backup).expect("mkdir");
    (dir, primary, backup)
}

fn created() -> Timestamp {
    Timestamp::utc(OffsetDateTime::from_unix_timestamp(1_793_491_200).expect("time"))
}

fn is_empty(folder: &Path) -> bool {
    std::fs::read_dir(folder).expect("list").next().is_none()
}

#[cfg(feature = "production")]
#[test]
fn fr22_ac6_sec11_a_production_build_has_no_test_seams() {
    // Covers: FR-22 AC6, SEC-11, SEC-18
    const { assert!(!keystone_core::ops::TEST_SEAMS_COMPILED) };
    // No simulated devices: the real device numbers decide, so two folders on one file
    // system are one device, and no CA is created on them.
    let (_dir, primary, backup) = two_folders();
    match DriveSet::create(&primary, &[&backup], created()) {
        Err(StoreError::DriveSet(message)) => {
            assert!(message.contains("on the same device"), "{message}");
        }
        other => panic!("a production build must refuse one device, got {other:?}"),
    }
    assert!(
        is_empty(&primary) && is_empty(&backup),
        "nothing was written"
    );
}

#[cfg(not(feature = "production"))]
#[test]
fn fr22_ac6_sec11_a_development_build_has_the_test_seams() {
    // Covers: FR-22 AC6, SEC-11
    use keystone_core::ops::testing;
    const { assert!(keystone_core::ops::TEST_SEAMS_COMPILED) };
    // Sibling folders stand in for separate drives here...
    let (_dir, primary, backup) = two_folders();
    let set = DriveSet::create(&primary, &[&backup], created()).expect("create");
    assert_eq!(set.drives().len(), 2);
    // ...unless a test puts them on one simulated device.
    let (_other, first, second) = two_folders();
    testing::put_on_device(&first, 5);
    testing::put_on_device(&second, 5);
    assert!(matches!(
        DriveSet::create(&first, &[&second], created()),
        Err(StoreError::DriveSet(_))
    ));
    testing::reset();
    assert!(is_empty(&first) && is_empty(&second), "nothing was written");
}
