//! Flow A: create the master (FR-02, FR-03, FR-04, FR-12, FR-13 AC6, FR-16, FR-20,
//! FR-22, SEC-20).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use keystone_core::cert::parse_certificate_pem;
use keystone_core::crl::parse_crl_der;
use keystone_core::crypto::hash::sha256;
use keystone_core::crypto::pkcs8::decrypt_key_pem;
use keystone_core::crypto::verify::verify_crl_signature;
use keystone_core::crypto::{CancelFlag, CryptoError};
use keystone_core::model::CaLevel;
use keystone_core::ops::{
    CreateMasterRequest, ExportStatus, NoProgress, OpsError, Progress, Step, plan_create_master,
    testing,
};
use keystone_core::store::{AuditAction, AuditResult, OperationId, OperationState, StoreError};
use keystone_testkit::names::test_name;
use keystone_testkit::{TestDrives, keys};

use crate::support::*;

#[test]
fn flow_a_creates_the_master_on_every_drive_and_exports_its_first_crl() {
    // Covers: FR-02 AC2, FR-02 AC3, FR-04 AC1, FR-04 AC2, FR-12 AC1, FR-12 AC2, FR-13 AC6, FR-20 AC1, FR-22 AC1, FR-22 AC2, FR-14 AC1, FR-11 AC1
    let drives = TestDrives::new(2);
    let now = base_time();
    let (passphrase, words) = master_passphrase();
    let outcome =
        run_flow_a(&drives, "A1", now, &passphrase, Some(drives.export_drive())).expect("Flow A");

    // The certificate: self-signed RSA 8,192 master per profile; fingerprint shown.
    let cert_pem = same_on_every_drive(&drives, "certs/master.crt");
    assert_eq!(cert_pem, outcome.certificate_pem.as_bytes());
    let (der, info) = parse_certificate_pem(&cert_pem).expect("certificate");
    assert_eq!(info.ca_level(), Some(CaLevel::Master));
    assert!(info.signature_is_sha384_rsa);
    assert_eq!(info.not_after.year() - info.not_before.year(), 20);
    assert_eq!(info.serial, outcome.serial);
    assert_eq!(outcome.fingerprint, sha256(&der));
    assert_eq!(
        outcome.fingerprint_text,
        sha256(&der).to_fingerprint_string()
    );
    assert!(outcome.fingerprint_text.contains(':'));

    // The key: only encrypted (scrypt), decrypts with the confirmed words.
    let key_pem = same_on_every_drive(&drives, "keys/master.key");
    assert!(key_pem.starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    let key = decrypt_key_pem(&key_pem, entered(&words).secret()).expect("decrypts");
    assert_eq!(key.bits(), 8192);
    assert_eq!(key.public_key_spki_der().unwrap(), info.spki_der);

    // FR-13 AC6: the first, empty CRL, on every drive and on the export drive.
    let crl = same_on_every_drive(&drives, "crls/master-crl-000001.crl");
    let crl_info = parse_crl_der(&crl).expect("CRL");
    assert_eq!(crl_info.crl_number, 1);
    assert!(crl_info.revoked.is_empty());
    verify_crl_signature(&crl, &info.spki_der).expect("signed by the master");
    match &outcome.export {
        ExportStatus::Written(files) => {
            assert_eq!(files.len(), 1);
            assert_eq!(files[0].name, "master-crl-000001.crl");
            assert_eq!(std::fs::read(&files[0].path).unwrap(), crl);
        }
        other => panic!("not exported: {other:?}"),
    }

    // FR-22: pending first, completed last; FR-14: audited; FR-11: recorded.
    let journal = outcome.ca.drive_set().drives()[0]
        .operation_journal(OperationId(1))
        .unwrap()
        .expect("journal");
    assert_eq!(journal.state(), OperationState::Completed);
    let tags: Vec<&str> = journal.entries().iter().map(|e| e.event.tag()).collect();
    assert_eq!(tags, ["pending", "signed", "signed", "staged", "completed"]);
    assert_eq!(journal.planned_serials(), [outcome.serial]);
    let log = outcome.ca.drive_set().audit_log().unwrap();
    let entry = &log.entries()[0];
    assert_eq!(entry.action, AuditAction::CreateMaster);
    assert_eq!(entry.result, AuditResult::Success);
    assert_eq!(entry.serial, Some(outcome.serial));
    assert_eq!(entry.fingerprint, Some(outcome.fingerprint));
    assert_eq!(log.entries()[1].action, AuditAction::Export);
    let state = outcome.ca.state().unwrap();
    let master = state.master().expect("master");
    assert_eq!(master.record.fingerprint, outcome.fingerprint);
    assert_eq!(
        state.current_crl(master.serial()).unwrap().info.crl_number,
        1
    );
    assert_consistent(&outcome.ca);
    drop(outcome);
}

#[test]
fn fr04_ac3_wrong_master_passphrase_gives_a_clear_error_and_nothing_else() {
    // Covers: FR-04 AC3
    let test = new_ca("A2");
    let key_pem = same_on_every_drive(&test.drives, "keys/master.key");
    let (_, other_words) = master_passphrase();
    let error = decrypt_key_pem(&key_pem, entered(&other_words).secret()).unwrap_err();
    assert!(matches!(error, CryptoError::WrongPassphrase));
    assert!(error.to_string().contains("nothing was decrypted"));
}

#[test]
fn sec20_a_new_ca_is_never_created_over_an_existing_one() {
    // Covers: SEC-20, FR-12 AC1
    let test = new_ca("A3");
    let now = test.now + time::Duration::minutes(5);
    let backups = [test.drives.ca_drive(1)];
    let request =
        CreateMasterRequest::new(test.drives.ca_drive(0), &backups, test_name("A3 again"));
    let error = plan_create_master(request, confirmed_new(now)).unwrap_err();
    assert!(
        matches!(error, OpsError::Store(StoreError::DriveHoldsCa { .. })),
        "{error}"
    );
    // A CA drive together with an empty drive is refused too.
    let mut drives = TestDrives::new(1);
    let empty = drives.add_ca_drive();
    let request = CreateMasterRequest::new(
        test.drives.ca_drive(0),
        &[empty.as_path()],
        test_name("A3 mix"),
    );
    assert!(matches!(
        plan_create_master(request, confirmed_new(now)).unwrap_err(),
        OpsError::Store(StoreError::DriveHoldsCa { .. })
    ));
    // A drive with other files is refused; so is a CA without a backup drive.
    std::fs::write(drives.ca_drive(0).join("notes.txt"), "KEYSTONE TEST").unwrap();
    let request = CreateMasterRequest::new(
        drives.ca_drive(0),
        &[empty.as_path()],
        test_name("A3 other"),
    );
    assert!(matches!(
        plan_create_master(request, confirmed_new(now)).unwrap_err(),
        OpsError::Store(StoreError::DriveNotEmpty { .. })
    ));
    let request = CreateMasterRequest::new(&empty, &[], test_name("A3 single"));
    assert!(matches!(
        plan_create_master(request, confirmed_new(now)).unwrap_err(),
        OpsError::Store(StoreError::NotEnoughDrives { .. })
    ));
    // The existing key file was never touched.
    assert_eq!(
        same_on_every_drive(&test.drives, "keys/master.key"),
        drive_files(&test.drives, "keys/master.key")[0]
    );
}

#[test]
fn fr02_ac4_review_shows_the_fixed_profile_and_rejects_bad_names() {
    // Covers: FR-02 AC4, FR-10 AC3
    let drives = TestDrives::new(2);
    let now = base_time();
    let backups = [drives.ca_drive(1)];
    let mut name = test_name("A4 Master");
    name.country = Some("USA".into());
    let request = CreateMasterRequest::new(drives.ca_drive(0), &backups, name);
    assert!(matches!(
        plan_create_master(request, confirmed_new(now)).unwrap_err(),
        OpsError::Profile(_)
    ));
    let mut request =
        CreateMasterRequest::new(drives.ca_drive(0), &backups, test_name("A4 Master"));
    request.validity_years = 26;
    assert!(matches!(
        plan_create_master(request.clone(), confirmed_new(now)).unwrap_err(),
        OpsError::Profile(_)
    ));
    request.validity_years = 25;
    let plan = plan_create_master(request, confirmed_new(now)).expect("plan");
    let review = plan.review();
    assert!(review.value("Key").unwrap().contains("RSA 8,192"));
    assert!(review.value("Signature").unwrap().contains("SHA-384"));
    assert!(
        review
            .value("Basic constraints")
            .unwrap()
            .contains("no path length")
    );
    assert_eq!(
        review.value("Serial number").unwrap(),
        plan.serial().to_hex()
    );
    // Planning writes nothing.
    assert_eq!(std::fs::read_dir(drives.ca_drive(0)).unwrap().count(), 0);
}

fn collecting_sink() -> (
    impl Fn(Progress) + Send + Sync,
    std::sync::Arc<Mutex<Vec<Progress>>>,
) {
    let events = std::sync::Arc::new(Mutex::new(Vec::new()));
    let sink_events = std::sync::Arc::clone(&events);
    (
        move |progress: Progress| sink_events.lock().unwrap().push(progress),
        events,
    )
}

#[test]
fn fr16_ac2_cancel_during_master_key_generation_is_journaled_and_drives_stay_reusable() {
    // Covers: FR-16 AC2, NFR-03, FR-22 AC1
    let drives = TestDrives::new(2);
    let now = base_time();
    let (passphrase, _) = master_passphrase();
    let backups = [drives.ca_drive(1)];
    let request = CreateMasterRequest::new(drives.ca_drive(0), &backups, test_name("A5 Master"));
    let plan = plan_create_master(request.clone(), confirmed_new(now)).expect("plan");
    let reserved = plan.serial();
    // A real RSA 8,192 generation, cancelled at its first progress report.
    let cancel = CancelFlag::new();
    let cancel_in_sink = cancel.clone();
    let sink = move |progress: Progress| {
        if matches!(progress, Progress::KeyGeneration { .. }) {
            cancel_in_sink.cancel();
        }
    };
    let error = plan.execute(&passphrase, None, &sink, &cancel).unwrap_err();
    let OpsError::Cancelled {
        operation,
        reserved_serials,
    } = error
    else {
        panic!("{error}");
    };
    assert_eq!(reserved_serials, [reserved]);
    let roots: Vec<&Path> = drives.ca_drives().iter().map(PathBuf::as_path).collect();
    let ca = keystone_core::ops::Ca::open(&roots).unwrap();
    let journal = ca.drive_set().drives()[0]
        .operation_journal(operation)
        .unwrap()
        .unwrap();
    assert_eq!(journal.state(), OperationState::Cancelled);
    assert!(ca.drive_set().known_serials().unwrap().contains(&reserved));
    for drive in drives.ca_drives() {
        assert_eq!(
            std::fs::read_dir(drive.join("keystone/keys"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            std::fs::read_dir(drive.join("keystone/staging"))
                .unwrap()
                .count(),
            0
        );
    }
    assert_consistent(&ca);
    drop(ca);

    // The drives hold no certificate, so Flow A may run again; the serial stays reserved.
    let later = now + time::Duration::minutes(1);
    let plan = plan_create_master(request, confirmed_new(later)).expect("plan on reused drives");
    assert_ne!(plan.serial(), reserved);
    testing::supply_generated_key(keys::master(0));
    let outcome = plan
        .execute(&passphrase, None, &NoProgress, &CancelFlag::new())
        .expect("Flow A on reused drives");
    assert_ne!(outcome.serial, reserved);
    assert_consistent(&outcome.ca);
}

#[test]
fn fr16_ac2_cancel_after_the_key_was_staged_deletes_the_staged_key() {
    // Covers: FR-16 AC2
    let drives = TestDrives::new(2);
    let now = base_time();
    let (passphrase, _) = master_passphrase();
    let backups = [drives.ca_drive(1)];
    let request = CreateMasterRequest::new(drives.ca_drive(0), &backups, test_name("A6 Master"));
    let plan = plan_create_master(request, confirmed_new(now)).expect("plan");
    let cancel = CancelFlag::new();
    let cancel_in_sink = cancel.clone();
    let (collect, events) = collecting_sink();
    let sink = move |progress: Progress| {
        if progress
            == (Progress::Step {
                step: Step::StagingKey,
                cancel_available: true,
            })
        {
            cancel_in_sink.cancel();
        }
        collect(progress);
    };
    testing::supply_generated_key(keys::master(0));
    let error = plan.execute(&passphrase, None, &sink, &cancel).unwrap_err();
    assert!(matches!(error, OpsError::Cancelled { .. }), "{error}");
    assert!(events.lock().unwrap().contains(&Progress::Step {
        step: Step::Cancelling,
        cancel_available: false
    }));
    for drive in drives.ca_drives() {
        assert_eq!(
            std::fs::read_dir(drive.join("keystone/staging"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            std::fs::read_dir(drive.join("keystone/keys"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            std::fs::read_dir(drive.join("keystone/certs"))
                .unwrap()
                .count(),
            0
        );
    }
}

#[test]
fn fr16_ac2_cancel_is_offered_only_before_the_first_signature() {
    // Covers: FR-16 AC2, FR-16 AC1
    let drives = TestDrives::new(2);
    let now = base_time();
    let (passphrase, _) = master_passphrase();
    let backups = [drives.ca_drive(1)];
    let request = CreateMasterRequest::new(drives.ca_drive(0), &backups, test_name("A7 Master"));
    let plan = plan_create_master(request, confirmed_new(now)).expect("plan");
    let (sink, events) = collecting_sink();
    // A cancel pressed after the first signature is ignored: the operation finishes.
    let cancel = CancelFlag::new();
    let cancel_late = cancel.clone();
    let late = move |progress: Progress| {
        if let Progress::Step {
            step: Step::SigningCrl,
            ..
        } = progress
        {
            cancel_late.cancel();
        }
        sink(progress);
    };
    testing::supply_generated_key(keys::master(0));
    let outcome = plan
        .execute(&passphrase, None, &late, &cancel)
        .expect("finishes");
    let events = events.lock().unwrap();
    let available = |wanted: Step| {
        events.iter().find_map(|event| match event {
            Progress::Step {
                step,
                cancel_available,
            } if *step == wanted => Some(*cancel_available),
            _ => None,
        })
    };
    assert_eq!(available(Step::GeneratingKey), Some(true));
    assert_eq!(available(Step::SigningCertificate), Some(true));
    assert_eq!(available(Step::SigningCrl), Some(false));
    assert_eq!(available(Step::MovingIntoPlace), Some(false));
    assert_eq!(available(Step::Done), Some(false));
    assert!(events.contains(&Progress::KeyGeneration { work: 1 }));
    assert_consistent(&outcome.ca);
}
