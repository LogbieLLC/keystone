//! Tests for writing journaled operations (FR-22, FR-16, FR-12, SEC-04, SEC-20).
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use keystone_testkit::TestDrives;

use super::*;
use crate::model::CaLevel;
use crate::store::ExportDrive;
use crate::store::journal::OperationJournal;
use crate::store::testutil::{
    cert, cert_pem, encrypted_key_pem, issue_master, new_ca, open_all, serial, ts,
};

fn journal_of(root: &Path, id: OperationId) -> OperationJournal {
    crate::store::CaDrive::open(root)
        .expect("open")
        .operation_journal(id)
        .expect("journal")
        .expect("exists")
}

fn all_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir).expect("list") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}

fn key_path(n: u8) -> OutputPath {
    OutputPath::new(OutputDir::Keys, &format!("{}.key", serial(n).to_hex())).expect("path")
}

#[test]
fn fr22_ac1_pending_entry_with_planned_serial_is_on_every_drive_first() {
    // Covers: FR-22 AC1, FR-10 AC2
    let drives = TestDrives::new(3);
    let set = new_ca(&drives);
    let op = set
        .begin_operation(
            OperationKind::CreateMaster,
            "CN=KEYSTONE TEST",
            &[serial(1)],
            ts(5),
        )
        .expect("begin");
    assert_eq!(op.id(), OperationId(1));
    for root in drives.ca_drives() {
        let journal = journal_of(root, op.id());
        assert_eq!(journal.entries().len(), 1);
        assert_eq!(journal.planned_serials(), &[serial(1)]);
        assert_eq!(journal.state(), OperationState::Pending);
    }
    // While it is pending, no other operation can start.
    assert!(matches!(
        set.begin_operation(OperationKind::CreateMaster, "x", &[serial(2)], ts(6)),
        Err(StoreError::PendingOperation(OperationId(1)))
    ));
}

#[test]
fn fr22_ac2_outputs_are_staged_verified_moved_and_completed_last() {
    // Covers: FR-22 AC2, FR-12 AC1, FR-12 AC2, FR-12 AC4
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let id = issue_master(&set, 1, ts(10));
    for root in drives.ca_drives() {
        let journal = journal_of(root, id);
        assert_eq!(journal.state(), OperationState::Completed);
        let last = journal.entries().last().expect("entry");
        assert!(matches!(last.event, JournalEvent::Completed { .. }));
        let outputs = journal.completed_outputs().expect("outputs");
        assert_eq!(outputs.len(), 3);
        for output in outputs {
            let data =
                fs::read(root.join("keystone").join(output.path.to_string())).expect("placed");
            assert_eq!(sha256(&data), output.sha256);
            assert_eq!(data.len() as u64, output.size);
        }
        // Staging is empty again, and no temporary file is left anywhere.
        assert!(!root.join("keystone/staging").join(id.stem()).exists());
        for file in all_files(root) {
            let name = file
                .file_name()
                .expect("name")
                .to_string_lossy()
                .to_string();
            assert!(!name.starts_with('.'), "temporary file left: {file:?}");
        }
    }
    // The next operation gets the next number.
    assert_eq!(set.next_operation_id().expect("next"), OperationId(2));
}

#[test]
fn fr16_cancel_before_a_persistent_change_keeps_the_serial_reserved() {
    // Covers: FR-16 AC1, FR-22 AC1, FR-10 AC2
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let mut op = set
        .begin_operation(
            OperationKind::CreateMaster,
            "CN=KEYSTONE TEST",
            &[serial(1)],
            ts(5),
        )
        .expect("begin");
    let id = op.id();
    // Long key generation stages the encrypted key: still cancellable.
    op.stage(key_path(1), encrypted_key_pem(serial(1)).as_bytes())
        .expect("stage");
    assert!(!op.has_persistent_change());
    op.cancel(ts(6)).expect("cancel");
    for root in drives.ca_drives() {
        let journal = journal_of(root, id);
        assert_eq!(journal.state(), OperationState::Cancelled);
        assert_eq!(journal.planned_serials(), &[serial(1)]);
        assert!(!root.join("keystone/staging").join(id.stem()).exists());
        assert!(!root.join("keystone/keys").join(key_path(1).name()).exists());
    }
    let log = set.audit_log().expect("log");
    assert_eq!(
        log.entries()[0].result,
        crate::store::AuditResult::Cancelled
    );
    assert_eq!(log.entries()[0].operation, Some(id));
    assert!(set.known_serials().expect("known").contains(&serial(1)));
    assert!(set.ensure_in_sync().is_ok());
}

#[test]
fn regression_cancel_on_a_resumed_operation_removes_every_staged_file() {
    // Covers: FR-16 AC2, FR-22 AC7
    // Regression (review finding 9): a resumed handle knows no staged outputs until
    // staging is sealed, so cancel deleted nothing and the staged key stayed behind.
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let mut op = set
        .begin_operation(
            OperationKind::CreateMaster,
            "CN=KEYSTONE TEST",
            &[serial(1)],
            ts(5),
        )
        .expect("begin");
    let id = op.id();
    op.stage(key_path(1), encrypted_key_pem(serial(1)).as_bytes())
        .expect("stage");
    // A second file reached only the primary before an interruption.
    crate::store::fault::fail_after(1);
    assert!(
        op.stage(
            OutputPath::new(OutputDir::Certs, "partial.crt").expect("path"),
            cert_pem(serial(1)).as_bytes(),
        )
        .is_err()
    );
    crate::store::fault::disarm();
    drop(op);
    let set = open_all(&drives);
    let op = set.resume_operation(id).expect("resume");
    assert!(op.outputs().is_empty(), "a resumed handle lists no outputs");
    op.cancel(ts(6)).expect("cancel");
    for root in drives.ca_drives() {
        assert_eq!(journal_of(root, id).state(), OperationState::Cancelled);
        let staging = root.join("keystone/staging").join(id.stem());
        assert!(
            !staging.exists(),
            "{} still holds {:?}",
            staging.display(),
            all_files(&staging)
        );
    }
    assert!(set.ensure_in_sync().is_ok());
}

#[test]
fn fr16_no_cancel_after_a_signature() {
    // Covers: FR-16 AC1, FR-22 AC3
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let mut op = set
        .begin_operation(
            OperationKind::CreateMaster,
            "CN=KEYSTONE TEST",
            &[serial(1)],
            ts(5),
        )
        .expect("begin");
    op.record_signed(
        SignedObject::Certificate {
            record: Box::new(cert(serial(1), CaLevel::Master, serial(1))),
            pem: cert_pem(serial(1)),
        },
        ts(5),
    )
    .expect("signed");
    assert!(op.has_persistent_change());
    assert!(matches!(
        op.cancel(ts(6)),
        Err(StoreError::OperationState { .. })
    ));
}

#[test]
fn fr22_ac3_an_unplanned_serial_is_still_journaled() {
    // Covers: FR-22 AC3, FR-10 AC2
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let mut op = set
        .begin_operation(
            OperationKind::CreateMaster,
            "CN=KEYSTONE TEST",
            &[serial(1)],
            ts(5),
        )
        .expect("begin");
    let id = op.id();
    let error = op
        .record_signed(
            SignedObject::Certificate {
                record: Box::new(cert(serial(9), CaLevel::Master, serial(9))),
                pem: cert_pem(serial(9)),
            },
            ts(5),
        )
        .expect_err("unplanned");
    assert!(matches!(error, StoreError::OperationState { .. }));
    for root in drives.ca_drives() {
        assert_eq!(journal_of(root, id).signed().count(), 1);
    }
}

#[test]
fn sec04_plaintext_private_keys_never_reach_a_drive() {
    // Covers: SEC-04, SEC-15
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let mut op = set
        .begin_operation(
            OperationKind::CreateMaster,
            "CN=KEYSTONE TEST",
            &[serial(1)],
            ts(5),
        )
        .expect("begin");
    // Build the markers at run time so this source file holds no marker itself.
    let plain = format!("-----BEGIN {}PRIVATE KEY-----\nAAAA\n", "");
    let rsa = format!("-----BEGIN {}PRIVATE KEY-----\nAAAA\n", "RSA ");
    assert!(matches!(
        op.stage(key_path(1), plain.as_bytes()),
        Err(StoreError::Unsafe(_))
    ));
    let crt = OutputPath::new(OutputDir::Certs, "bundle.pem").expect("path");
    assert!(matches!(
        op.stage(crt, rsa.as_bytes()),
        Err(StoreError::Unsafe(_))
    ));
    assert!(matches!(
        op.stage(key_path(2), b"not a key"),
        Err(StoreError::Unsafe(_))
    ));
    op.stage(key_path(3), encrypted_key_pem(serial(3)).as_bytes())
        .expect("encrypted keys are fine");
    op.cancel(ts(6)).expect("cancel");
}

#[test]
fn sec20_moving_into_place_never_overwrites_an_existing_key() {
    // Covers: SEC-20
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let existing = drives
        .ca_drive(1)
        .join("keystone/keys")
        .join(key_path(1).name());
    let original = encrypted_key_pem(serial(99));
    fs::write(&existing, &original).expect("existing key");
    let mut op = set
        .begin_operation(
            OperationKind::CreateMaster,
            "CN=KEYSTONE TEST",
            &[serial(1)],
            ts(5),
        )
        .expect("begin");
    op.stage(key_path(1), encrypted_key_pem(serial(1)).as_bytes())
        .expect("stage");
    op.seal_staging(ts(5)).expect("seal");
    assert!(matches!(op.commit(), Err(StoreError::AlreadyExists { .. })));
    assert_eq!(fs::read_to_string(&existing).expect("read"), original);
}

#[test]
fn fr22_ac7_yubikey_setup_is_journaled_step_by_step_and_resumable() {
    // Covers: FR-22 AC7, FR-22 AC1
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    issue_master(&set, 1, ts(1));
    let mut op = set
        .begin_operation(
            OperationKind::SetupYubikey,
            "CN=KEYSTONE TEST main",
            &[serial(2)],
            ts(5),
        )
        .expect("begin");
    let id = op.id();
    op.record_yubikey_step(YubikeySetupStep::PinChanged, 4242, ts(6))
        .expect("pin");
    op.record_yubikey_step(YubikeySetupStep::PukChanged, 4242, ts(7))
        .expect("puk");
    assert!(
        op.record_yubikey_step(YubikeySetupStep::PinChanged, 4242, ts(8))
            .is_err()
    );
    assert!(
        op.record_yubikey_step(YubikeySetupStep::ManagementKeySet, 9999, ts(8))
            .is_err()
    );
    // Interrupted here; after a restart the operation is resumed from the journal.
    drop(op);
    let set = open_all(&drives);
    let mut resumed = set.resume_operation(id).expect("resume");
    assert_eq!(
        resumed.completed_yubikey_steps().expect("steps"),
        vec![
            (YubikeySetupStep::PinChanged, 4242),
            (YubikeySetupStep::PukChanged, 4242)
        ]
    );
    assert!(resumed.has_persistent_change());
    resumed
        .record_yubikey_step(YubikeySetupStep::ManagementKeySet, 4242, ts(9))
        .expect("management key");
    for root in drives.ca_drives() {
        let journal = journal_of(root, id);
        assert_eq!(journal.yubikey_steps().len(), 3);
        // No secret in any journal file.
        for raw in journal.raw_entries() {
            let text = String::from_utf8_lossy(raw).to_lowercase();
            assert!(!text.contains("\"pin\"") && !text.contains("\"puk\""));
        }
    }
    // Only YubiKey setup records YubiKey steps.
    drop(resumed);
}

#[test]
fn fr22_ac2_export_needs_the_completed_entry_and_verified_outputs_on_two_drives() {
    // Covers: FR-22 AC2
    let drives = TestDrives::new(3);
    let set = new_ca(&drives);
    let mut op = set
        .begin_operation(
            OperationKind::CreateMaster,
            "CN=KEYSTONE TEST",
            &[serial(1)],
            ts(5),
        )
        .expect("begin");
    let pending_id = op.id();
    op.stage(key_path(1), encrypted_key_pem(serial(1)).as_bytes())
        .expect("stage");
    assert!(
        set.export_ready(pending_id).is_err(),
        "no completed entry yet"
    );
    op.cancel(ts(6)).expect("cancel");
    let id = issue_master(&set, 2, ts(10));
    let (outputs, verified) = set.export_ready(id).expect("ready");
    assert_eq!(verified.len(), 3);
    // One damaged copy: still two verified drives.
    let cert_out = outputs
        .iter()
        .find(|o| o.path.dir() == OutputDir::Certs)
        .expect("cert")
        .clone();
    fs::write(
        drives
            .ca_drive(2)
            .join("keystone")
            .join(cert_out.path.to_string()),
        b"x",
    )
    .expect("damage");
    assert_eq!(set.export_ready(id).expect("ready").1.len(), 2);
    // Two damaged copies: export refused.
    fs::write(
        drives
            .ca_drive(1)
            .join("keystone")
            .join(cert_out.path.to_string()),
        b"x",
    )
    .expect("damage");
    assert!(set.export_ready(id).is_err());
    // A healthy CA exports, create-only and verified.
    let healthy = TestDrives::new(2);
    let set = new_ca(&healthy);
    let id = issue_master(&set, 3, ts(10));
    let (outputs, _) = set.export_ready(id).expect("ready");
    let export = ExportDrive::open(healthy.export_drive()).expect("export");
    let files: Vec<(OutputPath, String)> = outputs
        .iter()
        .filter(|o| o.path.dir() != OutputDir::Record)
        .map(|o| (o.path.clone(), o.path.name().to_string()))
        .collect();
    let written = set.export_outputs(id, &export, &files).expect("export");
    assert_eq!(written.len(), 2);
    assert!(
        healthy
            .export_drive()
            .join("keystone-export")
            .join(files[0].1.clone())
            .exists()
    );
    assert!(
        set.export_outputs(id, &export, &files).is_err(),
        "never overwritten"
    );
}

#[test]
fn completing_needs_staging_placement_and_audit() {
    // Covers: FR-22 AC2, FR-14 AC1
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let op = set
        .begin_operation(OperationKind::RefreshCrl, "CN=KEYSTONE TEST", &[], ts(5))
        .expect("begin");
    assert!(matches!(
        op.complete(ts(6)),
        Err(StoreError::OperationState { .. })
    ));
    let set = open_all(&drives);
    let mut op = set.resume_operation(OperationId(1)).expect("resume");
    op.seal_staging(ts(6)).expect("seal");
    op.commit().expect("commit nothing");
    assert!(op.append_audit(&[], ts(6)).is_err());
    let op_id = op.id();
    assert!(matches!(
        set.resume_operation(op_id).expect("resume").complete(ts(7)),
        Err(StoreError::OperationState { .. })
    ));
}

#[test]
fn operation_steps_in_the_wrong_order_are_refused() {
    // Covers: FR-22 AC1, FR-22 AC2, FR-22 AC7, SEC-20
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let mut op = set
        .begin_operation(
            OperationKind::CreateSubIntermediate,
            "CN=KEYSTONE TEST",
            &[serial(5)],
            ts(1),
        )
        .expect("begin");
    let id = op.id();
    assert!(matches!(
        op.record_yubikey_step(YubikeySetupStep::PinChanged, 1, ts(1)),
        Err(StoreError::OperationState { .. })
    ));
    assert!(op.commit().is_err(), "commit before sealing");
    op.stage(key_path(5), encrypted_key_pem(serial(5)).as_bytes())
        .expect("stage");
    assert!(
        op.stage(key_path(5), encrypted_key_pem(serial(5)).as_bytes())
            .is_err()
    );
    let big = OutputPath::new(OutputDir::Certs, "big.crt").expect("path");
    assert!(
        op.stage(big, &vec![b'x'; MAX_OUTPUT_FILE_BYTES + 1])
            .is_err()
    );
    assert_eq!(op.outputs().len(), 1);
    assert_eq!(op.planned_serials(), &[serial(5)]);
    assert_eq!(op.kind(), OperationKind::CreateSubIntermediate);
    op.seal_staging(ts(1)).expect("seal");
    assert!(op.seal_staging(ts(1)).is_err());
    let late = OutputPath::new(OutputDir::Certs, "late.crt").expect("path");
    assert!(op.stage(late, b"KEYSTONE TEST").is_err());
    let signed = SignedObject::Certificate {
        record: Box::new(cert(serial(5), CaLevel::SubIntermediate, serial(1))),
        pem: cert_pem(serial(5)),
    };
    assert!(
        op.record_signed(signed, ts(1)).is_err(),
        "nothing is signed after staging"
    );
    // A staged copy missing on one drive stops the move into place.
    let staged = drives
        .ca_drive(1)
        .join("keystone/staging")
        .join(id.stem())
        .join("keys")
        .join(key_path(5).name());
    fs::remove_file(&staged).expect("remove");
    assert!(op.commit().is_err());
    drop(op);
    // Resuming needs a journal on every drive and an unfinished operation.
    assert!(set.resume_operation(OperationId(99)).is_err());
    let done = TestDrives::new(2);
    let done_set = new_ca(&done);
    let finished = issue_master(&done_set, 1, ts(1));
    assert!(matches!(
        done_set.resume_operation(finished),
        Err(StoreError::OperationState { .. })
    ));
    let export = ExportDrive::open(done.export_drive()).expect("export");
    let not_an_output = OutputPath::new(OutputDir::Crls, "none.crl").expect("path");
    assert!(matches!(
        done_set.export_outputs(finished, &export, &[(not_an_output, "x.crl".to_string())]),
        Err(StoreError::Unsafe(_))
    ));
}
