//! Tests for recovery after interrupted operations (FR-22 AC4, AC6, AC7, SEC-22).
#![forbid(unsafe_code)]

use keystone_testkit::TestDrives;

use super::*;
use crate::model::CaLevel;
use crate::store::audit::{AuditAction, AuditResult};
use crate::store::compare::DriveComparison;
use crate::store::fault;
use crate::store::journal::OperationJournal;
use crate::store::paths::OutputPath;
use crate::store::record::{RecordChange, RecordSource, RecordUpdate};
use crate::store::testutil::{
    cert, cert_pem, encrypted_key_pem, issue, new_ca, open_all, serial, ts,
};

fn only_pending(set: &DriveSet) -> PendingOperation {
    let report = set.recovery_report().expect("report");
    assert_eq!(report.pending.len(), 1, "{report:?}");
    report.pending.into_iter().next().expect("pending")
}

fn master_record() -> crate::store::record::CertificateRecord {
    cert(serial(1), CaLevel::Master, serial(1))
}

/// The outputs `issue` stages for the master with serial 1.
fn master_outputs(operation: OperationId) -> Vec<(OutputPath, Vec<u8>)> {
    let update = RecordUpdate::new(
        operation,
        vec![RecordChange::Issued {
            certificate: Box::new(master_record()),
        }],
    );
    vec![
        (
            OutputPath::new(OutputDir::Certs, &format!("{}.crt", serial(1).to_hex()))
                .expect("path"),
            cert_pem(serial(1)).into_bytes(),
        ),
        (
            OutputPath::new(OutputDir::Keys, &format!("{}.key", serial(1).to_hex())).expect("path"),
            encrypted_key_pem(serial(1)).into_bytes(),
        ),
        (update.output_path(), update.to_bytes()),
    ]
}

#[test]
fn fr22_ac4_nothing_signed_offers_abandon_and_keeps_the_serial() {
    // Covers: FR-22 AC4, FR-22 AC8, FR-10 AC2
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let op = set
        .begin_operation(
            OperationKind::CreateMaster,
            "CN=KEYSTONE TEST",
            &[serial(1)],
            ts(5),
        )
        .expect("begin");
    let id = op.id();
    drop(op); // interrupted
    let set = open_all(&drives);
    let pending = only_pending(&set);
    assert_eq!(pending.operation, id);
    assert!(!pending.signed_output_exists);
    assert_eq!(pending.actions, vec![RecoveryAction::Abandon]);
    assert_eq!(pending.drives.len(), 2);
    assert!(
        pending
            .drives
            .iter()
            .all(|d| d.journal_entries == vec!["001-pending.json"])
    );
    let sentence = pending.actions[0].description(id);
    assert!(
        sentence.contains("nothing is deleted or overwritten"),
        "{sentence}"
    );
    // Finishing is not offered, so it is refused.
    assert!(set.finish_operation(id, 0, ts(6)).is_err());
    set.abandon_operation(id, ts(6)).expect("abandon");
    for drive in set.drives() {
        let journal = drive.operation_journal(id).expect("read").expect("journal");
        assert_eq!(journal.state(), OperationState::Abandoned);
    }
    let log = set.audit_log().expect("log");
    assert_eq!(log.entries()[0].action, AuditAction::RecoveryAbandon);
    assert_eq!(log.entries()[0].result, AuditResult::Abandoned);
    assert!(set.recovery_report().expect("report").is_clean());
    assert!(set.known_serials().expect("serials").contains(&serial(1)));
    assert_eq!(set.compare().expect("compare"), DriveComparison::InSync);
}

#[test]
fn fr22_ac4_signed_output_is_never_abandoned() {
    // Covers: FR-22 AC4, FR-22 AC3
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
            record: Box::new(master_record()),
            pem: cert_pem(serial(1)),
        },
        ts(5),
    )
    .expect("signed");
    let id = op.id();
    drop(op);
    let set = open_all(&drives);
    let pending = only_pending(&set);
    assert!(pending.signed_output_exists);
    assert!(!pending.actions.contains(&RecoveryAction::Abandon));
    assert!(pending.blocked_reason.is_some());
    assert!(
        pending
            .drives
            .iter()
            .all(|d| d.signed_certificates == vec![serial(1)])
    );
    assert!(set.abandon_operation(id, ts(6)).is_err());
    // The signed certificate is in the record.
    let record = set.issuance_record().expect("record");
    assert_eq!(
        record.get(serial(1)).expect("cert").source,
        RecordSource::JournalOnly
    );
}

#[test]
fn fr22_ac4_finishes_from_the_drive_that_holds_the_verified_output() {
    // Covers: FR-22 AC4, FR-22 AC2, FR-12 AC2
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
    op.record_signed(
        SignedObject::Certificate {
            record: Box::new(master_record()),
            pem: cert_pem(serial(1)),
        },
        ts(5),
    )
    .expect("signed");
    for (path, data) in master_outputs(id) {
        op.stage(path, &data).expect("stage");
    }
    op.seal_staging(ts(5)).expect("seal");
    // Interrupted while moving files into place: after one file on the primary.
    fault::fail_after(1);
    assert!(op.commit().is_err());
    fault::disarm();
    drop(op);
    let set = open_all(&drives);
    let pending = only_pending(&set);
    assert!(pending.signed_output_exists);
    let primary = &pending.drives[0];
    assert!(primary.holds_verified_output);
    assert_eq!(primary.outputs.len(), 3);
    assert_eq!(
        primary
            .outputs
            .iter()
            .filter(|o| o.placed == FileState::Verified)
            .count(),
        1
    );
    assert!(
        pending.drives[1]
            .outputs
            .iter()
            .all(|o| o.staged == FileState::Verified)
    );
    assert_eq!(pending.actions.len(), 1);
    let RecoveryAction::FinishFrom { drive_index, .. } = pending.actions[0] else {
        panic!("expected finish, got {:?}", pending.actions);
    };
    set.finish_operation(id, drive_index, ts(9))
        .expect("finish");
    for drive in set.drives() {
        let journal = drive.operation_journal(id).expect("read").expect("journal");
        assert_eq!(journal.state(), OperationState::Completed);
    }
    let log = set.audit_log().expect("log");
    assert_eq!(log.entries()[0].action, AuditAction::RecoveryFinish);
    assert_eq!(log.entries()[0].serial, Some(serial(1)));
    assert_eq!(set.compare().expect("compare"), DriveComparison::InSync);
    assert!(set.recovery_report().expect("report").is_clean());
    let record = set.issuance_record().expect("record");
    assert_eq!(
        record.get(serial(1)).expect("cert").source,
        RecordSource::RecordFile
    );
    assert!(set.export_ready(id).is_ok());
}

#[test]
fn fr22_ac7_interrupted_yubikey_setup_offers_resume() {
    // Covers: FR-22 AC7, FR-22 AC5
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let mut op = set
        .begin_operation(
            OperationKind::SetupYubikey,
            "CN=KEYSTONE TEST main",
            &[serial(2)],
            ts(5),
        )
        .expect("begin");
    op.record_yubikey_step(YubikeySetupStep::PinChanged, 77, ts(5))
        .expect("pin");
    op.record_yubikey_step(YubikeySetupStep::PukChanged, 77, ts(5))
        .expect("puk");
    // The management-key entry reached only the primary.
    fault::fail_after(1);
    assert!(
        op.record_yubikey_step(YubikeySetupStep::ManagementKeySet, 77, ts(5))
            .is_err()
    );
    fault::disarm();
    let id = op.id();
    drop(op);
    let set = open_all(&drives);
    let pending = only_pending(&set);
    assert_eq!(
        pending.actions,
        vec![RecoveryAction::ResumeYubikeySetup {
            next_step: Some(YubikeySetupStep::KeyGenerated)
        }]
    );
    assert_eq!(pending.drives[0].yubikey_steps.len(), 3);
    assert_eq!(pending.drives[1].yubikey_steps.len(), 2);
    // The operations layer syncs the journal, then resumes from the first missing step.
    assert!(
        set.resume_operation(id).is_err(),
        "journals differ until synced"
    );
    set.sync_operation_journal(id).expect("sync");
    let resumed = set.resume_operation(id).expect("resume");
    assert_eq!(resumed.completed_yubikey_steps().expect("steps").len(), 3);
}

/// Simulates the operations layer finishing an operation whose signature is journaled
/// but whose outputs were not all staged: re-stage from what was signed, then finish.
fn resume_and_finish(set: &DriveSet, id: OperationId) {
    set.sync_operation_journal(id).expect("sync");
    let mut op = set.resume_operation(id).expect("resume");
    for (path, data) in master_outputs(id) {
        op.stage(path, &data).expect("re-stage");
    }
    op.seal_staging(ts(8)).expect("seal");
    op.commit().expect("commit");
    let mut draft = crate::store::audit::AuditDraft::new(
        AuditAction::CreateMaster,
        "CN=KEYSTONE TEST",
        AuditResult::Success,
    );
    draft.serial = Some(serial(1));
    op.append_audit(&[draft], ts(8)).expect("audit");
    op.complete(ts(8)).expect("complete");
}

fn signed_anywhere(set: &DriveSet, id: OperationId) -> bool {
    set.drives().iter().any(|drive| {
        drive
            .operation_journal(id)
            .expect("read")
            .is_some_and(|journal: OperationJournal| journal.signed().next().is_some())
    })
}

#[test]
fn fr22_ac6_an_operation_interrupted_at_every_step_recovers_without_losing_a_record() {
    // Covers: FR-22 AC6, FR-22 AC3, FR-22 AC4, FR-12 AC2, SEC-22
    let count_drives = TestDrives::new(2);
    let set = new_ca(&count_drives);
    fault::take_count();
    issue(&set, OperationKind::CreateMaster, master_record(), ts(5));
    let total = fault::take_count();
    assert!(total >= 20, "{total}");
    for allowed in 0..total {
        let drives = TestDrives::new(2);
        let set = new_ca(&drives);
        fault::fail_after(allowed);
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            issue(&set, OperationKind::CreateMaster, master_record(), ts(5))
        }));
        fault::disarm();
        assert!(
            interrupted.is_err(),
            "the fault after {allowed} changes must interrupt"
        );
        let set = open_all(&drives);
        let id = OperationId(1);
        let was_signed = signed_anywhere(&set, id);
        let started = set
            .drives()
            .iter()
            .any(|drive| drive.operation_journal(id).expect("read").is_some());
        for pending in set.recovery_report().expect("report").pending {
            match pending.actions.first() {
                Some(RecoveryAction::FinishFrom { drive_index, .. }) => {
                    set.finish_operation(pending.operation, *drive_index, ts(9))
                        .expect("finish");
                }
                Some(RecoveryAction::Abandon) => {
                    assert!(
                        !was_signed,
                        "abandon offered after a signature (fault {allowed})"
                    );
                    set.abandon_operation(pending.operation, ts(9))
                        .expect("abandon");
                }
                Some(other) => panic!("unexpected action {other:?}"),
                None => {
                    assert!(pending.signed_output_exists, "blocked without a reason");
                    resume_and_finish(&set, pending.operation);
                }
            }
        }
        // Consistent: same history everywhere, nothing pending, record kept, serial reserved.
        let set = open_all(&drives);
        assert!(
            set.recovery_report().expect("report").is_clean(),
            "fault {allowed}"
        );
        assert_eq!(
            set.compare().expect("compare"),
            DriveComparison::InSync,
            "fault {allowed}"
        );
        assert!(set.ensure_in_sync().is_ok());
        // Once the pending entry reached any drive, the serial stays reserved.
        assert_eq!(
            set.known_serials().expect("serials").contains(&serial(1)),
            started
        );
        if was_signed {
            let record = set.issuance_record().expect("record");
            assert_eq!(
                record.get(serial(1)).expect("never dropped").source,
                RecordSource::RecordFile,
                "fault {allowed}"
            );
        }
    }
}
