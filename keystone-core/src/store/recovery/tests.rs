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

#[test]
fn regression_the_recovery_finish_entry_keeps_the_action_names_and_every_serial() {
    // Covers: FR-14 AC1, FR-21 AC6, FR-22 AC4
    // Regression (review finding 8): the entry written when recovery finished an
    // operation lost its original action, the permitted names and every serial but the
    // first certificate's.
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    crate::store::testutil::issue_master(&set, 1, ts(1));
    // A sub-intermediate with name constraints, staged and sealed, then interrupted.
    let sub = cert(serial(3), CaLevel::SubIntermediate, serial(1));
    let mut op = set
        .begin_operation(
            OperationKind::CreateSubIntermediate,
            &sub.subject.display(),
            &[serial(3)],
            ts(5),
        )
        .expect("begin");
    let id = op.id();
    op.record_signed(
        SignedObject::Certificate {
            record: Box::new(sub.clone()),
            pem: cert_pem(serial(3)),
        },
        ts(5),
    )
    .expect("signed");
    let update = RecordUpdate::new(
        id,
        vec![RecordChange::Issued {
            certificate: Box::new(sub.clone()),
        }],
    );
    op.stage(
        OutputPath::new(OutputDir::Certs, "sub.crt").expect("path"),
        cert_pem(serial(3)).as_bytes(),
    )
    .expect("stage");
    op.stage(update.output_path(), &update.to_bytes())
        .expect("stage");
    op.seal_staging(ts(5)).expect("seal");
    drop(op);
    let set = open_all(&drives);
    set.finish_operation(id, 0, ts(6)).expect("finish");
    let log = set.audit_log().expect("log");
    let entry = log.entries().last().expect("entry");
    assert_eq!(entry.action, AuditAction::RecoveryFinish);
    assert_eq!(entry.operation, Some(id));
    assert_eq!(entry.serial, Some(serial(3)));
    assert_eq!(entry.fingerprint, Some(sub.fingerprint));
    assert_eq!(entry.result, AuditResult::Success);
    let details = entry.details.as_ref().expect("details");
    assert_eq!(
        details.original_action,
        Some(AuditAction::CreateSubIntermediate)
    );
    assert_eq!(details.issuer_serial, Some(serial(1)));
    assert_eq!(details.name_constraints, Some(true));
    assert_eq!(details.permitted_dns, Some(vec!["starnet".to_string()]));
    assert_eq!(details.serials, Some(vec![serial(3)]));

    // A revocation that also marks two children: every serial and the reason are kept.
    let main = cert(serial(4), CaLevel::MainIntermediate, serial(1));
    let child_a = cert(serial(5), CaLevel::SubIntermediate, serial(4));
    let child_b = cert(serial(6), CaLevel::SubIntermediate, serial(4));
    for record in [main, child_a, child_b] {
        let kind = if record.level == CaLevel::MainIntermediate {
            OperationKind::SetupYubikey
        } else {
            OperationKind::CreateSubIntermediate
        };
        crate::store::testutil::issue(&set, kind, record, ts(7));
    }
    let mut op = set
        .begin_operation(
            OperationKind::ReplaceYubikey,
            "CN=KEYSTONE TEST main",
            &[],
            ts(8),
        )
        .expect("begin");
    let id = op.id();
    let update = RecordUpdate::new(
        id,
        vec![
            RecordChange::Revoked {
                serial: serial(4),
                date: ts(8),
                reason: crate::model::RevocationReason::KeyCompromise,
            },
            RecordChange::RevokedByAncestor {
                serial: serial(5),
                ancestor: serial(4),
                date: ts(8),
            },
            RecordChange::RevokedByAncestor {
                serial: serial(6),
                ancestor: serial(4),
                date: ts(8),
            },
        ],
    );
    op.stage(update.output_path(), &update.to_bytes())
        .expect("stage");
    op.seal_staging(ts(8)).expect("seal");
    drop(op);
    let set = open_all(&drives);
    set.finish_operation(id, 0, ts(9)).expect("finish");
    let log = set.audit_log().expect("log");
    let entry = log.entries().last().expect("entry");
    assert_eq!(entry.action, AuditAction::RecoveryFinish);
    assert_eq!(entry.serial, Some(serial(4)));
    let details = entry.details.as_ref().expect("details");
    assert_eq!(details.original_action, Some(AuditAction::ReplaceYubikey));
    assert_eq!(
        details.revocation_reason,
        Some(crate::model::RevocationReason::KeyCompromise)
    );
    assert_eq!(details.serials, Some(vec![serial(4), serial(5), serial(6)]));
    assert_eq!(set.compare().expect("compare"), DriveComparison::InSync);
}

/// Every drive's journals parse, no operation is pending, the drives agree and a new
/// operation can begin.
fn assert_recovered(drives: &TestDrives, context: &str) {
    let set = open_all(drives);
    for drive in set.drives() {
        let journals = drive
            .journal()
            .unwrap_or_else(|e| panic!("{context}: journal of {}: {e}", drive.label()));
        for (operation, journal) in journals {
            assert_ne!(
                journal.state(),
                OperationState::Pending,
                "{context}: {operation} on {}",
                drive.label()
            );
        }
    }
    assert!(
        set.recovery_report().expect("report").is_clean(),
        "{context}"
    );
    assert_eq!(
        set.compare().expect("compare"),
        DriveComparison::InSync,
        "{context}"
    );
    set.ensure_in_sync()
        .unwrap_or_else(|e| panic!("{context}: {e}"));
    let next = set
        .begin_operation(
            OperationKind::Revoke,
            "CN=KEYSTONE TEST next",
            &[serial(200)],
            ts(100),
        )
        .unwrap_or_else(|e| panic!("{context}: a new operation is refused: {e}"));
    next.cancel(ts(100)).expect("cancel the probe operation");
}

/// Takes the first offered action of every interrupted operation (at most `rounds`
/// times), as the recovery screen does after each restart.
fn recover_with_first_actions(drives: &TestDrives, rounds: usize, context: &str) {
    for round in 0..rounds {
        let set = open_all(drives);
        let report = set
            .recovery_report()
            .unwrap_or_else(|e| panic!("{context}: round {round}: {e}"));
        if report.is_clean() {
            return;
        }
        let time = ts(50 + round as i64);
        for pending in report.pending {
            let result = match pending.actions.first() {
                Some(RecoveryAction::FinishFrom { drive_index, .. }) => {
                    set.finish_operation(pending.operation, *drive_index, time)
                }
                Some(RecoveryAction::Abandon) => set.abandon_operation(pending.operation, time),
                other => panic!(
                    "{context}: round {round}: no usable action {other:?}: {:?}",
                    pending.blocked_reason
                ),
            };
            result.unwrap_or_else(|e| panic!("{context}: round {round}: {e}"));
        }
    }
}

fn begin_master(set: &DriveSet) -> crate::store::OperationHandle<'_> {
    set.begin_operation(
        OperationKind::CreateMaster,
        "CN=KEYSTONE TEST",
        &[serial(1)],
        ts(5),
    )
    .expect("begin")
}

#[test]
fn regression_abandon_after_an_interrupted_cancel_never_corrupts_the_journals() {
    // Covers: FR-22 AC4, FR-22 AC6, FR-16 AC2, SEC-22
    // Regression (review finding 1): the cancelled entry reached only the primary; the
    // recovery screen then offered Abandon, which wrote a second final entry and made
    // both drives' journals unreadable for good.
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let op = begin_master(&set);
    // cancel: audit primary, audit backup, cancelled primary, cancelled backup.
    fault::fail_after(3);
    assert!(op.cancel(ts(6)).is_err());
    fault::disarm();
    let set = open_all(&drives);
    let pending = only_pending(&set);
    assert_eq!(pending.drives[0].state, Some(OperationState::Cancelled));
    assert_eq!(pending.drives[1].state, Some(OperationState::Pending));
    assert!(
        !pending.actions.contains(&RecoveryAction::Abandon),
        "{:?}",
        pending.actions
    );
    assert!(
        set.abandon_operation(OperationId(1), ts(7)).is_err(),
        "abandon must be refused once a final entry exists"
    );
    assert!(
        matches!(
            pending.actions.as_slice(),
            [RecoveryAction::FinishFrom { drive_index: 0, .. }]
        ),
        "{:?}",
        pending.actions
    );
    set.finish_operation(OperationId(1), 0, ts(7))
        .expect("finish from the drive holding the cancelled entry");
    for drive in open_all(&drives).drives() {
        let journal = drive
            .operation_journal(OperationId(1))
            .expect("readable")
            .expect("journal");
        assert_eq!(journal.state(), OperationState::Cancelled);
    }
    assert_recovered(&drives, "after finishing the cancel");
}

#[test]
fn regression_an_abandon_interrupted_between_the_audit_writes_does_not_deadlock() {
    // Covers: FR-22 AC4, FR-12 AC3, SEC-22
    // Regression (review finding 2): the abandon's audit entry reached only the primary;
    // compare() then reported damage and Abandon failed with "compare and repair first".
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    drop(begin_master(&set));
    let set = open_all(&drives);
    // abandon: audit primary, audit backup, ... -> fail the backup's audit write.
    fault::fail_after(1);
    assert!(set.abandon_operation(OperationId(1), ts(6)).is_err());
    fault::disarm();
    let set = open_all(&drives);
    assert_eq!(
        only_pending(&set).actions,
        vec![RecoveryAction::Abandon],
        "abandon is offered again"
    );
    set.abandon_operation(OperationId(1), ts(7))
        .expect("abandon again");
    let log = open_all(&drives).audit_log().expect("same log everywhere");
    let abandons = log
        .entries()
        .iter()
        .filter(|e| e.action == AuditAction::RecoveryAbandon)
        .count();
    assert_eq!(abandons, 1, "the first abandon entry is reused");
    assert_recovered(&drives, "after abandoning again");
}

#[test]
fn regression_a_cancel_interrupted_between_the_audit_writes_does_not_deadlock() {
    // Covers: FR-16 AC2, FR-22 AC4, SEC-22
    // Regression (review finding 2): the cancel's audit entry reached only the primary.
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let op = begin_master(&set);
    fault::fail_after(1);
    assert!(op.cancel(ts(6)).is_err());
    fault::disarm();
    let context = "cancel interrupted after the primary's audit";
    recover_with_first_actions(&drives, 3, context);
    assert_recovered(&drives, context);
}

#[test]
fn fr22_ac6_cancel_interrupted_at_every_drive_change_recovers() {
    // Covers: FR-22 AC6, FR-16 AC2, FR-22 AC4, SEC-22
    fn staged(set: &DriveSet) -> crate::store::OperationHandle<'_> {
        let mut op = begin_master(set);
        op.stage(
            OutputPath::new(OutputDir::Keys, "k.key").expect("path"),
            encrypted_key_pem(serial(1)).as_bytes(),
        )
        .expect("stage");
        op
    }
    let probe = TestDrives::new(2);
    let set = new_ca(&probe);
    let op = staged(&set);
    fault::take_count();
    op.cancel(ts(6)).expect("clean cancel");
    let total = fault::take_count();
    assert!(total >= 6, "{total}");
    for allowed in 0..total {
        let drives = TestDrives::new(2);
        let set = new_ca(&drives);
        let op = staged(&set);
        fault::fail_after(allowed);
        assert!(op.cancel(ts(6)).is_err(), "fault {allowed}");
        fault::disarm();
        let context = format!("cancel fault {allowed}");
        recover_with_first_actions(&drives, 3, &context);
        assert_recovered(&drives, &context);
        assert!(
            open_all(&drives)
                .known_serials()
                .expect("serials")
                .contains(&serial(1))
        );
    }
}

#[test]
fn fr22_ac6_abandon_interrupted_at_every_drive_change_recovers() {
    // Covers: FR-22 AC6, FR-22 AC4, SEC-22
    let probe = TestDrives::new(2);
    drop(begin_master(&new_ca(&probe)));
    let set = open_all(&probe);
    fault::take_count();
    set.abandon_operation(OperationId(1), ts(6))
        .expect("clean abandon");
    let total = fault::take_count();
    assert!(total >= 4, "{total}");
    for allowed in 0..total {
        let drives = TestDrives::new(2);
        drop(begin_master(&new_ca(&drives)));
        let set = open_all(&drives);
        fault::fail_after(allowed);
        assert!(
            set.abandon_operation(OperationId(1), ts(6)).is_err(),
            "fault {allowed}"
        );
        fault::disarm();
        let context = format!("abandon fault {allowed}");
        recover_with_first_actions(&drives, 3, &context);
        assert_recovered(&drives, &context);
    }
}

/// An operation signed, staged and sealed, then interrupted before moving into place.
fn sealed_master(drives: &TestDrives) {
    let set = new_ca(drives);
    let mut op = begin_master(&set);
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
}

#[test]
fn fr22_ac6_finish_interrupted_at_every_drive_change_recovers() {
    // Covers: FR-22 AC6, FR-22 AC4, FR-22 AC3, SEC-22
    let probe = TestDrives::new(2);
    sealed_master(&probe);
    let set = open_all(&probe);
    fault::take_count();
    set.finish_operation(OperationId(1), 0, ts(6))
        .expect("clean finish");
    let total = fault::take_count();
    assert!(total >= 8, "{total}");
    for allowed in 0..total {
        let drives = TestDrives::new(2);
        sealed_master(&drives);
        let set = open_all(&drives);
        fault::fail_after(allowed);
        assert!(
            set.finish_operation(OperationId(1), 0, ts(6)).is_err(),
            "fault {allowed}"
        );
        fault::disarm();
        let context = format!("finish fault {allowed}");
        recover_with_first_actions(&drives, 3, &context);
        assert_recovered(&drives, &context);
        let record = open_all(&drives).issuance_record().expect("record");
        assert_eq!(
            record.get(serial(1)).expect("kept").source,
            RecordSource::RecordFile,
            "{context}"
        );
    }
}

/// A YubiKey setup whose PIN step is on both drives and whose next two steps reached
/// the primary only (as after two interrupted journal writes).
fn setup_ahead_on_primary(drives: &TestDrives) {
    let set = new_ca(drives);
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
    let rel = format!("{JOURNAL_DIR}/{}", op.id().stem());
    drop(op);
    for (step, kind) in [
        (3u32, YubikeySetupStep::PukChanged),
        (4, YubikeySetupStep::ManagementKeySet),
    ] {
        let entry = JournalEntry {
            format: JOURNAL_FORMAT,
            operation: OperationId(1),
            step,
            time: ts(5),
            event: JournalEvent::YubikeyStep {
                step: kind,
                device_serial: 77,
            },
        };
        set.drives()[0]
            .write_one_verified(
                &rel,
                &entry.file_name(),
                &to_json_file(&entry),
                WriteMode::CreateOnly,
            )
            .expect("write");
    }
}

#[test]
fn fr22_ac6_journal_sync_interrupted_at_every_drive_change_recovers() {
    // Covers: FR-22 AC6, FR-22 AC7, SEC-22
    let probe = TestDrives::new(2);
    setup_ahead_on_primary(&probe);
    let set = open_all(&probe);
    fault::take_count();
    set.sync_operation_journal(OperationId(1)).expect("sync");
    assert_eq!(fault::take_count(), 2);
    for allowed in 0..2 {
        let drives = TestDrives::new(2);
        setup_ahead_on_primary(&drives);
        let set = open_all(&drives);
        fault::fail_after(allowed);
        assert!(set.sync_operation_journal(OperationId(1)).is_err());
        fault::disarm();
        let set = open_all(&drives);
        let pending = only_pending(&set);
        assert!(pending.blocked_reason.is_none(), "{pending:?}");
        assert_eq!(
            pending.actions.first(),
            Some(&RecoveryAction::ResumeYubikeySetup {
                next_step: Some(YubikeySetupStep::KeyGenerated)
            }),
            "sync fault {allowed}"
        );
        set.sync_operation_journal(OperationId(1))
            .expect("sync again");
        let resumed = set.resume_operation(OperationId(1)).expect("resume");
        assert_eq!(resumed.completed_yubikey_steps().expect("steps").len(), 3);
    }
}
