//! FR-17 AC3 end to end through the public API: a future-dated entry blocks signing, the
//! clock-correction baseline is recorded, and signing resumes. Synthetic data only
//! (TEST-11); files only in temporary directories (TEST-12).
#![forbid(unsafe_code)]

use keystone_core::build_info::build_date;
use keystone_core::clock::{
    Clock, ClockCorrection, ClockError, assess_for_log, confirm, future_dated_certificates,
};
use keystone_core::model::{CaLevel, Serial, Sha256Digest, Timestamp};
use keystone_core::store::{
    AuditAction, AuditDraft, AuditResult, CertificateRecord, DriveSet, OperationKind, OutputDir,
    OutputPath, RecordChange, RecordUpdate, SignedObject, SubjectName,
};
use keystone_testkit::{TEST_CN_MARKER, TestClock, TestDrives};
use time::Duration;

fn serial(n: u8) -> Serial {
    let mut bytes = [0u8; 20];
    bytes[0] = 0x22;
    bytes[19] = n;
    Serial::from_bytes(bytes).expect("serial")
}

fn whole(time: time::OffsetDateTime) -> Timestamp {
    Timestamp::utc(time.replace_nanosecond(0).expect("valid"))
}

/// Issues a self-signed test master with serial `n`, signed at `when`.
fn issue_master(set: &DriveSet, n: u8, when: Timestamp) {
    let record = CertificateRecord {
        serial: serial(n),
        level: CaLevel::Master,
        subject: SubjectName {
            common_name: format!("{TEST_CN_MARKER} master {n}"),
            organization: None,
            country: None,
        },
        issuer_serial: serial(n),
        issuer: SubjectName {
            common_name: format!("{TEST_CN_MARKER} master {n}"),
            organization: None,
            country: None,
        },
        not_before: when,
        not_after: Timestamp::utc(when.get() + Duration::days(365)),
        fingerprint: Sha256Digest([n; 32]),
        name_constraints: false,
        permitted_dns: Vec::new(),
        permitted_ip: Vec::new(),
        attestation_pem: None,
    };
    let pem =
        format!("-----BEGIN CERTIFICATE-----\n{TEST_CN_MARKER} {n}\n-----END CERTIFICATE-----\n");
    let key = format!(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n{TEST_CN_MARKER} {n}\n-----END ENCRYPTED PRIVATE KEY-----\n"
    );
    let mut op = set
        .begin_operation(
            OperationKind::CreateMaster,
            &record.subject.display(),
            &[serial(n)],
            when,
        )
        .expect("begin");
    op.record_signed(
        SignedObject::Certificate {
            record: Box::new(record.clone()),
            pem: pem.clone(),
        },
        when,
    )
    .expect("signed");
    let update = RecordUpdate::new(
        op.id(),
        vec![RecordChange::Issued {
            certificate: Box::new(record.clone()),
        }],
    );
    op.stage(
        OutputPath::new(OutputDir::Certs, &format!("master-{n}.crt")).expect("path"),
        pem.as_bytes(),
    )
    .expect("stage cert");
    op.stage(
        OutputPath::new(OutputDir::Keys, &format!("master-{n}.key")).expect("path"),
        key.as_bytes(),
    )
    .expect("stage key");
    op.stage(update.output_path(), &update.to_bytes())
        .expect("stage record");
    op.seal_staging(when).expect("seal");
    op.commit().expect("commit");
    let mut draft = AuditDraft::new(
        AuditAction::CreateMaster,
        record.subject.display(),
        AuditResult::Success,
    );
    draft.serial = Some(record.serial);
    draft.fingerprint = Some(record.fingerprint);
    op.append_audit(&[draft], when).expect("audit");
    op.complete(when).expect("complete");
}

#[test]
fn fr17_ac3_future_dated_entry_is_corrected_and_signing_resumes() {
    // Covers: FR-17 AC3, FR-17 AC2, FR-17 AC1, SEC-16
    let drives = TestDrives::new(2);
    let clock = TestClock::days_after_build(1);
    let set = DriveSet::create(
        drives.ca_drive(0),
        &[drives.ca_drive(1)],
        whole(clock.now()),
    )
    .expect("create CA");

    // The laptop clock was ten years ahead when the master was signed.
    let wrong = whole(clock.now() + Duration::days(3650));
    issue_master(&set, 1, wrong);

    // Back at the real time, signing is blocked: the clock is earlier than the newest entry.
    let log = set.audit_log().expect("log");
    let assessment = assess_for_log(clock.now(), log.entries());
    assert!(assessment.is_blocked());
    assert!(matches!(
        confirm(&assessment, true),
        Err(ClockError::Blocked(_))
    ));

    // The operator runs "Correct clock baseline" with the right current time.
    let correction = ClockCorrection::plan(log.entries(), clock.now(), build_date()).expect("plan");
    assert_eq!(correction.previous_newest(), wrong);
    let entry = correction.record(&set).expect("record");
    assert_eq!(entry.action, AuditAction::ClockCorrection);
    let after = set.audit_log().expect("log");
    assert_eq!(
        &after.entries()[..log.len()],
        log.entries(),
        "existing entries unchanged"
    );

    // Signing resumes.
    let assessment = assess_for_log(clock.now(), after.entries());
    assert!(!assessment.is_blocked(), "{assessment:?}");
    let confirmed = confirm(&assessment, false).expect("confirmed");

    // The certificate signed with the future date is listed for revoke and re-issue.
    let record = set.issuance_record().expect("record");
    let future = future_dated_certificates(&record, confirmed.get());
    assert_eq!(future.len(), 1);
    assert_eq!(future[0].certificate.serial, serial(1));

    // A new signing operation at the confirmed time succeeds.
    clock.advance(Duration::minutes(5));
    issue_master(&set, 2, whole(clock.now()));
    assert!(set.compare().expect("compare").signing_allowed());

    // The baseline keeps advancing: moving the clock back past the new entry is blocked.
    let log = set.audit_log().expect("log");
    assert!(assess_for_log(clock.now() - Duration::minutes(1), log.entries()).is_blocked());
}
