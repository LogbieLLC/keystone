//! Helpers for the store's unit tests. Synthetic data only (TEST-11): every name carries
//! `KEYSTONE TEST`; "certificates" and "keys" are placeholder PEM text, never real keys.
#![forbid(unsafe_code)]

use std::path::Path;

use keystone_testkit::TestDrives;
use time::{Duration, OffsetDateTime};

use super::audit::{AuditDraft, AuditResult};
use super::drive::DriveSet;
use super::ids::OperationId;
use super::journal::{OperationKind, SignedObject};
use super::paths::{OutputDir, OutputPath};
use super::record::{CertificateRecord, RecordChange, RecordUpdate, SubjectName};
use crate::model::{CaLevel, Serial, Sha256Digest, Timestamp};

/// 2026-11-01T00:00:00Z plus `seconds`.
pub(crate) fn ts(seconds: i64) -> Timestamp {
    Timestamp::utc(
        OffsetDateTime::from_unix_timestamp(1_793_491_200).expect("epoch")
            + Duration::seconds(seconds),
    )
}

/// A deterministic positive serial.
pub(crate) fn serial(n: u8) -> Serial {
    let mut bytes = [0u8; 20];
    bytes[0] = 0x11;
    bytes[19] = n;
    Serial::from_bytes(bytes).expect("valid serial")
}

pub(crate) fn name(cn: &str) -> SubjectName {
    SubjectName {
        common_name: format!("KEYSTONE TEST {cn}"),
        organization: None,
        country: None,
    }
}

/// A record entry for a test certificate.
pub(crate) fn cert(serial_no: Serial, level: CaLevel, issuer: Serial) -> CertificateRecord {
    CertificateRecord {
        serial: serial_no,
        level,
        subject: name(&format!("{level:?} {serial_no}")),
        issuer_serial: issuer,
        issuer: name("issuer"),
        not_before: ts(0),
        not_after: ts(365 * 86_400),
        fingerprint: Sha256Digest([serial_no.as_bytes()[19]; 32]),
        name_constraints: level == CaLevel::SubIntermediate,
        permitted_dns: if level == CaLevel::SubIntermediate {
            vec!["starnet".to_string()]
        } else {
            Vec::new()
        },
        permitted_ip: Vec::new(),
        attestation_pem: (level == CaLevel::MainIntermediate).then(|| {
            "-----BEGIN CERTIFICATE-----\nKEYSTONE TEST attestation\n-----END CERTIFICATE-----\n"
                .to_string()
        }),
    }
}

/// Placeholder certificate PEM (not a real certificate).
pub(crate) fn cert_pem(serial_no: Serial) -> String {
    format!("-----BEGIN CERTIFICATE-----\nKEYSTONE TEST {serial_no}\n-----END CERTIFICATE-----\n")
}

/// Placeholder encrypted key PEM (not a real key).
pub(crate) fn encrypted_key_pem(serial_no: Serial) -> String {
    format!(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nKEYSTONE TEST {serial_no}\n-----END ENCRYPTED PRIVATE KEY-----\n"
    )
}

/// Creates a CA on all of `drives` (drive 0 primary, the rest backups).
pub(crate) fn new_ca(drives: &TestDrives) -> DriveSet {
    let backups: Vec<&Path> = drives.ca_drives()[1..]
        .iter()
        .map(|p| p.as_path())
        .collect();
    DriveSet::create(drives.ca_drive(0), &backups, ts(0)).expect("create CA")
}

/// Opens every CA drive of `drives`.
pub(crate) fn open_all(drives: &TestDrives) -> DriveSet {
    let roots: Vec<&Path> = drives.ca_drives().iter().map(|p| p.as_path()).collect();
    DriveSet::open(&roots).expect("open drives")
}

/// Opens only the given CA drives of `drives`.
pub(crate) fn open_some(drives: &TestDrives, indexes: &[usize]) -> DriveSet {
    let roots: Vec<&Path> = indexes.iter().map(|i| drives.ca_drive(*i)).collect();
    DriveSet::open(&roots).expect("open drives")
}

/// Runs one complete certificate-issuing operation: pending, signed, staged (certificate,
/// encrypted key, record update), committed, audited, completed.
pub(crate) fn issue(
    set: &DriveSet,
    kind: OperationKind,
    record: CertificateRecord,
    time: Timestamp,
) -> OperationId {
    let serial_no = record.serial;
    let mut op = set
        .begin_operation(kind, &record.subject.display(), &[serial_no], time)
        .expect("begin");
    op.record_signed(
        SignedObject::Certificate {
            record: Box::new(record.clone()),
            pem: cert_pem(serial_no),
        },
        time,
    )
    .expect("signed");
    let id = op.id();
    op.stage(
        OutputPath::new(OutputDir::Certs, &format!("{}.crt", serial_no.to_hex())).expect("path"),
        cert_pem(serial_no).as_bytes(),
    )
    .expect("stage cert");
    op.stage(
        OutputPath::new(OutputDir::Keys, &format!("{}.key", serial_no.to_hex())).expect("path"),
        encrypted_key_pem(serial_no).as_bytes(),
    )
    .expect("stage key");
    let update = RecordUpdate::new(
        id,
        vec![RecordChange::Issued {
            certificate: Box::new(record.clone()),
        }],
    );
    op.stage(update.output_path(), &update.to_bytes())
        .expect("stage record");
    op.seal_staging(time).expect("seal");
    op.commit().expect("commit");
    let mut draft = AuditDraft::new(kind.into(), record.subject.display(), AuditResult::Success);
    draft.serial = Some(serial_no);
    draft.fingerprint = Some(record.fingerprint);
    op.append_audit(&[draft], time).expect("audit");
    op.complete(time).expect("complete");
    id
}

/// Issues a master certificate with serial `n`.
pub(crate) fn issue_master(set: &DriveSet, n: u8, time: Timestamp) -> OperationId {
    issue(
        set,
        OperationKind::CreateMaster,
        cert(serial(n), CaLevel::Master, serial(n)),
        time,
    )
}

/// Copies a folder tree (as a drive image would), without following links.
pub(crate) fn copy_folder(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir");
    for entry in std::fs::read_dir(from).expect("list") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_folder(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

/// One CA whose drives hold two different histories, through the real store path: the
/// CA (master, serial 1) is created on drives 0 (primary) and 1 (backup), both are
/// copied to drives 2 and 3 (as if imaged, same identities), and then each pair is used
/// on its own: drives 0 and 1 issue serial 7, drives 2 and 3 issue serial 9. Drive 0
/// with drive 3 is then a primary and a backup of one CA whose histories diverge.
pub(crate) fn diverged_ca() -> TestDrives {
    let mut drives = TestDrives::new(2);
    issue_master(&new_ca(&drives), 1, ts(10));
    for index in 0..2 {
        let copy = drives.add_ca_drive();
        copy_folder(
            &drives.ca_drive(index).join(super::KEYSTONE_DIR),
            &copy.join(super::KEYSTONE_DIR),
        );
    }
    issue(
        &open_some(&drives, &[0, 1]),
        OperationKind::CreateSubIntermediate,
        cert(serial(7), CaLevel::SubIntermediate, serial(1)),
        ts(20),
    );
    issue(
        &open_some(&drives, &[2, 3]),
        OperationKind::CreateSubIntermediate,
        cert(serial(9), CaLevel::SubIntermediate, serial(1)),
        ts(21),
    );
    drives
}
