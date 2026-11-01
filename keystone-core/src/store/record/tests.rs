//! Tests for the issuance record (FR-11, FR-15, FR-22 AC3, FR-10 AC2, SEC-08).
#![forbid(unsafe_code)]

use keystone_testkit::TestDrives;
use proptest::prelude::*;

use super::*;
use crate::store::journal::OperationKind;
use crate::store::testutil::{cert, cert_pem, issue, issue_master, new_ca, serial, ts};

fn issued(op: u64, certificate: CertificateRecord) -> RecordUpdate {
    RecordUpdate::new(
        OperationId(op),
        vec![RecordChange::Issued {
            certificate: Box::new(certificate),
        }],
    )
}

/// master 1 -> main 2 -> subs 3, 4; master 1 -> main 5.
fn hierarchy() -> Vec<RecordUpdate> {
    vec![
        issued(1, cert(serial(1), CaLevel::Master, serial(1))),
        issued(2, cert(serial(2), CaLevel::MainIntermediate, serial(1))),
        issued(3, cert(serial(3), CaLevel::SubIntermediate, serial(2))),
        issued(4, cert(serial(4), CaLevel::SubIntermediate, serial(2))),
        issued(5, cert(serial(5), CaLevel::MainIntermediate, serial(1))),
    ]
}

#[test]
fn fr11_ac1_every_signed_certificate_is_recorded_with_all_fields() {
    // Covers: FR-11 AC1, SEC-10, FR-21 AC6, FR-07 AC5
    let record = IssuanceRecord::from_updates(&hierarchy()).expect("record");
    assert_eq!(record.certificates().len(), 5);
    let sub = record.get(serial(3)).expect("sub");
    assert_eq!(sub.certificate.serial, serial(3));
    assert!(
        sub.certificate
            .subject
            .common_name
            .contains("KEYSTONE TEST")
    );
    assert_eq!(sub.certificate.issuer_serial, serial(2));
    assert!(sub.certificate.not_before < sub.certificate.not_after);
    assert_eq!(sub.certificate.permitted_dns, vec!["starnet".to_string()]);
    assert_eq!(sub.status, CertStatus::Valid);
    assert_eq!(sub.operation, OperationId(3));
    assert!(
        record
            .get(serial(2))
            .expect("main")
            .certificate
            .attestation_pem
            .is_some()
    );
    // Revocation date and reason are recorded.
    let mut record = record;
    record
        .apply(&RecordUpdate::new(
            OperationId(6),
            vec![RecordChange::Revoked {
                serial: serial(3),
                date: ts(100),
                reason: RevocationReason::KeyCompromise,
            }],
        ))
        .expect("revoke");
    assert_eq!(
        record.get(serial(3)).expect("sub").status,
        CertStatus::Revoked {
            date: ts(100),
            reason: RevocationReason::KeyCompromise
        }
    );
}

#[test]
fn fr11_ac2_filter_by_issuer_and_status() {
    // Covers: FR-11 AC2, FR-15 AC1
    let mut updates = hierarchy();
    updates.push(RecordUpdate::new(
        OperationId(6),
        vec![
            RecordChange::Revoked {
                serial: serial(2),
                date: ts(100),
                reason: RevocationReason::CaCompromise,
            },
            RecordChange::RevokedByAncestor {
                serial: serial(3),
                ancestor: serial(2),
                date: ts(100),
            },
        ],
    ));
    let record = IssuanceRecord::from_updates(&updates).expect("record");
    let now = ts(200).get();
    let by_main = record.filter(Some(serial(2)), None, now);
    assert_eq!(by_main.len(), 2);
    let revoked_by_ancestor = record.filter(None, Some(StatusFilter::RevokedByAncestor), now);
    assert_eq!(revoked_by_ancestor.len(), 1);
    assert_eq!(revoked_by_ancestor[0].certificate.serial, serial(3));
    let valid_under_main = record.filter(Some(serial(2)), Some(StatusFilter::Valid), now);
    assert_eq!(valid_under_main.len(), 1);
    assert_eq!(valid_under_main[0].certificate.serial, serial(4));
    assert_eq!(
        record.filter(None, Some(StatusFilter::Revoked), now).len(),
        1
    );
    // After not_after, unrevoked certificates show as expired.
    let later = ts(400 * 86_400).get();
    let expired = record.filter(None, Some(StatusFilter::Expired), later);
    assert_eq!(expired.len(), 3);
    assert_eq!(record.children_of(serial(1)).len(), 2);
}

#[test]
fn inconsistent_updates_are_rejected() {
    // Covers: FR-10 AC2, SEC-08
    let mut twice = hierarchy();
    twice.push(issued(
        6,
        cert(serial(3), CaLevel::SubIntermediate, serial(2)),
    ));
    assert!(IssuanceRecord::from_updates(&twice).is_err());
    let orphan = vec![issued(
        1,
        cert(serial(3), CaLevel::SubIntermediate, serial(2)),
    )];
    assert!(IssuanceRecord::from_updates(&orphan).is_err());
    let mut unknown = hierarchy();
    unknown.push(RecordUpdate::new(
        OperationId(6),
        vec![RecordChange::Revoked {
            serial: serial(9),
            date: ts(1),
            reason: RevocationReason::Unspecified,
        }],
    ));
    assert!(IssuanceRecord::from_updates(&unknown).is_err());
    // "Revoked by ancestor" needs a revoked ancestor.
    let mut not_revoked = hierarchy();
    not_revoked.push(RecordUpdate::new(
        OperationId(6),
        vec![RecordChange::RevokedByAncestor {
            serial: serial(3),
            ancestor: serial(2),
            date: ts(1),
        }],
    ));
    assert!(IssuanceRecord::from_updates(&not_revoked).is_err());
    let mut wrong_branch = hierarchy();
    wrong_branch.push(RecordUpdate::new(
        OperationId(6),
        vec![
            RecordChange::Revoked {
                serial: serial(5),
                date: ts(1),
                reason: RevocationReason::Superseded,
            },
            RecordChange::RevokedByAncestor {
                serial: serial(3),
                ancestor: serial(5),
                date: ts(1),
            },
        ],
    ));
    assert!(IssuanceRecord::from_updates(&wrong_branch).is_err());
}

#[test]
fn sec08_record_parser_is_strict() {
    // Covers: SEC-08
    let good = String::from_utf8(hierarchy()[2].to_bytes()).expect("utf8");
    assert!(parse_record(good.as_bytes()).is_ok());
    for bad in [
        good.replacen("\"format\": 1", "\"format\": 9", 1),
        good.replacen("\"serial\"", "\"unknown\": 1, \"serial\"", 1),
        good.replacen("sub_intermediate", "leaf", 1),
        good.replacen(
            "\"name_constraints\": true",
            "\"name_constraints\": false",
            1,
        ),
    ] {
        if bad != good {
            assert!(parse_record(bad.as_bytes()).is_err(), "{bad}");
        }
    }
    let empty_cn = good.replacen(
        &format!(
            "\"common_name\": \"KEYSTONE TEST SubIntermediate {}\"",
            serial(3)
        ),
        "\"common_name\": \"\"",
        1,
    );
    assert_ne!(empty_cn, good);
    assert!(parse_record(empty_cn.as_bytes()).is_err());
    // A main intermediate without its attestation, a master that is not self-signed.
    let mut main = cert(serial(2), CaLevel::MainIntermediate, serial(1));
    main.attestation_pem = None;
    assert!(parse_record(&issued(2, main).to_bytes()).is_err());
    assert!(
        parse_record(&issued(1, cert(serial(1), CaLevel::Master, serial(2))).to_bytes()).is_err()
    );
    assert!(matches!(
        parse_record(&vec![b' '; MAX_RECORD_BYTES + 1]),
        Err(ParseError::TooLarge { .. })
    ));
}

#[test]
fn fr22_ac3_a_signed_certificate_is_never_dropped() {
    // Covers: FR-22 AC3, FR-11 AC1
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    issue_master(&set, 1, ts(10));
    // An operation signs a certificate and is then interrupted before its record update.
    let main = cert(serial(2), CaLevel::MainIntermediate, serial(1));
    let mut op = set
        .begin_operation(OperationKind::SetupYubikey, "main", &[serial(2)], ts(20))
        .expect("begin");
    op.record_signed(
        crate::store::journal::SignedObject::Certificate {
            record: Box::new(main.clone()),
            pem: cert_pem(serial(2)),
        },
        ts(20),
    )
    .expect("signed");
    drop(op);
    let record = set.issuance_record().expect("record");
    let entry = record.get(serial(2)).expect("still recorded");
    assert_eq!(entry.source, RecordSource::JournalOnly);
    assert_eq!(entry.certificate, main);
    assert_eq!(
        record.get(serial(1)).expect("master").source,
        RecordSource::RecordFile
    );
}

#[test]
fn fr10_ac2_known_serials_cover_records_journals_and_every_drive() {
    // Covers: FR-10 AC2, FR-16 AC1
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    issue_master(&set, 1, ts(10));
    // A cancelled operation keeps its reserved serial.
    let op = set
        .begin_operation(
            OperationKind::CreateSubIntermediate,
            "sub",
            &[serial(7)],
            ts(20),
        )
        .expect("begin");
    op.cancel(ts(21)).expect("cancel");
    let known = set.known_serials().expect("serials");
    assert!(known.contains(&serial(1)));
    assert!(known.contains(&serial(7)));
    // Reusing either serial is refused before signing.
    for reused in [serial(1), serial(7)] {
        assert!(matches!(
            set.begin_operation(OperationKind::CreateSubIntermediate, "sub", &[reused], ts(30)),
            Err(StoreError::SerialAlreadyUsed(s)) if s == reused
        ));
    }
    // A serial seen only on one drive (a divergent history) still counts.
    let other = TestDrives::new(2);
    let other_set = new_ca(&other);
    issue(
        &other_set,
        OperationKind::CreateMaster,
        cert(serial(9), CaLevel::Master, serial(9)),
        ts(5),
    );
    let mixed = vec![
        CaDrive::open(drives.ca_drive(0)).expect("open"),
        CaDrive::open(other.ca_drive(1)).expect("open"),
    ];
    let all = known_serials(&mixed).expect("serials");
    assert!(all.contains(&serial(9)) && all.contains(&serial(7)));
}

proptest! {
    #[test]
    fn sec08_record_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        // Covers: SEC-08
        let _ = parse_record(&bytes);
    }
}
