//! Tests for journal entries and per-drive journal reading (FR-22, SEC-08).
#![forbid(unsafe_code)]

use std::fs;

use keystone_testkit::TestDrives;
use proptest::prelude::*;

use super::*;
use crate::store::drive::to_json_file;
use crate::store::testutil::{issue_master, new_ca, open_all, serial, ts};

fn pending(op: u64) -> JournalEntry {
    JournalEntry {
        format: JOURNAL_FORMAT,
        operation: OperationId(op),
        step: 1,
        time: ts(0),
        event: JournalEvent::Pending {
            kind: OperationKind::CreateMaster,
            subject: "CN=KEYSTONE TEST master".to_string(),
            planned_serials: vec![serial(1)],
        },
    }
}

#[test]
fn fr22_ac1_pending_entry_round_trips_and_names_its_file() {
    // Covers: FR-22 AC1
    let entry = pending(7);
    assert_eq!(entry.file_name(), "001-pending.json");
    let bytes = to_json_file(&entry);
    assert_eq!(parse_journal_entry(&bytes).expect("valid"), entry);
}

#[test]
fn sec08_journal_parser_rejects_bad_entries() {
    // Covers: SEC-08
    let good = String::from_utf8(to_json_file(&pending(1))).expect("utf8");
    let cases = [
        good.replacen("\"format\": 1", "\"format\": 2", 1),
        good.replacen("\"operation\": 1", "\"operation\": 0", 1),
        good.replacen("\"step\": 1", "\"step\": 2", 1),
        good.replacen("\"step\": 1", "\"step\": 1000", 1),
        good.replacen("{", "{\"unknown\": true,", 1),
        good.replacen("create_master", "launch_rockets", 1),
        good.replacen("\"T00:00:00Z\"", "\"T00:00:00.5Z\"", 1),
        good.replacen("2026-11-01T00:00:00Z", "2026-11-01T00:00:00.5Z", 1),
        good.replacen(&serial(1).to_hex(), "zz", 1),
        "[]".to_string(),
        String::new(),
    ];
    for (index, case) in cases.iter().enumerate() {
        if *case != good {
            assert!(
                parse_journal_entry(case.as_bytes()).is_err(),
                "case {index}: {case}"
            );
        }
    }
    // A duplicate planned serial.
    let mut dup = pending(1);
    if let JournalEvent::Pending {
        planned_serials, ..
    } = &mut dup.event
    {
        planned_serials.push(serial(1));
    }
    assert!(parse_journal_entry(&to_json_file(&dup)).is_err());
    assert!(matches!(
        parse_journal_entry(&vec![b' '; MAX_JOURNAL_ENTRY_BYTES + 1]),
        Err(ParseError::TooLarge { .. })
    ));
}

#[test]
fn fr22_ac7_yubikey_steps_hold_no_secret() {
    // Covers: FR-22 AC7
    let entry = JournalEntry {
        format: JOURNAL_FORMAT,
        operation: OperationId(2),
        step: 2,
        time: ts(0),
        event: JournalEvent::YubikeyStep {
            step: YubikeySetupStep::PinChanged,
            device_serial: 12_345_678,
        },
    };
    let text = String::from_utf8(to_json_file(&entry)).expect("utf8");
    assert_eq!(entry.file_name(), "002-yubikey-step.json");
    // The only fields are the step and the device serial: no PIN, PUK or key.
    let value: serde_json::Value = serde_json::from_str(&text).expect("json");
    let step = &value["event"]["yubikey_step"];
    let keys: Vec<&String> = step.as_object().expect("object").keys().collect();
    assert_eq!(keys, vec!["device_serial", "step"]);
    // A smuggled secret field is rejected.
    let smuggled = text.replacen(
        "\"device_serial\"",
        "\"pin\": \"123456\", \"device_serial\"",
        1,
    );
    assert!(parse_journal_entry(smuggled.as_bytes()).is_err());
}

#[test]
fn journal_order_rules_are_enforced() {
    let entry = |step: u32, event: JournalEvent| JournalEntry {
        format: JOURNAL_FORMAT,
        operation: OperationId(1),
        step,
        time: ts(0),
        event,
    };
    let audit = AuditHead {
        seq: 1,
        sha256: Sha256Digest([1; 32]),
    };
    let build = |entries: Vec<JournalEntry>| {
        OperationJournal::from_entries(
            OperationId(1),
            entries.into_iter().map(|e| (e, Vec::new())).collect(),
        )
    };
    let completed = |step| {
        entry(
            step,
            JournalEvent::Completed {
                outputs: Vec::new(),
                audit,
            },
        )
    };
    let cancelled = |step| entry(step, JournalEvent::Cancelled { audit });
    assert!(build(vec![pending(1), completed(2)]).is_ok());
    // Nothing after the final entry.
    assert!(build(vec![pending(1), cancelled(2), completed(3)]).is_err());
    // Steps must be consecutive.
    assert!(build(vec![pending(1), completed(3)]).is_err());
    // YubiKey steps in order.
    let yk = |step, s| {
        entry(
            step,
            JournalEvent::YubikeyStep {
                step: s,
                device_serial: 1,
            },
        )
    };
    assert!(
        build(vec![
            pending(1),
            yk(2, YubikeySetupStep::PinChanged),
            yk(3, YubikeySetupStep::PukChanged)
        ])
        .is_ok()
    );
    assert!(
        build(vec![
            pending(1),
            yk(2, YubikeySetupStep::PukChanged),
            yk(3, YubikeySetupStep::PinChanged)
        ])
        .is_err()
    );
    let journal = build(vec![pending(1), yk(2, YubikeySetupStep::PinChanged)]).expect("ok");
    assert_eq!(journal.state(), OperationState::Pending);
    assert!(journal.has_persistent_change());
    assert_eq!(journal.planned_serials(), &[serial(1)]);
}

#[test]
fn drive_journal_is_read_and_checked() {
    // Covers: FR-22 AC1, FR-22 AC2, SEC-08
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let op = issue_master(&set, 1, ts(10));
    let journal = set.drives()[0].journal().expect("journal");
    let this = &journal[&op];
    assert_eq!(this.state(), OperationState::Completed);
    let names: Vec<String> = this.entries().iter().map(JournalEntry::file_name).collect();
    assert_eq!(
        names,
        vec![
            "001-pending.json",
            "002-signed.json",
            "003-staged.json",
            "004-completed.json"
        ]
    );
    assert_eq!(this.completed_outputs().expect("outputs").len(), 3);
    assert_eq!(this.audit_head().expect("head").seq, 1);
    // A stray file in the journal is an error, never skipped silently.
    let folder = drives.ca_drive(0).join("keystone/journal").join(op.stem());
    fs::write(folder.join("005-notes.json"), b"{}").expect("write");
    assert!(open_all(&drives).drives()[0].journal().is_err());
    fs::remove_file(folder.join("005-notes.json")).expect("rm");
    // A renamed entry (name and content differ) is an error.
    fs::rename(
        folder.join("002-signed.json"),
        folder.join("002-staged.json"),
    )
    .expect("mv");
    assert!(open_all(&drives).drives()[0].journal().is_err());
}

#[test]
fn journal_staging_rules_are_enforced() {
    // Covers: FR-22 AC2, FR-22 AC3, SEC-08
    let entry = |step: u32, event: JournalEvent| JournalEntry {
        format: JOURNAL_FORMAT,
        operation: OperationId(1),
        step,
        time: ts(0),
        event,
    };
    let output = |name: &str| OutputFile {
        path: OutputPath::parse(&format!("certs/{name}")).expect("path"),
        sha256: Sha256Digest([1; 32]),
        size: 1,
    };
    let audit = AuditHead {
        seq: 1,
        sha256: Sha256Digest([1; 32]),
    };
    let staged = |step, names: &[&str]| {
        entry(
            step,
            JournalEvent::Staged {
                outputs: names.iter().map(|n| output(n)).collect(),
            },
        )
    };
    let completed = |step, names: &[&str]| {
        entry(
            step,
            JournalEvent::Completed {
                outputs: names.iter().map(|n| output(n)).collect(),
                audit,
            },
        )
    };
    let signed = |step| {
        entry(
            step,
            JournalEvent::Signed {
                object: SignedObject::Crl(Box::new(SignedCrl {
                    issuer_serial: serial(1),
                    crl_number: 1,
                    this_update: ts(0),
                    next_update: ts(86_400),
                    sha256: Sha256Digest([2; 32]),
                    pem: "-----BEGIN X509 CRL-----\nKEYSTONE TEST\n-----END X509 CRL-----\n".into(),
                })),
            },
        )
    };
    let build = |entries: Vec<JournalEntry>| {
        OperationJournal::from_entries(
            OperationId(1),
            entries.into_iter().map(|e| (e, Vec::new())).collect(),
        )
    };
    let ok = build(vec![
        pending(1),
        signed(2),
        staged(3, &["a"]),
        completed(4, &["a"]),
    ])
    .expect("valid");
    assert_eq!(ok.staged_outputs().map(<[OutputFile]>::len), Some(1));
    assert_eq!(ok.signed().count(), 1);
    assert!(build(vec![pending(1), staged(2, &["a"]), staged(3, &["a"])]).is_err());
    assert!(build(vec![pending(1), staged(2, &["a"]), signed(3)]).is_err());
    assert!(build(vec![pending(1), staged(2, &["a"]), completed(3, &["b"])]).is_err());
    assert!(build(vec![pending(1), completed(2, &["a"])]).is_err());
    assert!(build(Vec::new()).is_err());
    // A signed CRL must end after it starts.
    let mut backwards = signed(2);
    if let JournalEvent::Signed {
        object: SignedObject::Crl(crl),
    } = &mut backwards.event
    {
        crl.next_update = crl.this_update;
    }
    assert!(parse_journal_entry(&to_json_file(&backwards)).is_err());
    assert!(parse_journal_entry(&to_json_file(&signed(2))).is_ok());
    // File names.
    assert_eq!(parse_entry_name("012-staged.json"), Some((12, "staged")));
    for bad in [
        "12-staged.json",
        "abc-staged.json",
        "012staged.json",
        "012-staged.txt",
    ] {
        assert_eq!(parse_entry_name(bad), None, "{bad}");
    }
}

#[test]
fn unexpected_journal_folders_are_errors() {
    // Covers: SEC-08
    let drives = TestDrives::new(2);
    new_ca(&drives);
    fs::create_dir(drives.ca_drive(0).join("keystone/journal/notes")).expect("mkdir");
    assert!(open_all(&drives).drives()[0].journal().is_err());
}

proptest! {
    #[test]
    fn sec08_journal_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        // Covers: SEC-08
        let _ = parse_journal_entry(&bytes);
    }

    #[test]
    fn sec08_journal_parser_never_panics_on_json_like_text(text in "[{}\\[\\]\":,a-z0-9 _-]{0,512}") {
        // Covers: SEC-08
        let _ = parse_journal_entry(text.as_bytes());
    }
}
