//! Tests for the hash-chained audit log (FR-14, SEC-09, SEC-08).
#![forbid(unsafe_code)]

use std::fs;

use keystone_testkit::TestDrives;
use proptest::prelude::*;

use super::*;
use crate::store::DriveComparison;
use crate::store::testutil::{issue_master, new_ca, open_all, serial, ts};

fn draft(n: u8) -> AuditDraft {
    let mut draft = AuditDraft::new(
        AuditAction::CreateSubIntermediate,
        format!("CN=KEYSTONE TEST sub {n}"),
        AuditResult::Success,
    );
    draft.serial = Some(serial(n));
    draft.fingerprint = Some(Sha256Digest([n; 32]));
    draft
}

/// A valid log of `count` entries.
fn log_of(count: u8) -> AuditLog {
    let drafts: Vec<AuditDraft> = (1..=count).map(draft).collect();
    let (bytes, _) = AuditLog::empty()
        .with_appended(&drafts, ts(60))
        .expect("append");
    parse_audit_log(&bytes).expect("valid")
}

fn lines(log: &AuditLog) -> Vec<String> {
    String::from_utf8(log.as_bytes().to_vec())
        .expect("utf8")
        .lines()
        .map(str::to_string)
        .collect()
}

fn join(lines: &[String]) -> Vec<u8> {
    lines
        .iter()
        .map(|l| format!("{l}\n"))
        .collect::<String>()
        .into_bytes()
}

fn first_bad(bytes: &[u8]) -> (u64, AuditProblem) {
    match parse_audit_log(bytes) {
        Err(ParseError::Audit { entry, problem }) => (entry, problem),
        other => panic!("expected an audit error, got {other:?}"),
    }
}

#[test]
fn fr14_ac1_every_operation_appends_an_entry() {
    // Covers: FR-14 AC1, SEC-09, SEC-10
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    let operation = issue_master(&set, 1, ts(100));
    let log = set.audit_log().expect("log");
    assert_eq!(log.len(), 1);
    let entry = &log.entries()[0];
    assert_eq!(entry.seq, 1);
    assert_eq!(entry.time, ts(100));
    assert_eq!(entry.operation, Some(operation));
    assert_eq!(entry.action, AuditAction::CreateMaster);
    assert!(entry.subject.contains("KEYSTONE TEST"));
    assert_eq!(entry.serial, Some(serial(1)));
    assert!(entry.fingerprint.is_some());
    assert_eq!(entry.result, AuditResult::Success);
    // The same bytes are on every drive.
    let primary = fs::read(drives.ca_drive(0).join("keystone/audit.log")).expect("read");
    let backup = fs::read(drives.ca_drive(1).join("keystone/audit.log")).expect("read");
    assert_eq!(primary, backup);
}

#[test]
fn fr14_ac2_each_entry_contains_the_hash_of_the_previous_entry() {
    // Covers: FR-14 AC2, SEC-09
    let log = log_of(4);
    let text = lines(&log);
    assert_eq!(log.entries()[0].prev, GENESIS_PREV);
    for index in 1..4 {
        assert_eq!(
            log.entries()[index].prev,
            sha256(text[index - 1].as_bytes())
        );
        assert_eq!(
            log.entry_hash(index as u64),
            Some(sha256(text[index - 1].as_bytes()))
        );
    }
    assert_eq!(log.head().seq, 4);
    assert_eq!(log.head().sha256, sha256(text[3].as_bytes()));
    // The canonical form is exactly the stored line.
    for (entry, line) in log.entries().iter().zip(&text) {
        assert_eq!(entry.canonical_bytes(), line.as_bytes());
    }
}

#[test]
fn fr14_ac3_a_changed_entry_is_named_as_the_first_bad_entry() {
    // Covers: FR-14 AC3, SEC-09
    let log = log_of(5);
    let mut text = lines(&log);
    text[2] = text[2].replace("sub 3", "sub X");
    let (entry, problem) = first_bad(&join(&text));
    assert_eq!(entry, 3);
    assert_eq!(problem, AuditProblem::HashMismatch { next_entry: 4 });
    let message = parse_audit_log(&join(&text)).expect_err("bad").to_string();
    assert!(message.contains("entry 3"), "{message}");
    // Changing the hash link stored in entry 4 changes entry 4, not entry 3: entry 3
    // still verifies, and entry 5's link no longer matches entry 4. Entry 4 is named.
    let mut text = lines(&log);
    let wrong = Sha256Digest([7; 32]).to_hex();
    let old = log.entries()[3].prev.to_hex();
    text[3] = text[3].replace(&old, &wrong);
    assert_eq!(first_bad(&join(&text)), (4, AuditProblem::LinkChanged));
    let message = parse_audit_log(&join(&text)).expect_err("bad").to_string();
    assert!(message.contains("entry 4"), "{message}");
}

#[test]
fn regression_an_edited_link_names_the_entry_that_holds_it() {
    // Covers: FR-14 AC3, SEC-09
    // Regression (review finding 16): editing the `prev` of entry n named the unchanged
    // entry n-1 as the first bad entry.
    let log = log_of(6);
    for n in 2..=5usize {
        let mut text = lines(&log);
        let old = log.entries()[n - 1].prev.to_hex();
        text[n - 1] = text[n - 1].replace(&old, &Sha256Digest([9; 32]).to_hex());
        assert_eq!(
            first_bad(&join(&text)),
            (n as u64, AuditProblem::LinkChanged),
            "link of entry {n}"
        );
        // A changed entry (not its link) is still named itself.
        let mut text = lines(&log);
        text[n - 2] = text[n - 2].replace("KEYSTONE TEST", "KEYSTONE TEST X");
        assert_eq!(
            first_bad(&join(&text)),
            (
                (n - 1) as u64,
                AuditProblem::HashMismatch { next_entry: n as u64 }
            ),
            "content of entry {}",
            n - 1
        );
    }
    // The last entry's link has no later entry to tell the two cases apart: the earlier
    // entry is named, since it may be the changed one (the cross-drive comparison and
    // the journal heads catch the rest).
    let mut text = lines(&log);
    let old = log.entries()[5].prev.to_hex();
    text[5] = text[5].replace(&old, &Sha256Digest([9; 32]).to_hex());
    assert_eq!(
        first_bad(&join(&text)),
        (5, AuditProblem::HashMismatch { next_entry: 6 })
    );
}

#[test]
fn fr14_ac3_truncation_is_detected() {
    // Covers: FR-14 AC3, SEC-09
    let log = log_of(4);
    let bytes = log.as_bytes();
    // Cut off in the middle of the last entry.
    let cut = &bytes[..bytes.len() - 10];
    assert_eq!(first_bad(cut), (4, AuditProblem::Truncated));
    // Entries removed from the start.
    let text = lines(&log);
    assert_eq!(
        first_bad(&join(&text[1..])),
        (
            1,
            AuditProblem::WrongSequence {
                expected: 1,
                found: 2
            }
        )
    );
    // An entry removed from the middle.
    let mut without_two = text.clone();
    without_two.remove(1);
    assert_eq!(
        first_bad(&join(&without_two)),
        (
            2,
            AuditProblem::WrongSequence {
                expected: 2,
                found: 3
            }
        )
    );
}

#[test]
fn fr14_ac3_whole_entries_cut_from_the_end_are_caught_by_the_journal_head() {
    // Covers: FR-14 AC3, FR-12 AC3, SEC-09
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    issue_master(&set, 1, ts(100));
    let path = drives.ca_drive(1).join("keystone/audit.log");
    fs::write(&path, b"").expect("truncate the backup's log");
    let set = open_all(&drives);
    match set.compare().expect("compare") {
        DriveComparison::Damaged { problems } => {
            assert!(
                problems.iter().any(|p| p.contains("audit entry 1")),
                "{problems:?}"
            );
        }
        other => panic!("expected damage, got {other:?}"),
    }
    // A changed last entry is caught the same way.
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    issue_master(&set, 1, ts(100));
    let path = drives.ca_drive(0).join("keystone/audit.log");
    let changed = fs::read_to_string(&path)
        .expect("read")
        .replace("Master", "Mister");
    fs::write(&path, changed).expect("write");
    assert!(
        !open_all(&drives)
            .compare()
            .expect("compare")
            .signing_allowed()
    );
}

#[test]
fn fr14_ac3_reordered_entries_are_detected() {
    // Covers: FR-14 AC3, SEC-09
    let log = log_of(4);
    let mut text = lines(&log);
    text.swap(1, 2);
    assert_eq!(
        first_bad(&join(&text)),
        (
            2,
            AuditProblem::WrongSequence {
                expected: 2,
                found: 3
            }
        )
    );
    // Renumbering to hide the swap breaks the hash chain instead.
    let mut text = lines(&log);
    text.swap(1, 2);
    text[1] = text[1].replacen("\"seq\":3", "\"seq\":2", 1);
    text[2] = text[2].replacen("\"seq\":2", "\"seq\":3", 1);
    let (entry, problem) = first_bad(&join(&text));
    assert!(entry <= 2, "{entry} {problem}");
}

#[test]
fn sec08_audit_parser_is_strict() {
    // Covers: SEC-08
    let log = log_of(2);
    let text = lines(&log);
    // Not canonical: extra whitespace.
    let mut spaced = text.clone();
    spaced[1] = spaced[1].replacen("{\"seq\":2", "{ \"seq\":2", 1);
    assert_eq!(first_bad(&join(&spaced)), (2, AuditProblem::NotCanonical));
    // Unknown field.
    let mut extra = text.clone();
    extra[0] = extra[0].replacen("{\"seq\":1", "{\"x\":1,\"seq\":1", 1);
    assert!(matches!(
        first_bad(&join(&extra)),
        (1, AuditProblem::Invalid(_))
    ));
    // Empty line, junk, CRLF.
    let mut empty = text.clone();
    empty.insert(1, String::new());
    assert_eq!(first_bad(&join(&empty)), (2, AuditProblem::Empty));
    assert!(matches!(
        first_bad(b"not json\n"),
        (1, AuditProblem::Invalid(_))
    ));
    let crlf = join(&text)
        .iter()
        .flat_map(|b| {
            if *b == b'\n' {
                vec![b'\r', b'\n']
            } else {
                vec![*b]
            }
        })
        .collect::<Vec<u8>>();
    assert_eq!(first_bad(&crlf).0, 1);
    // Non-UTC time.
    let mut local = text.clone();
    local[0] = local[0].replacen("T00:01:00Z", "T01:01:00+01:00", 1);
    assert!(parse_audit_log(&join(&local)).is_err());
    // Size limits.
    let long_line = format!("{}\n", "x".repeat(MAX_AUDIT_ENTRY_BYTES + 1));
    assert_eq!(
        first_bad(long_line.as_bytes()),
        (
            1,
            AuditProblem::TooLong {
                limit: MAX_AUDIT_ENTRY_BYTES
            }
        )
    );
    assert!(matches!(
        parse_audit_log(&vec![b'\n'; MAX_AUDIT_LOG_BYTES + 1]),
        Err(ParseError::TooLarge { .. })
    ));
    assert!(parse_audit_log(b"").expect("empty log is valid").is_empty());
}

#[test]
fn clock_correction_details_round_trip() {
    // Covers: FR-17 AC3
    let mut correction = AuditDraft::new(AuditAction::ClockCorrection, "", AuditResult::Success);
    correction.details = Some(AuditDetails {
        clock_correction: Some(ClockCorrectionDetails {
            previous_newest: ts(10_000_000),
            confirmed: ts(500),
        }),
        ..AuditDetails::default()
    });
    let (bytes, added) = log_of(1)
        .with_appended(&[correction], ts(500))
        .expect("append");
    let log = parse_audit_log(&bytes).expect("valid");
    assert_eq!(log.entries()[1], added[0]);
    assert_eq!(log.newest_time(), Some(ts(500)));
    // An empty details object is not canonical.
    let mut empty = AuditDraft::new(AuditAction::Export, "", AuditResult::Success);
    empty.details = Some(AuditDetails::default());
    let (bytes, added) = AuditLog::empty()
        .with_appended(&[empty], ts(1))
        .expect("append");
    assert_eq!(added[0].details, None);
    assert!(parse_audit_log(&bytes).is_ok());
    let forced = String::from_utf8(bytes)
        .expect("utf8")
        .replace("\"details\":null", "\"details\":{}");
    assert!(parse_audit_log(forced.as_bytes()).is_err());
}

#[test]
fn appending_needs_identical_logs_on_every_drive() {
    // Covers: FR-12 AC1, FR-14 AC1
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    set.append_audit(&[draft(1)], ts(1)).expect("append");
    fs::write(drives.ca_drive(1).join("keystone/audit.log"), b"").expect("reset backup");
    let set = open_all(&drives);
    assert!(matches!(
        set.append_audit(&[draft(2)], ts(2)),
        Err(StoreError::OutOfSync(_))
    ));
}

#[test]
fn audit_log_accessors_and_append_limits() {
    // Covers: FR-14 AC2, SEC-08
    let empty = AuditLog::empty();
    assert!(empty.is_empty());
    assert_eq!(empty.head().seq, 0);
    assert_eq!(empty.head().sha256, GENESIS_PREV);
    assert!(empty.prefix_bytes(3).is_empty());
    let log = log_of(3);
    assert_eq!(log.len(), 3);
    assert_eq!(log.entry_hash(0), None);
    assert_eq!(log.entry_hash(4), None);
    assert_eq!(
        parse_audit_log(log.prefix_bytes(2)).expect("valid").len(),
        2
    );
    assert_eq!(log.prefix_bytes(9), log.as_bytes());
    assert_eq!(log.common_prefix_len(&log_of(2)), 2);
    // Over-long text is refused before anything is written.
    let long = AuditDraft::new(
        AuditAction::Export,
        "x".repeat(MAX_AUDIT_TEXT + 1),
        AuditResult::Success,
    );
    assert!(log.with_appended(&[long], ts(1)).is_err());
    let mut note = AuditDraft::new(AuditAction::Export, "", AuditResult::Success);
    note.details = Some(AuditDetails {
        note: Some("y".repeat(MAX_AUDIT_TEXT + 1)),
        ..AuditDetails::default()
    });
    assert!(log.with_appended(&[note], ts(1)).is_err());
}

#[test]
fn fr14_ac3_a_damaged_drive_log_is_reported_with_its_path() {
    // Covers: FR-14 AC3, SEC-09
    let drives = TestDrives::new(2);
    let set = new_ca(&drives);
    set.append_audit(&[draft(1), draft(2)], ts(1))
        .expect("append");
    let path = drives.ca_drive(0).join("keystone/audit.log");
    let changed = fs::read_to_string(&path)
        .expect("read")
        .replacen("sub 1", "sub 9", 1);
    fs::write(&path, changed).expect("write");
    let set = open_all(&drives);
    match set.drives()[0].audit_log() {
        Err(StoreError::Parse {
            source: ParseError::Audit { entry: 1, .. },
            path: reported,
        }) => assert_eq!(reported, path),
        other => panic!("expected entry 1 to be named, got {other:?}"),
    }
    assert!(set.audit_log().is_err());
    match set.compare().expect("compare") {
        DriveComparison::Damaged { problems } => {
            assert!(problems[0].contains("entry 1"), "{problems:?}");
        }
        other => panic!("expected damage, got {other:?}"),
    }
}

proptest! {
    #[test]
    fn sec08_audit_parser_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        // Covers: SEC-08
        let _ = parse_audit_log(&bytes);
    }

    #[test]
    fn sec08_audit_parser_never_panics_on_mutated_logs(position in 0usize..2000, value in any::<u8>()) {
        // Covers: SEC-08, FR-14 AC3
        let mut bytes = log_of(3).as_bytes().to_vec();
        let index = position % bytes.len();
        let changed = bytes[index] != value;
        bytes[index] = value;
        let result = parse_audit_log(&bytes);
        if changed {
            // Any single-byte change of the first two entries is detected.
            let second_end = log_of(3).prefix_bytes(2).len();
            if index < second_end {
                prop_assert!(result.is_err());
            }
        }
    }
}
