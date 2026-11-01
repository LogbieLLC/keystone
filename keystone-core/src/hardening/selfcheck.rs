//! SEC-19: compare the running binary's SHA-256 with the value recorded at install.
//!
//! This only detects corruption or an accidental change: a deliberately modified binary
//! could skip its own check. The real authenticity check is the operator's `sha256sum`
//! before install, against the value on paper from the two matching builds (SEC-02).
//! A mismatch is therefore a clear *warning* result, not an error that stops Keystone.
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::HardeningError;
use crate::crypto::hash::Sha256Stream;
use crate::model::Sha256Digest;
use crate::store::DriveSet;

/// The running program.
pub const SELF_EXE: &str = "/proc/self/exe";

/// Result of the self-check (SEC-19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfCheck {
    /// Every drive that records a value records this binary's SHA-256.
    Match,
    /// No drive records a value yet (first run after install).
    NotRecorded,
    /// At least one drive records a different value.
    Mismatch {
        /// SHA-256 of the running binary.
        actual: Sha256Digest,
        /// Drives (labels) and the different values they record.
        recorded: Vec<(String, Sha256Digest)>,
    },
}

impl SelfCheck {
    /// The warning to show, if any.
    pub fn warning(&self) -> Option<String> {
        match self {
            SelfCheck::Mismatch { actual, recorded } => Some(format!(
                "Warning: this Keystone program's SHA-256 ({}) differs from the value recorded at install ({}). The program file may be damaged or changed. This check only detects accidental damage: check the program with sha256sum against the value written on paper before trusting it.",
                actual.to_hex(),
                recorded
                    .iter()
                    .map(|(drive, digest)| format!("{} on {drive}", digest.to_hex()))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            SelfCheck::Match | SelfCheck::NotRecorded => None,
        }
    }
}

/// SHA-256 of the file at `path` (streamed).
pub fn file_sha256(path: &Path) -> Result<Sha256Digest, HardeningError> {
    let unreadable = |e: std::io::Error| HardeningError::BinaryUnreadable {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
    let mut file = File::open(path).map_err(unreadable)?;
    let mut hash = Sha256Stream::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = file.read(&mut buffer).map_err(unreadable)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hash.finish())
}

/// Compares `actual` with the values recorded on each drive (`None`: nothing recorded).
pub fn compare_binary_hash(
    actual: Sha256Digest,
    recorded: &[(String, Option<Sha256Digest>)],
) -> SelfCheck {
    let different: Vec<(String, Sha256Digest)> = recorded
        .iter()
        .filter_map(|(drive, digest)| digest.filter(|d| *d != actual).map(|d| (drive.clone(), d)))
        .collect();
    if !different.is_empty() {
        SelfCheck::Mismatch {
            actual,
            recorded: different,
        }
    } else if recorded.iter().all(|(_, digest)| digest.is_none()) {
        SelfCheck::NotRecorded
    } else {
        SelfCheck::Match
    }
}

/// SEC-19 at start: hashes `/proc/self/exe` and compares it with `binary.sha256` on the
/// drives.
pub fn check_running_binary(drives: &DriveSet) -> Result<SelfCheck, HardeningError> {
    let actual = file_sha256(Path::new(SELF_EXE))?;
    let recorded = drives
        .binary_hashes()
        .map_err(|e| HardeningError::BinaryUnreadable {
            path: SELF_EXE.into(),
            reason: e.to_string(),
        })?;
    Ok(compare_binary_hash(actual, &recorded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::sha256;
    use crate::store::testutil::{new_ca, open_all, ts};
    use keystone_testkit::TestDrives;

    #[test]
    fn sec19_running_binary_matches_its_recorded_hash() {
        // Covers: SEC-19
        let drives = TestDrives::new(2);
        let set = new_ca(&drives);
        assert_eq!(
            check_running_binary(&set).expect("check"),
            SelfCheck::NotRecorded
        );
        let actual = file_sha256(Path::new(SELF_EXE)).expect("hash");
        assert_eq!(actual, sha256(&std::fs::read(SELF_EXE).expect("read exe")));
        set.record_binary_hash(actual, ts(5))
            .expect("record at install");
        let set = open_all(&drives);
        let result = check_running_binary(&set).expect("check");
        assert_eq!(result, SelfCheck::Match);
        assert!(result.warning().is_none());
        // Recording is audited.
        let log = set.audit_log().expect("log");
        assert_eq!(
            log.entries()[0].action,
            crate::store::AuditAction::BinaryHashRecorded
        );
    }

    #[test]
    fn sec19_a_changed_binary_gives_a_clear_warning() {
        // Covers: SEC-19
        let drives = TestDrives::new(2);
        let set = new_ca(&drives);
        let other = Sha256Digest([0x5a; 32]);
        set.record_binary_hash(other, ts(5)).expect("record");
        let result = check_running_binary(&open_all(&drives)).expect("check");
        let SelfCheck::Mismatch { recorded, .. } = &result else {
            panic!("expected a mismatch, got {result:?}");
        };
        assert_eq!(recorded.len(), 2);
        let warning = result.warning().expect("warning");
        assert!(
            warning.contains("differs") && warning.contains("sha256sum"),
            "{warning}"
        );
        assert!(warning.contains(&other.to_hex()));
    }

    #[test]
    fn sec19_one_drive_differing_is_a_mismatch() {
        // Covers: SEC-19
        let actual = Sha256Digest([1; 32]);
        let result = compare_binary_hash(
            actual,
            &[
                ("primary".to_string(), Some(actual)),
                ("backup".to_string(), Some(Sha256Digest([2; 32]))),
                ("new backup".to_string(), None),
            ],
        );
        assert!(matches!(result, SelfCheck::Mismatch { ref recorded, .. } if recorded.len() == 1));
        assert_eq!(
            compare_binary_hash(
                actual,
                &[("p".to_string(), Some(actual)), ("b".to_string(), None)]
            ),
            SelfCheck::Match
        );
        assert!(matches!(
            file_sha256(Path::new("/nonexistent/keystone")),
            Err(HardeningError::BinaryUnreadable { .. })
        ));
    }
}
