//! The result screen at the end of every flow (FR-12 AC1, AC2, FR-20 AC1, SEC-10).
//!
//! - One line per CA drive: written and read back, or the read-back failed, in which
//!   case the action is not reported as successful (FR-12 AC2).
//! - Every certificate created, with its SHA-256 fingerprint as uppercase hex pairs
//!   separated by colons, the way `openssl x509 -fingerprint -sha256` prints it
//!   (`model::Sha256Digest::to_fingerprint_string`, FR-20 AC1). The screen shows it as
//!   selectable text.
#![forbid(unsafe_code)]

use super::record::level_name;
use super::{Line, Status, format_utc};
use crate::backend::{FlowOutcome, FollowUp};

/// One certificate on the result screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateView {
    /// `CN=… (level)`.
    pub title: String,
    /// The fingerprint, colon-separated.
    pub fingerprint: String,
    /// `Serial: …`.
    pub serial: String,
}

/// What the result screen shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultView {
    /// The heading.
    pub title: String,
    /// True only when every drive was written and verified.
    pub success: bool,
    /// One line per drive.
    pub drives: Vec<Line>,
    /// Files per drive, in the same order as `drives`.
    pub drive_files: Vec<Vec<String>>,
    /// Export folder files.
    pub export_files: Vec<String>,
    /// Certificates with fingerprints.
    pub certificates: Vec<CertificateView>,
    /// CRL lines.
    pub crls: Vec<String>,
    /// Notes and follow-up advice.
    pub notes: Vec<Line>,
    /// Offer "Set up the new YubiKey now" (Flow E).
    pub offer_new_yubikey: bool,
}

/// Builds the result screen for `outcome`.
pub fn view(outcome: &FlowOutcome) -> ResultView {
    let all_verified = outcome.drive_writes.iter().all(|write| write.verified);
    let drives = outcome
        .drive_writes
        .iter()
        .map(|write| {
            if write.verified {
                Line::new(
                    Status::Ok,
                    format!(
                        "{}: every file was read back and matches its SHA-256.",
                        write.drive
                    ),
                )
            } else {
                Line::new(
                    Status::Blocked,
                    format!(
                        "{}: the read-back check failed; this action is not reported as successful.",
                        write.drive
                    ),
                )
            }
        })
        .collect();
    let title = if all_verified {
        outcome.title.clone()
    } else {
        format!("Not successful: {}", outcome.title)
    };
    let mut notes: Vec<Line> = outcome
        .notes
        .iter()
        .map(|note| Line::new(Status::Info, note.clone()))
        .collect();
    let mut offer_new_yubikey = false;
    for follow_up in &outcome.follow_up {
        match follow_up {
            FollowUp::SetUpNewYubikey => offer_new_yubikey = true,
            FollowUp::ReissueSubIntermediates(serials) if !serials.is_empty() => {
                notes.push(Line::new(
                    Status::Warning,
                    format!(
                        "Re-issue these sub-intermediates under the new main intermediate (New sub-intermediate): {}.",
                        serials
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
            FollowUp::ReissueSubIntermediates(_) => {}
        }
    }
    ResultView {
        title,
        success: all_verified,
        drives,
        drive_files: outcome
            .drive_writes
            .iter()
            .map(|write| write.files.clone())
            .collect(),
        export_files: outcome
            .export_files
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        certificates: outcome
            .certificates
            .iter()
            .map(|cert| CertificateView {
                title: format!("{} ({})", cert.subject, level_name(cert.level)),
                fingerprint: cert.fingerprint.to_fingerprint_string(),
                serial: format!("Serial: {}", cert.serial),
            })
            .collect(),
        crls: outcome
            .crls
            .iter()
            .map(|crl| {
                format!(
                    "CRL number {} of {}, next update {}.",
                    crl.crl_number,
                    crl.issuer,
                    format_utc(crl.next_update.get())
                )
            })
            .collect(),
        notes,
        offer_new_yubikey,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{CertificateSummary, CrlSummary, DriveWriteResult};
    use keystone_core::model::{CaLevel, Serial, Sha256Digest, Timestamp};

    fn outcome(verified: bool) -> FlowOutcome {
        FlowOutcome {
            title: "Master created".into(),
            drive_writes: vec![
                DriveWriteResult {
                    drive: "primary drive aaaa".into(),
                    verified: true,
                    files: vec!["certs/x.crt".into()],
                },
                DriveWriteResult {
                    drive: "backup drive bbbb".into(),
                    verified,
                    files: vec!["certs/x.crt".into()],
                },
            ],
            export_files: vec!["/media/export/keystone-export/master.crl".into()],
            certificates: vec![CertificateSummary {
                subject: "CN=KEYSTONE TEST Root".into(),
                level: CaLevel::Master,
                serial: Serial::from_bytes([0x11; 20]).expect("serial"),
                fingerprint: Sha256Digest([0xab; 32]),
            }],
            crls: vec![CrlSummary {
                issuer: "CN=KEYSTONE TEST Root".into(),
                crl_number: 1,
                next_update: Timestamp::utc(keystone_core::build_info::build_date()),
            }],
            notes: vec!["Upload the CRL to StarnetAuth.".into()],
            follow_up: vec![
                FollowUp::SetUpNewYubikey,
                FollowUp::ReissueSubIntermediates(vec![
                    Serial::from_bytes([0x22; 20]).expect("serial"),
                ]),
            ],
        }
    }

    #[test]
    fn fr20_ac1_fingerprint_is_shown_colon_separated() {
        // Covers: FR-20 AC1, SEC-10
        let v = view(&outcome(true));
        let cert = &v.certificates[0];
        assert_eq!(cert.title, "CN=KEYSTONE TEST Root (master (root))");
        assert_eq!(cert.fingerprint.len(), 95);
        assert!(cert.fingerprint.starts_with("AB:AB:"));
        assert!(cert.fingerprint.split(':').all(|pair| pair.len() == 2));
        assert!(cert.serial.starts_with("Serial: 1111"));
    }

    #[test]
    fn fr12_ac2_a_failed_read_back_is_never_reported_as_success() {
        // Covers: FR-12 AC1, FR-12 AC2, SEC-11
        let ok = view(&outcome(true));
        assert!(ok.success);
        assert_eq!(ok.title, "Master created");
        assert!(ok.drives.iter().all(|line| line.status == Status::Ok));
        let failed = view(&outcome(false));
        assert!(!failed.success);
        assert!(failed.title.starts_with("Not successful"));
        assert_eq!(failed.drives[1].status, Status::Blocked);
        assert!(failed.drives[1].text.contains("not reported as successful"));
    }

    #[test]
    fn fr15_follow_ups_are_offered() {
        // Covers: FR-15 AC1
        let v = view(&outcome(true));
        assert!(v.offer_new_yubikey);
        assert!(
            v.notes
                .iter()
                .any(|line| line.status == Status::Warning && line.text.contains("Re-issue"))
        );
        assert!(v.crls[0].starts_with("CRL number 1 of CN=KEYSTONE TEST Root"));
        assert_eq!(v.export_files.len(), 1);
    }
}
