//! The issuance record list (FR-11 AC1, AC2, FR-15, FR-20, FR-21 AC6, FR-22 AC3).
//!
//! Filtering is core's `IssuanceRecord::filter(issuer, status, now)`; this module builds
//! the filter choices and one row per certificate.
#![forbid(unsafe_code)]

use keystone_core::model::{CaLevel, RevocationReason, Serial};
use keystone_core::store::{
    CertStatus, IssuanceRecord, RecordSource, RecordedCertificate, StatusFilter,
};
use time::OffsetDateTime;

use super::{Status, format_date, format_utc};

/// The status filter choices, in the order the drop-down lists them.
pub const STATUS_CHOICES: [(Option<StatusFilter>, &str); 5] = [
    (None, "All statuses"),
    (Some(StatusFilter::Valid), "Valid"),
    (Some(StatusFilter::Expired), "Expired"),
    (Some(StatusFilter::Revoked), "Revoked"),
    (Some(StatusFilter::RevokedByAncestor), "Revoked by ancestor"),
];

/// The issuer filter choices: "All issuers", then every certificate that issued
/// another one (the master issues itself and is listed too).
pub fn issuer_choices(record: &IssuanceRecord) -> Vec<(Option<Serial>, String)> {
    let mut choices = vec![(None, "All issuers".to_string())];
    for cert in record.certificates() {
        let serial = cert.certificate.serial;
        let issues = record
            .certificates()
            .iter()
            .any(|other| other.certificate.issuer_serial == serial);
        if issues {
            choices.push((
                Some(serial),
                format!(
                    "{} ({})",
                    cert.certificate.subject.display(),
                    level_name(cert.certificate.level)
                ),
            ));
        }
    }
    choices
}

/// A level in words.
pub fn level_name(level: CaLevel) -> &'static str {
    level.display_name()
}

/// A revocation reason in words.
pub fn reason_name(reason: RevocationReason) -> &'static str {
    match reason {
        RevocationReason::Unspecified => "unspecified",
        RevocationReason::KeyCompromise => "key compromise",
        RevocationReason::CaCompromise => "CA compromise",
        RevocationReason::AffiliationChanged => "affiliation changed",
        RevocationReason::Superseded => "superseded",
        RevocationReason::CessationOfOperation => "cessation of operation",
    }
}

/// One row of the record list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRow {
    /// Serial.
    pub serial: Serial,
    /// Level.
    pub level: CaLevel,
    /// Title line: subject and level.
    pub title: String,
    /// Status (shown as an icon and a word).
    pub status: Status,
    /// Status in words.
    pub status_text: String,
    /// Detail lines: issuer, validity, serial, fingerprint, permitted names.
    pub details: Vec<String>,
}

fn status_of(cert: &RecordedCertificate, now: OffsetDateTime) -> (Status, String) {
    match cert.status {
        CertStatus::Revoked { date, reason } => (
            Status::Blocked,
            format!(
                "Revoked on {} ({})",
                format_date(date.get()),
                reason_name(reason)
            ),
        ),
        CertStatus::RevokedByAncestor { ancestor, date } => (
            Status::Blocked,
            format!(
                "Revoked by ancestor {ancestor} (marked {})",
                format_date(date.get())
            ),
        ),
        CertStatus::Valid if cert.effective_status(now) == StatusFilter::Expired => (
            Status::Warning,
            format!(
                "Expired on {}",
                format_date(cert.certificate.not_after.get())
            ),
        ),
        CertStatus::Valid => (Status::Ok, "Valid".to_string()),
    }
}

/// The permitted names of a certificate, for the list and the review step (FR-21 AC6).
pub fn permitted_names(cert: &keystone_core::store::CertificateRecord) -> Option<String> {
    if cert.level != CaLevel::SubIntermediate {
        return None;
    }
    if !cert.name_constraints {
        return Some("Name constraints: off (may issue for any name)".to_string());
    }
    let mut text = format!("Permitted DNS names: {}", cert.permitted_dns.join(", "));
    if cert.permitted_ip.is_empty() {
        text.push_str("; IP addresses excluded; email addresses and URIs: none allowed");
    } else {
        text.push_str(&format!(
            "; permitted IP ranges: {}; email addresses and URIs: none allowed",
            cert.permitted_ip.join(", ")
        ));
    }
    Some(text)
}

/// One row for one certificate.
pub fn row(record: &IssuanceRecord, cert: &RecordedCertificate, now: OffsetDateTime) -> RecordRow {
    let c = &cert.certificate;
    let (status, status_text) = status_of(cert, now);
    let issuer = if c.issuer_serial == c.serial {
        "self-signed".to_string()
    } else {
        record.get(c.issuer_serial).map_or_else(
            || format!("serial {}", c.issuer_serial),
            |issuer| issuer.certificate.subject.display(),
        )
    };
    let mut details = vec![
        format!("Issuer: {issuer}"),
        format!(
            "Valid from {} to {}",
            format_utc(c.not_before.get()),
            format_utc(c.not_after.get())
        ),
        format!("Serial: {}", c.serial),
        format!(
            "SHA-256 fingerprint: {}",
            c.fingerprint.to_fingerprint_string()
        ),
    ];
    if let Some(names) = permitted_names(c) {
        details.push(names);
    }
    if cert.source == RecordSource::JournalOnly {
        details.push(
            "Known only from the operation journal: its operation did not finish. See the recovery screen."
                .to_string(),
        );
    }
    RecordRow {
        serial: c.serial,
        level: c.level,
        title: format!("{} ({})", c.subject.display(), level_name(c.level)),
        status,
        status_text,
        details,
    }
}

/// FR-11 AC2: the rows matching the filters.
pub fn rows(
    record: &IssuanceRecord,
    issuer: Option<Serial>,
    status: Option<StatusFilter>,
    now: OffsetDateTime,
) -> Vec<RecordRow> {
    record
        .filter(issuer, status, now)
        .into_iter()
        .map(|cert| row(record, cert, now))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::model::{Sha256Digest, Timestamp};
    use keystone_core::store::{
        CertificateRecord, OperationId, RecordChange, RecordUpdate, SubjectName,
    };
    use time::Duration;

    fn ts(days: i64) -> Timestamp {
        Timestamp::utc(keystone_core::build_info::build_date() + Duration::days(days))
    }

    fn serial(n: u8) -> Serial {
        let mut bytes = [0u8; 20];
        bytes[0] = 0x33;
        bytes[19] = n;
        Serial::from_bytes(bytes).expect("serial")
    }

    fn cert(n: u8, level: CaLevel, issuer: u8, days: i64) -> CertificateRecord {
        CertificateRecord {
            serial: serial(n),
            level,
            subject: SubjectName {
                common_name: format!("KEYSTONE TEST {n}"),
                organization: None,
                country: None,
            },
            issuer_serial: serial(issuer),
            issuer: SubjectName {
                common_name: "KEYSTONE TEST issuer".into(),
                organization: None,
                country: None,
            },
            not_before: ts(0),
            not_after: ts(days),
            fingerprint: Sha256Digest([n; 32]),
            name_constraints: level == CaLevel::SubIntermediate && n != 4,
            permitted_dns: if level == CaLevel::SubIntermediate && n != 4 {
                vec!["starnet".into()]
            } else {
                Vec::new()
            },
            permitted_ip: Vec::new(),
            attestation_pem: (level == CaLevel::MainIntermediate).then(|| {
                "-----BEGIN CERTIFICATE-----\nKEYSTONE TEST\n-----END CERTIFICATE-----\n".into()
            }),
        }
    }

    fn record() -> IssuanceRecord {
        let issued = |c: CertificateRecord| RecordChange::Issued {
            certificate: Box::new(c),
        };
        IssuanceRecord::from_updates(&[
            RecordUpdate::new(
                OperationId(1),
                vec![issued(cert(1, CaLevel::Master, 1, 7000))],
            ),
            RecordUpdate::new(
                OperationId(2),
                vec![issued(cert(2, CaLevel::MainIntermediate, 1, 3000))],
            ),
            RecordUpdate::new(
                OperationId(3),
                vec![
                    issued(cert(3, CaLevel::SubIntermediate, 2, 1000)),
                    issued(cert(4, CaLevel::SubIntermediate, 2, 1)),
                ],
            ),
            RecordUpdate::new(
                OperationId(4),
                vec![RecordChange::Revoked {
                    serial: serial(3),
                    date: ts(1),
                    reason: RevocationReason::KeyCompromise,
                }],
            ),
        ])
        .expect("record")
    }

    #[test]
    fn fr11_ac2_filter_by_issuer_and_status() {
        // Covers: FR-11 AC2
        let record = record();
        let now = (keystone_core::build_info::build_date() + Duration::days(10))
            .to_offset(time::UtcOffset::UTC);
        assert_eq!(rows(&record, None, None, now).len(), 4);
        let by_main = rows(&record, Some(serial(2)), None, now);
        assert_eq!(by_main.len(), 2);
        let revoked = rows(&record, None, Some(StatusFilter::Revoked), now);
        assert_eq!(revoked.len(), 1);
        assert!(revoked[0].status_text.contains("key compromise"));
        assert_eq!(revoked[0].status, Status::Blocked);
        let expired = rows(&record, None, Some(StatusFilter::Expired), now);
        assert_eq!(expired.len(), 1);
        assert!(expired[0].status_text.starts_with("Expired"));
        let choices = issuer_choices(&record);
        assert_eq!(choices.len(), 3, "all, master, main intermediate");
        assert!(choices[2].1.contains("main intermediate"));
        assert_eq!(STATUS_CHOICES.len(), 5);
    }

    #[test]
    fn fr21_ac6_fr20_rows_show_permitted_names_and_fingerprints() {
        // Covers: FR-21 AC6, FR-20 AC1, FR-11 AC1
        let record = record();
        let now = keystone_core::build_info::build_date();
        let rows = rows(&record, Some(serial(2)), None, now);
        let constrained = &rows[0];
        assert!(
            constrained
                .details
                .iter()
                .any(|d| d
                    == "Permitted DNS names: starnet; IP addresses excluded; email addresses and URIs: none allowed")
        );
        assert!(
            !constrained
                .details
                .iter()
                .any(|d| d.contains("email and URIs excluded")),
            "email and URI names are blocked through a reserved permitted domain (ADR 0001), not excluded"
        );
        assert!(
            constrained
                .details
                .iter()
                .any(|d| d.starts_with("SHA-256 fingerprint: 03:03:03"))
        );
        assert!(
            rows[1]
                .details
                .iter()
                .any(|d| d.contains("Name constraints: off"))
        );
        let master = row(&record, &record.certificates()[0], now);
        assert!(master.details[0].contains("self-signed"));
        assert!(permitted_names(&record.certificates()[0].certificate).is_none());
    }
}
