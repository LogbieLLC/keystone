//! The CA's current state as the operations layer sees it: every certificate and CRL
//! signed by a completed operation, the issuance record, the CRL address of each issuer
//! (FR-18) and the file names Keystone writes (FR-09 AC1).
//!
//! The state is rebuilt from a drive's journal every time it is needed: the `signed`
//! entries of completed operations hold the exact PEM of every certificate and CRL
//! (FR-22 AC3), and each one is checked against its recorded SHA-256 before use.
#![forbid(unsafe_code)]

use time::OffsetDateTime;

use crate::cert::{CertificateInfo, parse_certificate_pem};
use crate::crl::{CrlInfo, parse_crl_pem};
use crate::model::{CaLevel, Serial};
use crate::profile::{CrlLocation, CrlUrl};
use crate::store::{
    CaDrive, CertStatus, CertificateRecord, IssuanceRecord, OperationId, OperationState, OutputDir,
    OutputPath, SignedObject, StatusFilter,
};

use super::OpsError;

/// A certificate signed by a completed operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCert {
    /// What the issuance record holds.
    pub record: CertificateRecord,
    /// Its status in the issuance record.
    pub status: CertStatus,
    /// The operation that signed it.
    pub operation: OperationId,
    /// DER encoding.
    pub der: Vec<u8>,
    /// PEM encoding, exactly as stored.
    pub pem: String,
    /// Parsed facts.
    pub info: CertificateInfo,
}

impl StoredCert {
    /// The serial.
    pub fn serial(&self) -> Serial {
        self.record.serial
    }

    /// The level.
    pub fn level(&self) -> CaLevel {
        self.record.level
    }

    /// True when not revoked (directly or by an ancestor) and not expired at `now`.
    pub fn is_usable(&self, now: OffsetDateTime) -> bool {
        self.status == CertStatus::Valid && now <= self.info.not_after
    }

    /// The certificate's file in `certs/` (FR-09 AC1).
    pub fn certificate_path(&self) -> OutputPath {
        certificate_path(&self.record)
    }
}

/// A CRL signed by a completed operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCrl {
    /// Serial of the issuing certificate.
    pub issuer_serial: Serial,
    /// The operation that signed it.
    pub operation: OperationId,
    /// DER encoding (what is written to the drives and the export drive).
    pub der: Vec<u8>,
    /// Parsed facts (CRL number, thisUpdate, nextUpdate, revoked entries).
    pub info: CrlInfo,
}

/// The CA's state: certificates and CRLs of completed operations and the issuance
/// record (FR-11, FR-19).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CaState {
    record: IssuanceRecord,
    certs: Vec<StoredCert>,
    crls: Vec<StoredCrl>,
}

fn damaged(message: String) -> OpsError {
    OpsError::Damaged(message)
}

impl CaState {
    /// Rebuilds the state from one drive's journal and issuance record.
    pub fn load(drive: &CaDrive) -> Result<CaState, OpsError> {
        let record = drive.issuance_record()?;
        let mut certs = Vec::new();
        let mut crls = Vec::new();
        for (operation, journal) in drive.journal()? {
            if journal.state() != OperationState::Completed {
                continue;
            }
            for object in journal.signed() {
                match object {
                    SignedObject::Certificate { record: cert, pem } => {
                        let (der, info) = parse_certificate_pem(pem.as_bytes()).map_err(|e| {
                            damaged(format!(
                                "the certificate of {operation} cannot be read: {e}"
                            ))
                        })?;
                        if info.fingerprint != cert.fingerprint || info.serial != cert.serial {
                            return Err(damaged(format!(
                                "the certificate journaled by {operation} does not match its record"
                            )));
                        }
                        let status = record
                            .get(cert.serial)
                            .map(|entry| entry.status)
                            .ok_or_else(|| {
                                damaged(format!(
                                    "certificate {} of {operation} is missing from the issuance record",
                                    cert.serial
                                ))
                            })?;
                        certs.push(StoredCert {
                            record: (**cert).clone(),
                            status,
                            operation,
                            der,
                            pem: pem.clone(),
                            info,
                        });
                    }
                    SignedObject::Crl(crl) => {
                        let (der, info) = parse_crl_pem(crl.pem.as_bytes()).map_err(|e| {
                            damaged(format!("the CRL of {operation} cannot be read: {e}"))
                        })?;
                        if info.fingerprint != crl.sha256 || info.crl_number != crl.crl_number {
                            return Err(damaged(format!(
                                "the CRL journaled by {operation} does not match its journal entry"
                            )));
                        }
                        crls.push(StoredCrl {
                            issuer_serial: crl.issuer_serial,
                            operation,
                            der,
                            info,
                        });
                    }
                }
            }
        }
        if certs
            .iter()
            .filter(|c| c.level() == CaLevel::Master)
            .count()
            > 1
        {
            return Err(damaged("the drives record more than one master".into()));
        }
        Ok(CaState {
            record,
            certs,
            crls,
        })
    }

    /// The issuance record (FR-11), including certificates known only from the journal
    /// of an interrupted operation (FR-22 AC3).
    pub fn record(&self) -> &IssuanceRecord {
        &self.record
    }

    /// Every certificate of a completed operation, in operation order.
    pub fn certificates(&self) -> &[StoredCert] {
        &self.certs
    }

    /// Every CRL of a completed operation, in operation order.
    pub fn crls(&self) -> &[StoredCrl] {
        &self.crls
    }

    /// True when the drives hold no certificate at all (not even from an interrupted
    /// operation): the drive set holds no CA yet (SEC-20 decision, see `ops` docs).
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty() && self.record.certificates().is_empty()
    }

    /// The certificate with `serial`.
    pub fn certificate(&self, serial: Serial) -> Option<&StoredCert> {
        self.certs.iter().find(|cert| cert.serial() == serial)
    }

    /// The master certificate.
    pub fn master(&self) -> Option<&StoredCert> {
        self.certs
            .iter()
            .find(|cert| cert.level() == CaLevel::Master)
    }

    /// Every main intermediate, oldest first.
    pub fn main_intermediates(&self) -> Vec<&StoredCert> {
        self.of_level(CaLevel::MainIntermediate)
    }

    /// Every sub-intermediate, oldest first.
    pub fn sub_intermediates(&self) -> Vec<&StoredCert> {
        self.of_level(CaLevel::SubIntermediate)
    }

    fn of_level(&self, level: CaLevel) -> Vec<&StoredCert> {
        self.certs.iter().filter(|c| c.level() == level).collect()
    }

    /// The main intermediate that signs new sub-intermediates: the newest one that is
    /// neither revoked nor expired at `now`.
    pub fn active_main(&self, now: OffsetDateTime) -> Option<&StoredCert> {
        self.certs
            .iter()
            .rev()
            .find(|c| c.level() == CaLevel::MainIntermediate && c.is_usable(now))
    }

    /// Certificates issued directly by `issuer`, oldest first.
    pub fn children_of(&self, issuer: Serial) -> Vec<&StoredCert> {
        self.certs
            .iter()
            .filter(|c| c.record.issuer_serial == issuer && c.serial() != issuer)
            .collect()
    }

    /// The issuer's newest CRL (highest CRL number).
    pub fn current_crl(&self, issuer: Serial) -> Option<&StoredCrl> {
        self.crls
            .iter()
            .filter(|crl| crl.issuer_serial == issuer)
            .max_by_key(|crl| crl.info.crl_number)
    }

    /// The CRL address of `issuer` (FR-18 AC1), decided before its first child was
    /// signed and written into that child: `None` while the issuer has no child yet, so
    /// the GUI must ask for it. Later children reuse it.
    pub fn crl_location(&self, issuer: Serial) -> Result<Option<CrlLocation>, OpsError> {
        let Some(first) = self.children_of(issuer).into_iter().next() else {
            return Ok(None);
        };
        Ok(Some(match first.info.crl_distribution_urls.first() {
            Some(url) => CrlLocation::Url(CrlUrl::parse(url).map_err(|e| {
                damaged(format!(
                    "the CRL address in {} is invalid: {e}",
                    first.serial()
                ))
            })?),
            None => CrlLocation::ExplicitlyNone,
        }))
    }

    /// Flow E step 4 (FR-15 AC1): sub-intermediates cut off because their main
    /// intermediate was revoked and not yet re-issued under the active main
    /// intermediate (no usable sub-intermediate with the same subject exists under it).
    pub fn reissue_candidates(&self, now: OffsetDateTime) -> Vec<&StoredCert> {
        let active = self.active_main(now).map(StoredCert::serial);
        self.sub_intermediates()
            .into_iter()
            .filter(|sub| matches!(sub.status, CertStatus::RevokedByAncestor { .. }))
            .filter(|sub| {
                !self.sub_intermediates().iter().any(|other| {
                    Some(other.record.issuer_serial) == active
                        && other.is_usable(now)
                        && other.record.subject == sub.record.subject
                })
            })
            .collect()
    }

    /// FR-11 AC2: the record filtered by issuer and status (as shown on `now`).
    pub fn filter_record(
        &self,
        issuer: Option<Serial>,
        status: Option<StatusFilter>,
        now: OffsetDateTime,
    ) -> Vec<&crate::store::RecordedCertificate> {
        self.record.filter(issuer, status, now)
    }
}

// ---------------------------------------------------------------------------
// File names (FR-09 AC1)
// ---------------------------------------------------------------------------

/// Hex characters of the serial used in file names (63 random bits; files are
/// create-only, so a clash could never overwrite anything).
const SERIAL_CHARS: usize = 16;
/// Longest name part taken from a Common Name.
const MAX_SLUG: usize = 48;

/// A file-name part from a Common Name: lower-case letters and digits, every other run
/// of characters becomes one `-`.
pub fn slug(common_name: &str) -> String {
    let mut out = String::new();
    for ch in common_name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
        if out.len() >= MAX_SLUG {
            break;
        }
    }
    let trimmed = out.trim_end_matches('-');
    if trimmed.is_empty() {
        "sub-intermediate".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn short_serial(serial: Serial) -> String {
    serial.to_hex()[..SERIAL_CHARS].to_owned()
}

/// The stem of a certificate's files: `master`, `main-intermediate-<serial>` or
/// `<common-name>-<serial>` for a sub-intermediate (FR-09 AC1 `<name>`).
pub fn file_stem(level: CaLevel, common_name: &str, serial: Serial) -> String {
    match level {
        CaLevel::Master => "master".to_owned(),
        CaLevel::MainIntermediate => format!("main-intermediate-{}", short_serial(serial)),
        CaLevel::SubIntermediate => format!("{}-{}", slug(common_name), short_serial(serial)),
    }
}

fn path(dir: OutputDir, name: &str) -> OutputPath {
    OutputPath::new(dir, name).expect("file names built here are always valid")
}

/// `certs/<stem>.crt` (PEM).
pub fn certificate_path(record: &CertificateRecord) -> OutputPath {
    let stem = file_stem(record.level, &record.subject.common_name, record.serial);
    path(OutputDir::Certs, &format!("{stem}.crt"))
}

/// `keys/<stem>.key` (encrypted PKCS#8 PEM).
pub fn key_path(level: CaLevel, common_name: &str, serial: Serial) -> OutputPath {
    let stem = file_stem(level, common_name, serial);
    path(OutputDir::Keys, &format!("{stem}.key"))
}

/// `certs/<stem>-chain.pem`: sub-intermediate, main intermediate, master (FR-09 AC1).
pub fn chain_path(record: &CertificateRecord) -> OutputPath {
    let stem = file_stem(record.level, &record.subject.common_name, record.serial);
    path(OutputDir::Certs, &format!("{stem}-chain.pem"))
}

/// `crls/<issuer stem>-crl-<number>.crl` (DER, as RFC 5280 section 4.2.1.13 expects at
/// a CRL distribution point).
pub fn crl_path(issuer: &CertificateRecord, crl_number: u64) -> OutputPath {
    let stem = file_stem(issuer.level, &issuer.subject.common_name, issuer.serial);
    path(OutputDir::Crls, &format!("{stem}-crl-{crl_number:06}.crl"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr09_ac1_file_names_are_valid_and_distinct() {
        // Covers: FR-09 AC1
        let serial = Serial::from_hex(&format!("{:040x}", 0x1234_5678_9abc_def0_u64)).unwrap();
        assert_eq!(slug("KEYSTONE TEST A Sub"), "keystone-test-a-sub");
        assert_eq!(slug("  ***  "), "sub-intermediate");
        assert_eq!(slug(&"x".repeat(100)).len(), MAX_SLUG);
        assert_eq!(file_stem(CaLevel::Master, "anything", serial), "master");
        assert_eq!(
            file_stem(CaLevel::SubIntermediate, "Ünïcode Name", serial),
            "n-code-name-0000000000000000"
        );
        assert!(
            file_stem(CaLevel::MainIntermediate, "x", serial).starts_with("main-intermediate-")
        );
    }
}
