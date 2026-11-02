//! Issuance record (FR-11, FR-15, FR-22 AC3, SEC-10).
//!
//! The record is stored as one immutable file per operation, `keystone/record/op-NNNNNN.json`
//! (a [`RecordUpdate`]), written as an output of that operation and listed with its
//! SHA-256 in the operation's completed journal entry. The issuance record is all updates
//! applied in operation order. Because no record file is ever rewritten, every output of
//! every operation stays verifiable against its completed entry forever, and a behind
//! drive can be repaired one operation at a time (FR-12 AC3).
//!
//! FR-22 AC3: a certificate that was signed is journaled (`signed` entry) right after
//! signing. If its operation never wrote its record update, the certificate still
//! appears in the record, marked [`RecordSource::JournalOnly`]. A signed certificate is
//! never silently dropped.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::drive::{CaDrive, DriveSet, check_len, check_timestamp, to_json_file};
use super::ids::OperationId;
use super::journal::SignedObject;
use super::paths::{OutputDir, OutputPath, RECORD_DIR};
use super::{ParseError, StoreError};
use crate::limits::{MAX_PEM_BYTES, MAX_RECORD_BYTES};
use crate::model::{CaLevel, Fingerprint, NameFields, RevocationReason, Serial, Timestamp};

/// Current version of the record update format.
pub const RECORD_FORMAT: u32 = 1;
/// Longest name field accepted.
pub const MAX_NAME_TEXT: usize = 256;
/// Most permitted names of one kind accepted.
pub const MAX_PERMITTED_NAMES: usize = 256;
/// Most changes in one record update.
pub const MAX_CHANGES: usize = 4096;

/// Subject or issuer name as recorded (FR-11 AC1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectName {
    /// Common Name.
    pub common_name: String,
    /// Organization.
    pub organization: Option<String>,
    /// Country (2 letters).
    pub country: Option<String>,
}

impl SubjectName {
    /// `CN=..., O=..., C=..` for lists and audit entries.
    pub fn display(&self) -> String {
        let mut out = format!("CN={}", self.common_name);
        if let Some(organization) = &self.organization {
            out.push_str(&format!(", O={organization}"));
        }
        if let Some(country) = &self.country {
            out.push_str(&format!(", C={country}"));
        }
        out
    }

    fn validate(&self) -> Result<(), String> {
        let fields = [
            Some(&self.common_name),
            self.organization.as_ref(),
            self.country.as_ref(),
        ];
        if self.common_name.is_empty() {
            return Err("common name is empty".to_string());
        }
        if fields
            .into_iter()
            .flatten()
            .any(|f| f.len() > MAX_NAME_TEXT)
        {
            return Err("name field is too long".to_string());
        }
        Ok(())
    }
}

impl From<&NameFields> for SubjectName {
    fn from(fields: &NameFields) -> Self {
        SubjectName {
            common_name: fields.common_name.clone(),
            organization: fields.organization.clone(),
            country: fields.country.clone(),
        }
    }
}

/// Everything recorded about one signed certificate (FR-11 AC1, FR-21 AC6, FR-07 AC5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateRecord {
    /// Serial number.
    pub serial: Serial,
    /// Hierarchy level.
    pub level: CaLevel,
    /// Subject.
    pub subject: SubjectName,
    /// Serial of the issuing certificate (the master's own serial for the master).
    pub issuer_serial: Serial,
    /// Issuer name.
    pub issuer: SubjectName,
    /// Start of validity.
    pub not_before: Timestamp,
    /// End of validity.
    pub not_after: Timestamp,
    /// SHA-256 fingerprint of the DER certificate (SEC-10).
    pub fingerprint: Fingerprint,
    /// Name constraints on (sub-intermediates only, FR-21).
    pub name_constraints: bool,
    /// Permitted DNS names (FR-21 AC6).
    pub permitted_dns: Vec<String>,
    /// Permitted IP ranges (FR-21 AC3).
    pub permitted_ip: Vec<String>,
    /// PIV attestation certificate (PEM) of a main intermediate's key (FR-07 AC5).
    pub attestation_pem: Option<String>,
}

impl CertificateRecord {
    /// Structural checks on untrusted record data (SEC-08). These are not the
    /// certificate rules of FR-10, which the certificate builder enforces.
    pub(crate) fn validate(&self) -> Result<(), String> {
        self.subject.validate()?;
        self.issuer.validate()?;
        check_timestamp(self.not_before, "not_before").map_err(|e| e.to_string())?;
        check_timestamp(self.not_after, "not_after").map_err(|e| e.to_string())?;
        if self.not_after <= self.not_before {
            return Err("validity ends before it starts".to_string());
        }
        let self_signed = self.issuer_serial == self.serial;
        if self_signed != (self.level == CaLevel::Master) {
            return Err("only the master certificate is self-signed".to_string());
        }
        let constrained = self.name_constraints
            || !self.permitted_dns.is_empty()
            || !self.permitted_ip.is_empty();
        if constrained && self.level != CaLevel::SubIntermediate {
            return Err("name constraints apply to sub-intermediates only".to_string());
        }
        if self.name_constraints && self.permitted_dns.is_empty() {
            return Err("name constraints need at least one permitted DNS name".to_string());
        }
        if !self.name_constraints
            && (!self.permitted_dns.is_empty() || !self.permitted_ip.is_empty())
        {
            return Err("permitted names need name constraints switched on".to_string());
        }
        for list in [&self.permitted_dns, &self.permitted_ip] {
            if list.len() > MAX_PERMITTED_NAMES
                || list.iter().any(|n| n.is_empty() || n.len() > MAX_NAME_TEXT)
            {
                return Err("invalid permitted names".to_string());
            }
        }
        match (&self.attestation_pem, self.level) {
            (Some(pem), CaLevel::MainIntermediate)
                if !pem.is_empty() && pem.len() <= MAX_PEM_BYTES => {}
            (None, CaLevel::Master | CaLevel::SubIntermediate) => {}
            (_, CaLevel::MainIntermediate) => {
                return Err("a main intermediate needs its attestation certificate".to_string());
            }
            _ => return Err("only main intermediates carry an attestation".to_string()),
        }
        Ok(())
    }
}

/// One change to the issuance record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RecordChange {
    /// A certificate was signed.
    Issued {
        /// The certificate.
        certificate: Box<CertificateRecord>,
    },
    /// A certificate was revoked (Flow D, Flow E).
    Revoked {
        /// The revoked certificate.
        serial: Serial,
        /// Revocation date.
        date: Timestamp,
        /// Reason.
        reason: RevocationReason,
    },
    /// FR-15: a certificate is cut off because an ancestor was revoked.
    RevokedByAncestor {
        /// The certificate.
        serial: Serial,
        /// The revoked ancestor.
        ancestor: Serial,
        /// When it was marked.
        date: Timestamp,
    },
}

/// `record/op-NNNNNN.json`: the record changes made by one operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordUpdate {
    /// Always [`RECORD_FORMAT`].
    pub format: u32,
    /// The operation that made the changes.
    pub operation: OperationId,
    /// The changes, in order.
    pub changes: Vec<RecordChange>,
}

impl RecordUpdate {
    /// A new update for `operation`.
    pub fn new(operation: OperationId, changes: Vec<RecordChange>) -> Self {
        RecordUpdate {
            format: RECORD_FORMAT,
            operation,
            changes,
        }
    }

    /// Where the update is stored: `record/op-NNNNNN.json`.
    pub fn output_path(&self) -> OutputPath {
        OutputPath::new(
            OutputDir::Record,
            &format!("{}.json", self.operation.stem()),
        )
        .expect("operation stems are valid names")
    }

    /// The file content (stage it as an output of the operation).
    pub fn to_bytes(&self) -> Vec<u8> {
        to_json_file(self)
    }
}

/// Parses one issuance-record update (SEC-08). Never panics on any input.
pub fn parse_record(bytes: &[u8]) -> Result<RecordUpdate, ParseError> {
    check_len(bytes, MAX_RECORD_BYTES)?;
    let update: RecordUpdate = serde_json::from_slice(bytes)
        .map_err(|e| ParseError::invalid(format!("record update: {e}")))?;
    if update.format != RECORD_FORMAT {
        return Err(ParseError::invalid("unsupported record format"));
    }
    if !update.operation.is_valid() {
        return Err(ParseError::invalid("invalid operation number"));
    }
    if update.changes.len() > MAX_CHANGES {
        return Err(ParseError::invalid("too many record changes"));
    }
    for change in &update.changes {
        match change {
            RecordChange::Issued { certificate } => {
                certificate.validate().map_err(ParseError::Invalid)?;
            }
            RecordChange::Revoked { date, .. } | RecordChange::RevokedByAncestor { date, .. } => {
                check_timestamp(*date, "date")?;
            }
        }
    }
    Ok(update)
}

/// Stored status of a certificate (FR-11 AC1, FR-15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    /// Not revoked.
    Valid,
    /// Revoked.
    Revoked {
        /// Revocation date.
        date: Timestamp,
        /// Reason.
        reason: RevocationReason,
    },
    /// Cut off by a revoked ancestor (FR-15).
    RevokedByAncestor {
        /// The revoked ancestor.
        ancestor: Serial,
        /// When it was marked.
        date: Timestamp,
    },
}

/// Status filter for the record list (FR-11 AC2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusFilter {
    /// Not revoked and not expired.
    Valid,
    /// Not revoked but past `not_after`.
    Expired,
    /// Revoked.
    Revoked,
    /// Revoked by ancestor.
    RevokedByAncestor,
}

/// Where a certificate's entry comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordSource {
    /// A record update file.
    RecordFile,
    /// Only a `signed` journal entry: its operation did not write its record update
    /// (FR-22 AC3). The recovery screen finishes or explains that operation.
    JournalOnly,
}

/// One certificate in the issuance record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedCertificate {
    /// What was signed.
    pub certificate: CertificateRecord,
    /// Stored status.
    pub status: CertStatus,
    /// The operation that signed it.
    pub operation: OperationId,
    /// Where this entry comes from.
    pub source: RecordSource,
}

impl RecordedCertificate {
    /// Status as shown on `now` (adds "expired").
    pub fn effective_status(&self, now: OffsetDateTime) -> StatusFilter {
        match self.status {
            CertStatus::Revoked { .. } => StatusFilter::Revoked,
            CertStatus::RevokedByAncestor { .. } => StatusFilter::RevokedByAncestor,
            CertStatus::Valid if now > self.certificate.not_after.get() => StatusFilter::Expired,
            CertStatus::Valid => StatusFilter::Valid,
        }
    }
}

/// The issuance record (FR-11).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IssuanceRecord {
    certs: Vec<RecordedCertificate>,
}

fn record_err(message: String) -> ParseError {
    ParseError::Invalid(message)
}

impl IssuanceRecord {
    /// An empty record.
    pub fn empty() -> Self {
        IssuanceRecord::default()
    }

    /// Builds the record from updates (in any order; applied in operation order).
    pub fn from_updates(updates: &[RecordUpdate]) -> Result<Self, ParseError> {
        let mut sorted: Vec<&RecordUpdate> = updates.iter().collect();
        sorted.sort_by_key(|update| update.operation);
        let mut record = IssuanceRecord::empty();
        for update in sorted {
            record.apply(update)?;
        }
        Ok(record)
    }

    /// Applies one update. Inconsistent updates (a serial issued twice, revoking an
    /// unknown certificate, an unknown issuer) are errors.
    pub fn apply(&mut self, update: &RecordUpdate) -> Result<(), ParseError> {
        for change in &update.changes {
            match change {
                RecordChange::Issued { certificate } => {
                    if self.position(certificate.serial).is_some() {
                        return Err(record_err(format!(
                            "serial {} is recorded twice",
                            certificate.serial
                        )));
                    }
                    if certificate.level != CaLevel::Master
                        && self.position(certificate.issuer_serial).is_none()
                    {
                        return Err(record_err(format!(
                            "the issuer of {} is not in the record",
                            certificate.serial
                        )));
                    }
                    self.certs.push(RecordedCertificate {
                        certificate: (**certificate).clone(),
                        status: CertStatus::Valid,
                        operation: update.operation,
                        source: RecordSource::RecordFile,
                    });
                }
                RecordChange::Revoked {
                    serial,
                    date,
                    reason,
                } => {
                    let index = self.known(*serial)?;
                    if matches!(self.certs[index].status, CertStatus::Revoked { .. }) {
                        return Err(record_err(format!("{serial} is already revoked")));
                    }
                    self.certs[index].status = CertStatus::Revoked {
                        date: *date,
                        reason: *reason,
                    };
                }
                RecordChange::RevokedByAncestor {
                    serial,
                    ancestor,
                    date,
                } => {
                    let index = self.known(*serial)?;
                    if self.certs[index].status != CertStatus::Valid {
                        return Err(record_err(format!("{serial} is already revoked")));
                    }
                    let ancestor_index = self.known(*ancestor)?;
                    if !matches!(
                        self.certs[ancestor_index].status,
                        CertStatus::Revoked { .. }
                    ) || !self.is_ancestor(*ancestor, *serial)
                    {
                        return Err(record_err(format!(
                            "{ancestor} is not a revoked ancestor of {serial}"
                        )));
                    }
                    self.certs[index].status = CertStatus::RevokedByAncestor {
                        ancestor: *ancestor,
                        date: *date,
                    };
                }
            }
        }
        Ok(())
    }

    /// Adds a certificate known only from a `signed` journal entry (FR-22 AC3). Does
    /// nothing if the serial is already recorded.
    pub fn add_journal_only(&mut self, operation: OperationId, certificate: &CertificateRecord) {
        if self.position(certificate.serial).is_none() {
            self.certs.push(RecordedCertificate {
                certificate: certificate.clone(),
                status: CertStatus::Valid,
                operation,
                source: RecordSource::JournalOnly,
            });
        }
    }

    /// Every certificate, in the order they were recorded.
    pub fn certificates(&self) -> &[RecordedCertificate] {
        &self.certs
    }

    /// The certificate with `serial`.
    pub fn get(&self, serial: Serial) -> Option<&RecordedCertificate> {
        self.position(serial).map(|index| &self.certs[index])
    }

    /// FR-11 AC2: certificates filtered by issuer and/or status (as shown on `now`).
    pub fn filter(
        &self,
        issuer: Option<Serial>,
        status: Option<StatusFilter>,
        now: OffsetDateTime,
    ) -> Vec<&RecordedCertificate> {
        self.certs
            .iter()
            .filter(|cert| issuer.is_none_or(|issuer| cert.certificate.issuer_serial == issuer))
            .filter(|cert| status.is_none_or(|status| cert.effective_status(now) == status))
            .collect()
    }

    /// Certificates issued directly by `issuer` (not the issuer itself).
    pub fn children_of(&self, issuer: Serial) -> Vec<&RecordedCertificate> {
        self.certs
            .iter()
            .filter(|cert| {
                cert.certificate.issuer_serial == issuer && cert.certificate.serial != issuer
            })
            .collect()
    }

    /// Every serial in the record.
    pub fn serials(&self) -> BTreeSet<Serial> {
        self.certs
            .iter()
            .map(|cert| cert.certificate.serial)
            .collect()
    }

    fn position(&self, serial: Serial) -> Option<usize> {
        self.certs
            .iter()
            .position(|cert| cert.certificate.serial == serial)
    }

    fn known(&self, serial: Serial) -> Result<usize, ParseError> {
        self.position(serial)
            .ok_or_else(|| record_err(format!("{serial} is not in the record")))
    }

    fn is_ancestor(&self, ancestor: Serial, serial: Serial) -> bool {
        let mut current = serial;
        for _ in 0..8 {
            let Some(index) = self.position(current) else {
                return false;
            };
            let issuer = self.certs[index].certificate.issuer_serial;
            if issuer == current {
                return false;
            }
            if issuer == ancestor {
                return true;
            }
            current = issuer;
        }
        false
    }
}

impl CaDrive {
    /// The record updates stored on this drive, by operation.
    pub fn record_updates(&self) -> Result<BTreeMap<OperationId, RecordUpdate>, StoreError> {
        let mut out = BTreeMap::new();
        let Some(dir) = self.dir_at(RECORD_DIR, false)? else {
            return Ok(out);
        };
        for (name, _) in dir.entries()? {
            if name.starts_with('.') {
                continue;
            }
            let path = dir.child(&name);
            let operation = name
                .strip_suffix(".json")
                .and_then(OperationId::from_stem)
                .ok_or_else(|| StoreError::Parse {
                    path: path.clone(),
                    source: ParseError::invalid("unexpected file in the record folder"),
                })?;
            let update = parse_record(&dir.read(&name, MAX_RECORD_BYTES)?).map_err(|source| {
                StoreError::Parse {
                    path: path.clone(),
                    source,
                }
            })?;
            if update.operation != operation {
                return Err(StoreError::Parse {
                    path,
                    source: ParseError::invalid("file name and operation number differ"),
                });
            }
            out.insert(operation, update);
        }
        Ok(out)
    }

    /// This drive's issuance record: every record update, plus every certificate that
    /// was journaled as signed but is missing from the updates (FR-22 AC3).
    pub fn issuance_record(&self) -> Result<IssuanceRecord, StoreError> {
        let updates: Vec<RecordUpdate> = self.record_updates()?.into_values().collect();
        let mut record =
            IssuanceRecord::from_updates(&updates).map_err(|source| StoreError::Parse {
                path: self.keystone().child(RECORD_DIR),
                source,
            })?;
        for (operation, journal) in self.journal()? {
            for signed in journal.signed() {
                if let SignedObject::Certificate { record: cert, .. } = signed {
                    record.add_journal_only(operation, cert);
                }
            }
        }
        Ok(record)
    }

    /// Every serial this drive has seen: recorded, planned in any journal entry
    /// (including cancelled and abandoned operations) or journaled as signed (FR-10 AC2).
    pub fn seen_serials(&self) -> Result<BTreeSet<Serial>, StoreError> {
        let mut serials = BTreeSet::new();
        for update in self.record_updates()?.values() {
            for change in &update.changes {
                serials.insert(match change {
                    RecordChange::Issued { certificate } => certificate.serial,
                    RecordChange::Revoked { serial, .. }
                    | RecordChange::RevokedByAncestor { serial, .. } => *serial,
                });
            }
        }
        for journal in self.journal()?.values() {
            serials.extend(journal.planned_serials().iter().copied());
            for signed in journal.signed() {
                if let SignedObject::Certificate { record, .. } = signed {
                    serials.insert(record.serial);
                }
            }
        }
        Ok(serials)
    }
}

/// FR-10 AC2: every serial seen on any of `drives` (records and journals, including
/// abandoned operations and divergent histories). Any unreadable file is an error, so a
/// serial is never approved on incomplete information.
pub fn known_serials(drives: &[CaDrive]) -> Result<BTreeSet<Serial>, StoreError> {
    let mut serials = BTreeSet::new();
    for drive in drives {
        serials.extend(drive.seen_serials()?);
    }
    Ok(serials)
}

impl DriveSet {
    /// FR-10 AC2: every serial seen on any connected drive.
    pub fn known_serials(&self) -> Result<BTreeSet<Serial>, StoreError> {
        known_serials(self.drives())
    }

    /// The issuance record (FR-11), which must be the same on every drive.
    pub fn issuance_record(&self) -> Result<IssuanceRecord, StoreError> {
        let mut first: Option<(String, IssuanceRecord)> = None;
        for drive in self.drives() {
            let record = drive.issuance_record()?;
            match &first {
                None => first = Some((drive.label(), record)),
                Some((label, existing)) if *existing != record => {
                    return Err(StoreError::OutOfSync(format!(
                        "{label} and {} have different issuance records",
                        drive.label()
                    )));
                }
                Some(_) => {}
            }
        }
        Ok(first.map(|(_, record)| record).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests;
