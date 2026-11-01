//! X.509 v2 CRLs: building, refresh, expiry warning and parsing (FR-13).
//!
//! - The master signs the CRL covering main intermediates; the main intermediate
//!   (on the YubiKey) signs the CRL covering sub-intermediates (FR-13 AC1). Keystone
//!   signs no CRL for sub-intermediates; their issuing systems do that.
//! - Every CRL is v2 with cRLNumber and authorityKeyIdentifier, signed with
//!   sha384WithRSAEncryption; thisUpdate/nextUpdate use UTCTime through 2049 and
//!   GeneralizedTime from 2050 (FR-13 AC2, RFC 5280 section 5.1.2.4).
//! - Revoked entries carry a reasonCode entry extension, except for
//!   "unspecified", which RFC 5280 section 5.3.1 says to leave out.
//! - Refresh keeps the revoked list unchanged and uses a strictly higher CRL number
//!   (FR-13 AC4).
//! - Every CRL is decoded again and its signature verified with OpenSSL against the
//!   issuer's key before it is returned.
#![forbid(unsafe_code)]

use time::{Duration, OffsetDateTime};
use x509_cert::Version;
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::der::asn1::{BitString, OctetString, Uint};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::{Decode, Encode, Tagged};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, CrlNumber, CrlReason};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;

use crate::cert::encode::{SHA384_WITH_RSA, rfc5280_time, signature_algorithm, time_to_offset};
use crate::cert::{CertError, CertificateInfo, Sha384Signer, SignError, parse_certificate_der};
use crate::crypto::hash::sha256;
use crate::crypto::verify::{crl_der_to_pem, crl_pem_to_der, verify_crl_signature};
use crate::limits::MAX_CRL_BYTES;
use crate::model::{CaLevel, Fingerprint, RevocationReason, Serial};
use crate::profile::{CRL_WARNING_DAYS, default_crl_next_update, to_whole_seconds_utc};

/// Errors from this module.
#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    /// A certificate-level problem (issuer parsing, encoding helpers).
    #[error(transparent)]
    Cert(#[from] CertError),
    /// A crypto failure (size limit, signature check).
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
    /// A profile rule (default lifetimes).
    #[error(transparent)]
    Profile(#[from] crate::profile::ProfileError),
    /// Signing failed.
    #[error(transparent)]
    Sign(#[from] SignError),
    /// The request breaks a CRL rule.
    #[error("{0}")]
    Request(String),
    /// The CRL could not be encoded.
    #[error("CRL encoding failed: {0}")]
    Encoding(String),
    /// The CRL could not be read.
    #[error("CRL could not be read: {0}")]
    Parse(String),
}

fn encoding(context: &str) -> impl FnOnce(x509_cert::der::Error) -> CrlError + '_ {
    move |e| CrlError::Encoding(format!("{context}: {e}"))
}

fn parsing(context: &str) -> impl FnOnce(x509_cert::der::Error) -> CrlError + '_ {
    move |e| CrlError::Parse(format!("{context}: {e}"))
}

/// One revoked certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokedEntry {
    /// Serial of the revoked certificate.
    pub serial: Serial,
    /// When it was revoked.
    pub revocation_date: OffsetDateTime,
    /// Why (FR-11 AC1).
    pub reason: RevocationReason,
}

/// What a CRL says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlInfo {
    /// Issuer as RFC 4514 text.
    pub issuer: String,
    /// DER of the issuer Name.
    pub issuer_der: Vec<u8>,
    /// thisUpdate.
    pub this_update: OffsetDateTime,
    /// nextUpdate.
    pub next_update: OffsetDateTime,
    /// cRLNumber.
    pub crl_number: u64,
    /// authorityKeyIdentifier keyIdentifier.
    pub authority_key_id: Option<Vec<u8>>,
    /// Revoked entries, in CRL order.
    pub revoked: Vec<RevokedEntry>,
    /// SHA-256 of the DER CRL.
    pub fingerprint: Fingerprint,
    /// True when signed with sha384WithRSAEncryption (outer and inner agree).
    pub signature_is_sha384_rsa: bool,
    /// X.509 CRL version as written (1 = v2).
    pub version_raw: u8,
}

/// A signed, verified CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCrl {
    /// DER encoding.
    pub der: Vec<u8>,
    /// PEM encoding (`X509 CRL`).
    pub pem: String,
    /// Parsed facts.
    pub info: CrlInfo,
}

/// Input for [`build_crl`].
#[derive(Debug, Clone, Copy)]
pub struct CrlRequest<'a> {
    /// The issuing CA's certificate (master or main intermediate), DER.
    pub issuer_certificate_der: &'a [u8],
    /// cRLNumber; at least 1.
    pub crl_number: u64,
    /// thisUpdate.
    pub this_update: OffsetDateTime,
    /// nextUpdate.
    pub next_update: OffsetDateTime,
    /// Revoked certificates.
    pub revoked: &'a [RevokedEntry],
}

fn crl_reason(reason: RevocationReason) -> CrlReason {
    match reason {
        RevocationReason::Unspecified => CrlReason::Unspecified,
        RevocationReason::KeyCompromise => CrlReason::KeyCompromise,
        RevocationReason::CaCompromise => CrlReason::CaCompromise,
        RevocationReason::AffiliationChanged => CrlReason::AffiliationChanged,
        RevocationReason::Superseded => CrlReason::Superseded,
        RevocationReason::CessationOfOperation => CrlReason::CessationOfOperation,
    }
}

fn revocation_reason(reason: CrlReason) -> Result<RevocationReason, CrlError> {
    Ok(match reason {
        CrlReason::Unspecified => RevocationReason::Unspecified,
        CrlReason::KeyCompromise => RevocationReason::KeyCompromise,
        CrlReason::CaCompromise => RevocationReason::CaCompromise,
        CrlReason::AffiliationChanged => RevocationReason::AffiliationChanged,
        CrlReason::Superseded => RevocationReason::Superseded,
        CrlReason::CessationOfOperation => RevocationReason::CessationOfOperation,
        other => {
            return Err(CrlError::Parse(format!(
                "unsupported revocation reason {other:?}"
            )));
        }
    })
}

fn issuer_of_crls(der: &[u8]) -> Result<(CertificateInfo, CaLevel), CrlError> {
    let issuer = parse_certificate_der(der)?;
    match issuer.ca_level() {
        Some(level @ (CaLevel::Master | CaLevel::MainIntermediate)) => Ok((issuer, level)),
        _ => Err(CrlError::Request(
            "only the master and the main intermediate sign CRLs in Keystone".into(),
        )),
    }
}

fn check_request(request: &CrlRequest<'_>, issuer: &CertificateInfo) -> Result<(), CrlError> {
    if request.crl_number == 0 {
        return Err(CrlError::Request("CRL numbers start at 1".into()));
    }
    if request.next_update <= request.this_update {
        return Err(CrlError::Request(
            "nextUpdate must be after thisUpdate".into(),
        ));
    }
    if request.this_update < issuer.not_before || request.this_update > issuer.not_after {
        return Err(CrlError::Request(
            "the issuer certificate is not valid at thisUpdate".into(),
        ));
    }
    if issuer.subject_key_id.is_none() {
        return Err(CrlError::Request(
            "the issuer certificate has no subjectKeyIdentifier".into(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for entry in request.revoked {
        if !seen.insert(entry.serial) {
            return Err(CrlError::Request(format!(
                "serial {} is listed twice",
                entry.serial
            )));
        }
        if entry.revocation_date > request.this_update {
            return Err(CrlError::Request(format!(
                "serial {} has a revocation date after thisUpdate",
                entry.serial
            )));
        }
    }
    Ok(())
}

fn revoked_cert(entry: &RevokedEntry) -> Result<RevokedCert, CrlError> {
    let serial_number =
        SerialNumber::new(entry.serial.as_bytes()).map_err(encoding("revoked serial"))?;
    let crl_entry_extensions = if entry.reason == RevocationReason::Unspecified {
        None
    } else {
        let value = crl_reason(entry.reason)
            .to_der()
            .map_err(encoding("reasonCode"))?;
        Some(vec![Extension {
            extn_id: CrlReason::OID,
            critical: false,
            extn_value: OctetString::new(value).map_err(encoding("reasonCode"))?,
        }])
    };
    Ok(RevokedCert {
        serial_number,
        revocation_date: rfc5280_time(to_whole_seconds_utc(entry.revocation_date)?)?,
        crl_entry_extensions,
    })
}

/// Builds, signs and verifies a CRL (FR-13 AC1, AC2).
pub fn build_crl(
    request: &CrlRequest<'_>,
    signer: &mut dyn Sha384Signer,
) -> Result<IssuedCrl, CrlError> {
    let (issuer, _) = issuer_of_crls(request.issuer_certificate_der)?;
    check_request(request, &issuer)?;
    if signer.signer_public_key_der()? != issuer.spki_der {
        return Err(CrlError::Cert(CertError::SignerKeyMismatch));
    }
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(
            OctetString::new(issuer.subject_key_id.clone().unwrap_or_default())
                .map_err(encoding("AKI"))?,
        ),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    let number =
        CrlNumber(Uint::new(&request.crl_number.to_be_bytes()).map_err(encoding("cRLNumber"))?);
    let extensions = vec![
        Extension {
            extn_id: AuthorityKeyIdentifier::OID,
            critical: false,
            extn_value: OctetString::new(aki.to_der().map_err(encoding("AKI"))?)
                .map_err(encoding("AKI"))?,
        },
        Extension {
            extn_id: CrlNumber::OID,
            critical: false,
            extn_value: OctetString::new(number.to_der().map_err(encoding("cRLNumber"))?)
                .map_err(encoding("cRLNumber"))?,
        },
    ];
    let revoked = request
        .revoked
        .iter()
        .map(revoked_cert)
        .collect::<Result<Vec<_>, _>>()?;
    let tbs = TbsCertList {
        version: Version::V2,
        signature: signature_algorithm(),
        issuer: Name::from_der(&issuer.subject_der).map_err(parsing("issuer name"))?,
        this_update: rfc5280_time(to_whole_seconds_utc(request.this_update)?)?,
        next_update: Some(rfc5280_time(to_whole_seconds_utc(request.next_update)?)?),
        // RFC 5280 section 5.1.2.6: absent, not empty, when nothing is revoked.
        revoked_certificates: (!revoked.is_empty()).then_some(revoked),
        crl_extensions: Some(extensions),
    };
    let tbs_der = tbs.to_der().map_err(encoding("TBSCertList"))?;
    let signature = signer.sign_sha384(&tbs_der)?;
    let list = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: signature_algorithm(),
        signature: BitString::from_bytes(&signature).map_err(encoding("signature"))?,
    };
    let der = list.to_der().map_err(encoding("CRL"))?;
    let info = parse_crl_der(&der)?;
    verify_crl_signature(&der, &issuer.spki_der)?;
    let pem = crl_der_to_pem(&der)?;
    Ok(IssuedCrl { der, pem, info })
}

/// The issuer's first, empty CRL: number 1, thisUpdate `now`, default nextUpdate
/// (FR-13 AC6).
pub fn first_crl(
    issuer_certificate_der: &[u8],
    now: OffsetDateTime,
    signer: &mut dyn Sha384Signer,
) -> Result<IssuedCrl, CrlError> {
    let (_, level) = issuer_of_crls(issuer_certificate_der)?;
    build_crl(
        &CrlRequest {
            issuer_certificate_der,
            crl_number: 1,
            this_update: now,
            next_update: default_crl_next_update(level, now)?,
            revoked: &[],
        },
        signer,
    )
}

fn successor(
    current_crl_der: &[u8],
    issuer_certificate_der: &[u8],
    now: OffsetDateTime,
) -> Result<(CrlInfo, CaLevel), CrlError> {
    let (issuer, level) = issuer_of_crls(issuer_certificate_der)?;
    let current = parse_crl_der(current_crl_der)?;
    if current.issuer_der != issuer.subject_der || current.authority_key_id != issuer.subject_key_id
    {
        return Err(CrlError::Request(
            "the current CRL was not issued by this issuer".into(),
        ));
    }
    verify_crl_signature(current_crl_der, &issuer.spki_der)?;
    if to_whole_seconds_utc(now)? < current.this_update {
        return Err(CrlError::Request(
            "the clock is earlier than the current CRL's thisUpdate; correct the clock".into(),
        ));
    }
    if current.crl_number == u64::MAX {
        return Err(CrlError::Request("CRL number space exhausted".into()));
    }
    Ok((current, level))
}

/// Refresh CRL (FR-13 AC4): re-signs the issuer's current CRL with the same revoked
/// entries, a new thisUpdate (`now`), the default nextUpdate and a CRL number one
/// higher.
pub fn refresh_crl(
    current_crl_der: &[u8],
    issuer_certificate_der: &[u8],
    now: OffsetDateTime,
    signer: &mut dyn Sha384Signer,
) -> Result<IssuedCrl, CrlError> {
    let (current, level) = successor(current_crl_der, issuer_certificate_der, now)?;
    build_crl(
        &CrlRequest {
            issuer_certificate_der,
            crl_number: current.crl_number + 1,
            this_update: now,
            next_update: default_crl_next_update(level, now)?,
            revoked: &current.revoked,
        },
        signer,
    )
}

/// Revocation (Flow D): the current CRL's entries plus `entry`, with a CRL number one
/// higher, thisUpdate `now` and the default nextUpdate (FR-13 AC1).
pub fn crl_with_revocation(
    current_crl_der: &[u8],
    issuer_certificate_der: &[u8],
    entry: RevokedEntry,
    now: OffsetDateTime,
    signer: &mut dyn Sha384Signer,
) -> Result<IssuedCrl, CrlError> {
    let (current, level) = successor(current_crl_der, issuer_certificate_der, now)?;
    if current
        .revoked
        .iter()
        .any(|existing| existing.serial == entry.serial)
    {
        return Err(CrlError::Request(format!(
            "serial {} is already revoked",
            entry.serial
        )));
    }
    let mut revoked = current.revoked.clone();
    revoked.push(entry);
    build_crl(
        &CrlRequest {
            issuer_certificate_der,
            crl_number: current.crl_number + 1,
            this_update: now,
            next_update: default_crl_next_update(level, now)?,
            revoked: &revoked,
        },
        signer,
    )
}

/// How close a CRL is to its nextUpdate (FR-13 AC3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlFreshness {
    /// More than 30 days left.
    Fresh,
    /// 30 days or less left: the GUI warns and offers Refresh CRL.
    RefreshSoon {
        /// Whole days left (rounded down).
        days_left: i64,
    },
    /// nextUpdate has passed: relying parties may reject certificates.
    Expired,
}

/// Classifies a CRL by its nextUpdate (FR-13 AC3: warn 30 days before).
pub fn crl_freshness(next_update: OffsetDateTime, now: OffsetDateTime) -> CrlFreshness {
    if now >= next_update {
        CrlFreshness::Expired
    } else if next_update - now <= Duration::days(CRL_WARNING_DAYS) {
        CrlFreshness::RefreshSoon {
            days_left: (next_update - now).whole_days(),
        }
    } else {
        CrlFreshness::Fresh
    }
}

/// True when the GUI must show the Refresh CRL warning (FR-13 AC3).
pub fn needs_refresh_warning(next_update: OffsetDateTime, now: OffsetDateTime) -> bool {
    crl_freshness(next_update, now) != CrlFreshness::Fresh
}

/// Parses a DER CRL; the size limit is checked first (SEC-08).
pub fn parse_crl_der(der: &[u8]) -> Result<CrlInfo, CrlError> {
    if der.len() > MAX_CRL_BYTES {
        return Err(CrlError::Crypto(
            crate::crypto::CryptoError::InputTooLarge {
                what: "CRL",
                limit: MAX_CRL_BYTES,
                actual: der.len(),
            },
        ));
    }
    let list = CertificateList::<x509_cert::certificate::Rfc5280>::from_der(der)
        .map_err(parsing("CRL"))?;
    if list.to_der().map_err(parsing("CRL"))? != der {
        return Err(CrlError::Parse("CRL is not in canonical DER".into()));
    }
    let tbs = &list.tbs_cert_list;
    let mut crl_number = None;
    let mut authority_key_id = None;
    for ext in tbs.crl_extensions.iter().flatten() {
        if ext.extn_id == CrlNumber::OID {
            let number =
                CrlNumber::from_der(ext.extn_value.as_bytes()).map_err(parsing("cRLNumber"))?;
            let bytes = number.0.as_bytes();
            if bytes.len() > 8 {
                return Err(CrlError::Parse("cRLNumber is out of range".into()));
            }
            crl_number = Some(bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)));
        } else if ext.extn_id == AuthorityKeyIdentifier::OID {
            let aki = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())
                .map_err(parsing("authorityKeyIdentifier"))?;
            authority_key_id = aki.key_identifier.map(|id| id.as_bytes().to_vec());
        } else if ext.critical {
            return Err(CrlError::Parse(format!(
                "unknown critical CRL extension {}",
                ext.extn_id
            )));
        }
    }
    let mut revoked = Vec::new();
    for cert in tbs.revoked_certificates.iter().flatten() {
        let serial = Serial::from_be_slice(cert.serial_number.as_bytes())
            .ok_or_else(|| CrlError::Parse("revoked serial is not a Keystone serial".into()))?;
        let mut reason = RevocationReason::Unspecified;
        for ext in cert.crl_entry_extensions.iter().flatten() {
            if ext.extn_id == CrlReason::OID {
                reason = revocation_reason(
                    CrlReason::from_der(ext.extn_value.as_bytes())
                        .map_err(parsing("reasonCode"))?,
                )?;
            } else if ext.critical {
                return Err(CrlError::Parse(
                    "unknown critical CRL entry extension".into(),
                ));
            }
        }
        revoked.push(RevokedEntry {
            serial,
            revocation_date: time_to_offset(&cert.revocation_date)?,
            reason,
        });
    }
    let next_update = tbs
        .next_update
        .as_ref()
        .ok_or_else(|| CrlError::Parse("nextUpdate is missing".into()))?;
    let null_params = list
        .signature_algorithm
        .parameters
        .as_ref()
        .is_some_and(|p| p.value().is_empty() && p.tag() == x509_cert::der::Tag::Null);
    Ok(CrlInfo {
        issuer: tbs.issuer.to_string(),
        issuer_der: tbs.issuer.to_der().map_err(parsing("issuer"))?,
        this_update: time_to_offset(&tbs.this_update)?,
        next_update: time_to_offset(next_update)?,
        crl_number: crl_number.ok_or_else(|| CrlError::Parse("cRLNumber is missing".into()))?,
        authority_key_id,
        revoked,
        fingerprint: sha256(der),
        signature_is_sha384_rsa: list.signature_algorithm == tbs.signature
            && list.signature_algorithm.oid == SHA384_WITH_RSA
            && null_params,
        version_raw: tbs.version as u8,
    })
}

/// Parses a PEM CRL (size limit first, SEC-08). Returns the DER and the facts.
pub fn parse_crl_pem(pem: &[u8]) -> Result<(Vec<u8>, CrlInfo), CrlError> {
    let der = crl_pem_to_der(pem)?;
    let info = parse_crl_der(&der)?;
    Ok((der, info))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> OffsetDateTime {
        OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).unwrap()
    }

    #[test]
    fn fr13_ac3_warns_30_days_before_next_update() {
        // Covers: FR-13 AC3
        let next = at("2027-01-31T00:00:00Z");
        assert_eq!(
            crl_freshness(next, at("2026-12-31T23:59:59Z")),
            CrlFreshness::Fresh
        );
        assert!(!needs_refresh_warning(next, at("2026-12-31T23:59:59Z")));
        assert_eq!(
            crl_freshness(next, at("2027-01-01T00:00:00Z")),
            CrlFreshness::RefreshSoon { days_left: 30 }
        );
        assert!(needs_refresh_warning(next, at("2027-01-01T00:00:00Z")));
        assert_eq!(
            crl_freshness(next, at("2027-01-30T12:00:00Z")),
            CrlFreshness::RefreshSoon { days_left: 0 }
        );
        assert_eq!(crl_freshness(next, next), CrlFreshness::Expired);
        assert!(needs_refresh_warning(next, at("2028-01-01T00:00:00Z")));
    }

    #[test]
    fn sec08_crl_parser_rejects_oversized_and_garbage() {
        // Covers: SEC-08
        assert!(matches!(
            parse_crl_der(&vec![0u8; MAX_CRL_BYTES + 1]),
            Err(CrlError::Crypto(
                crate::crypto::CryptoError::InputTooLarge { .. }
            ))
        ));
        assert!(parse_crl_der(&[0x30, 0x03, 0x02, 0x01, 0x01]).is_err());
        assert!(
            parse_crl_pem(b"-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n").is_err()
        );
    }
}
