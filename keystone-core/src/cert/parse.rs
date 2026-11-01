//! Certificate parsing with strict size limits (SEC-08).
#![forbid(unsafe_code)]

use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode, Tagged};
use x509_cert::ext::pkix::name::DistributionPointName;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, CrlDistributionPoints, KeyUsage, KeyUsages,
    NameConstraints, SubjectKeyIdentifier,
};

use super::CertError;
use super::encode::{SHA384_WITH_RSA, time_to_offset};
use crate::crypto::hash::sha256;
use crate::crypto::verify::certificate_pem_to_der;
use crate::limits::MAX_CERT_DER_BYTES;
use crate::model::{CaLevel, Fingerprint, Serial};

/// basicConstraints as found in a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicConstraintsInfo {
    /// Whether the extension is critical.
    pub critical: bool,
    /// cA flag.
    pub ca: bool,
    /// pathLenConstraint.
    pub path_len: Option<u8>,
}

/// keyUsage as found in a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsageInfo {
    /// Whether the extension is critical.
    pub critical: bool,
    /// keyCertSign.
    pub key_cert_sign: bool,
    /// cRLSign.
    pub crl_sign: bool,
    /// True when any other bit is set.
    pub other_bits: bool,
}

/// One name in a name-constraints subtree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintName {
    /// dNSName.
    Dns(String),
    /// iPAddress: address followed by mask.
    Ip(Vec<u8>),
    /// rfc822Name (empty = all email).
    Email(String),
    /// uniformResourceIdentifier (empty = all URIs).
    Uri(String),
    /// Any other name form.
    Other,
}

/// nameConstraints as found in a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameConstraintsInfo {
    /// Whether the extension is critical.
    pub critical: bool,
    /// permittedSubtrees bases.
    pub permitted: Vec<ConstraintName>,
    /// excludedSubtrees bases.
    pub excluded: Vec<ConstraintName>,
}

/// The facts Keystone records and checks about a certificate (FR-11 AC1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    /// X.509 version number as written (2 = v3).
    pub version_raw: u8,
    /// Serial number.
    pub serial: Serial,
    /// Subject as RFC 4514 text.
    pub subject: String,
    /// Issuer as RFC 4514 text.
    pub issuer: String,
    /// Subject Common Name, if present and a string.
    pub subject_common_name: Option<String>,
    /// DER of the subject Name.
    pub subject_der: Vec<u8>,
    /// DER of the issuer Name.
    pub issuer_der: Vec<u8>,
    /// Start of validity.
    pub not_before: OffsetDateTime,
    /// End of validity.
    pub not_after: OffsetDateTime,
    /// SHA-256 of the DER certificate (FR-20, SEC-10).
    pub fingerprint: Fingerprint,
    /// DER SubjectPublicKeyInfo.
    pub spki_der: Vec<u8>,
    /// OID of the signature algorithm (outer and inner must agree).
    pub signature_algorithm_oid: String,
    /// True when the signature algorithm is sha384WithRSAEncryption with NULL parameters.
    pub signature_is_sha384_rsa: bool,
    /// subjectKeyIdentifier.
    pub subject_key_id: Option<Vec<u8>>,
    /// authorityKeyIdentifier keyIdentifier.
    pub authority_key_id: Option<Vec<u8>>,
    /// basicConstraints.
    pub basic_constraints: Option<BasicConstraintsInfo>,
    /// keyUsage.
    pub key_usage: Option<KeyUsageInfo>,
    /// URIs from cRLDistributionPoints.
    pub crl_distribution_urls: Vec<String>,
    /// Whether cRLDistributionPoints is present.
    pub has_crl_distribution_points: bool,
    /// nameConstraints.
    pub name_constraints: Option<NameConstraintsInfo>,
    /// OIDs of every extension, in order.
    pub extension_oids: Vec<String>,
}

impl CertificateInfo {
    /// True when subject and issuer are the same name (the master).
    pub fn is_self_issued(&self) -> bool {
        self.subject_der == self.issuer_der
    }

    /// The CA level this certificate's structure matches, judged by basicConstraints
    /// and self-issuance (master: self-issued, no path length; main: path length 1;
    /// sub: path length 0). `None` for anything else, such as a leaf.
    pub fn ca_level(&self) -> Option<CaLevel> {
        let bc = self.basic_constraints?;
        if !bc.ca {
            return None;
        }
        match (self.is_self_issued(), bc.path_len) {
            (true, None) => Some(CaLevel::Master),
            (false, Some(1)) => Some(CaLevel::MainIntermediate),
            (false, Some(0)) => Some(CaLevel::SubIntermediate),
            _ => None,
        }
    }
}

fn general_name(name: &GeneralName) -> ConstraintName {
    match name {
        GeneralName::DnsName(value) => ConstraintName::Dns(value.to_string()),
        GeneralName::IpAddress(value) => ConstraintName::Ip(value.as_bytes().to_vec()),
        GeneralName::Rfc822Name(value) => ConstraintName::Email(value.to_string()),
        GeneralName::UniformResourceIdentifier(value) => ConstraintName::Uri(value.to_string()),
        _ => ConstraintName::Other,
    }
}

fn parse_error(context: &str) -> impl FnOnce(x509_cert::der::Error) -> CertError + '_ {
    move |error| CertError::Parse(format!("{context}: {error}"))
}

/// Parses a DER certificate. The size limit is checked first (SEC-08); the parser
/// is x509-cert's strict DER/RFC 5280 decoder, and the encoding must be canonical.
pub fn parse_certificate_der(der: &[u8]) -> Result<CertificateInfo, CertError> {
    if der.len() > MAX_CERT_DER_BYTES {
        return Err(CertError::Crypto(
            crate::crypto::CryptoError::InputTooLarge {
                what: "certificate",
                limit: MAX_CERT_DER_BYTES,
                actual: der.len(),
            },
        ));
    }
    let cert = Certificate::from_der(der).map_err(parse_error("certificate"))?;
    if cert.to_der().map_err(parse_error("certificate"))? != der {
        return Err(CertError::Parse(
            "certificate is not in canonical DER".into(),
        ));
    }
    let tbs = cert.tbs_certificate();
    let serial = Serial::from_be_slice(tbs.serial_number().as_bytes())
        .ok_or_else(|| CertError::Parse("serial number is not a positive 20-byte value".into()))?;
    let validity = tbs.validity();
    let outer = cert.signature_algorithm();
    let inner = tbs.signature();
    if outer != inner {
        return Err(CertError::Parse(
            "inner and outer signature algorithms differ".into(),
        ));
    }
    let null_params = outer
        .parameters
        .as_ref()
        .is_some_and(|p| p.tag() == x509_cert::der::Tag::Null && p.value().is_empty());
    let subject_key_id = tbs
        .get_extension::<SubjectKeyIdentifier>()
        .map_err(parse_error("subjectKeyIdentifier"))?
        .map(|(_, ski)| ski.0.as_bytes().to_vec());
    let authority_key_id = tbs
        .get_extension::<AuthorityKeyIdentifier>()
        .map_err(parse_error("authorityKeyIdentifier"))?
        .and_then(|(_, aki)| aki.key_identifier.map(|id| id.as_bytes().to_vec()));
    let basic_constraints = tbs
        .get_extension::<BasicConstraints>()
        .map_err(parse_error("basicConstraints"))?
        .map(|(critical, bc)| BasicConstraintsInfo {
            critical,
            ca: bc.ca,
            path_len: bc.path_len_constraint,
        });
    let key_usage = tbs
        .get_extension::<KeyUsage>()
        .map_err(parse_error("keyUsage"))?
        .map(|(critical, ku)| {
            let flags = ku.0;
            let known = KeyUsages::KeyCertSign | KeyUsages::CRLSign;
            KeyUsageInfo {
                critical,
                key_cert_sign: flags.contains(KeyUsages::KeyCertSign),
                crl_sign: flags.contains(KeyUsages::CRLSign),
                other_bits: !(flags & !known).is_empty(),
            }
        });
    let cdp = tbs
        .get_extension::<CrlDistributionPoints>()
        .map_err(parse_error("cRLDistributionPoints"))?;
    let has_crl_distribution_points = cdp.is_some();
    let mut crl_distribution_urls = Vec::new();
    for point in cdp.map(|(_, c)| c.0).unwrap_or_default() {
        if let Some(DistributionPointName::FullName(names)) = point.distribution_point {
            for name in names {
                if let GeneralName::UniformResourceIdentifier(uri) = name {
                    crl_distribution_urls.push(uri.to_string());
                }
            }
        }
    }
    let name_constraints = tbs
        .get_extension::<NameConstraints>()
        .map_err(parse_error("nameConstraints"))?
        .map(|(critical, nc)| NameConstraintsInfo {
            critical,
            permitted: nc
                .permitted_subtrees
                .unwrap_or_default()
                .iter()
                .map(|subtree| general_name(&subtree.base))
                .collect(),
            excluded: nc
                .excluded_subtrees
                .unwrap_or_default()
                .iter()
                .map(|subtree| general_name(&subtree.base))
                .collect(),
        });
    let subject_common_name = tbs.subject().common_name().ok().flatten().map(String::from);
    Ok(CertificateInfo {
        version_raw: tbs.version() as u8,
        serial,
        subject: tbs.subject().to_string(),
        issuer: tbs.issuer().to_string(),
        subject_common_name,
        subject_der: tbs.subject().to_der().map_err(parse_error("subject"))?,
        issuer_der: tbs.issuer().to_der().map_err(parse_error("issuer"))?,
        not_before: time_to_offset(&validity.not_before)?,
        not_after: time_to_offset(&validity.not_after)?,
        fingerprint: sha256(der),
        spki_der: tbs
            .subject_public_key_info()
            .to_der()
            .map_err(parse_error("public key"))?,
        signature_algorithm_oid: outer.oid.to_string(),
        signature_is_sha384_rsa: outer.oid == SHA384_WITH_RSA && null_params,
        subject_key_id,
        authority_key_id,
        basic_constraints,
        key_usage,
        crl_distribution_urls,
        has_crl_distribution_points,
        name_constraints,
        extension_oids: tbs
            .extensions()
            .map(|exts| exts.iter().map(|e| e.extn_id.to_string()).collect())
            .unwrap_or_default(),
    })
}

/// Parses one PEM certificate (size limit first, SEC-08). Returns the DER and the
/// parsed facts.
pub fn parse_certificate_pem(pem: &[u8]) -> Result<(Vec<u8>, CertificateInfo), CertError> {
    let der = certificate_pem_to_der(pem)?;
    let info = parse_certificate_der(&der)?;
    Ok((der, info))
}
