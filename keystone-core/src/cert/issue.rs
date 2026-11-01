//! Building and signing CA certificates exactly per the fixed profile
//! (FR-02 AC2-AC4, FR-07 AC2, FR-08 AC2, FR-10, FR-18, FR-21 AC2-AC3).
//!
//! Only CA certificates for the three levels can be built here. Leaf (end-entity)
//! certificates are a version 1 non-goal and cannot be produced by this crate.
#![forbid(unsafe_code)]

use x509_cert::der::Encode;
use x509_cert::der::asn1::{BitString, Ia5String, OctetString};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, CrlDistributionPoints, KeyUsage, KeyUsages,
    NameConstraints, SubjectKeyIdentifier,
};
use x509_cert::serial_number::SerialNumber;

use super::encode::{
    explicit, extension, key_identifier, name_der, rfc5280_time, sequence, signature_algorithm_der,
};
use super::parse::{CertificateInfo, parse_certificate_der};
use super::signer::Sha384Signer;
use super::{CertError, encode::der_error};
use crate::crypto::rsa::inspect_rsa_spki;
use crate::crypto::verify::{certificate_der_to_pem, verify_certificate_signature};
use crate::model::{CaLevel, Serial};
use crate::profile::{
    CertValidity, CrlLocation, NameConstraintsChoice, NameConstraintsSpec, PUBLIC_EXPONENT,
    ValidatedName, level_profile,
};

/// Most attempts to find an unused random serial before giving up.
pub const MAX_SERIAL_ATTEMPTS: usize = 32;

/// A serial number that was checked against every known history (FR-10 AC2).
///
/// Created by [`plan_serial`], which asks the caller's hook whether a candidate was
/// ever seen, or by [`PlannedSerial::from_reserved`] when resuming an operation
/// whose journal entry already reserved the serial (FR-22 AC1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedSerial(Serial);

impl PlannedSerial {
    /// The serial.
    pub fn serial(&self) -> Serial {
        self.0
    }

    /// A serial that a pending journal entry already reserved for this same
    /// operation (recovery after a restart). Do not use for new operations.
    pub fn from_reserved(serial: Serial) -> Self {
        PlannedSerial(serial)
    }
}

/// Draws random 159-bit serials (`crypto::rand::random_serial`) until `is_known`
/// says one was never seen in any issuance record or journal on any drive
/// (FR-10 AC2). The caller records the result in its pending journal entry before
/// signing.
pub fn plan_serial(is_known: &mut dyn FnMut(&Serial) -> bool) -> Result<PlannedSerial, CertError> {
    for _ in 0..MAX_SERIAL_ATTEMPTS {
        let candidate = crate::crypto::rand::random_serial()?;
        if !is_known(&candidate) {
            return Ok(PlannedSerial(candidate));
        }
    }
    Err(CertError::SerialSpaceExhausted)
}

/// The issuer of a new certificate.
#[derive(Debug, Clone, Copy)]
pub enum Issuer<'a> {
    /// The master signs itself.
    SelfSigned,
    /// An existing CA certificate (DER) of the issuing level.
    Certificate(&'a [u8]),
}

/// What to certify. Every field is an already-validated profile type, so nothing
/// structural can be chosen here (FR-10 AC3).
#[derive(Debug, Clone)]
pub struct CaCertificateRequest<'a> {
    /// Level of the new certificate.
    pub level: CaLevel,
    /// Subject name (FR-02 AC4).
    pub subject: &'a ValidatedName,
    /// The new CA's public key as DER SubjectPublicKeyInfo.
    pub subject_public_key_der: &'a [u8],
    /// Validity planned for this level (FR-10 AC1, AC3).
    pub validity: CertValidity,
    /// Serial checked for uniqueness (FR-10 AC2).
    pub serial: PlannedSerial,
    /// Who signs.
    pub issuer: Issuer<'a>,
    /// Where the issuer's CRL is hosted (FR-18). Required for intermediates,
    /// `None` for the master.
    pub issuer_crl: Option<&'a CrlLocation>,
    /// Name constraints (FR-21). Required for sub-intermediates, `None` otherwise.
    pub name_constraints: Option<&'a NameConstraintsChoice>,
}

/// A signed certificate, verified with OpenSSL against the issuer's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCertificate {
    /// DER encoding.
    pub der: Vec<u8>,
    /// PEM encoding (`CERTIFICATE`).
    pub pem: String,
    /// Parsed facts (serial, names, validity, fingerprint, ...).
    pub info: CertificateInfo,
}

fn check_request(
    request: &CaCertificateRequest<'_>,
    issuer: Option<&CertificateInfo>,
    subject_der: &[u8],
) -> Result<(), CertError> {
    let profile = level_profile(request.level);
    let key = inspect_rsa_spki(request.subject_public_key_der)?;
    if key.bits != profile.key_bits {
        return Err(CertError::WrongKeySize {
            level: request.level.display_name(),
            expected: profile.key_bits,
            actual: key.bits,
        });
    }
    if key.public_exponent != PUBLIC_EXPONENT {
        return Err(CertError::WrongExponent(key.public_exponent));
    }
    if request.validity.level() != request.level {
        return Err(CertError::Profile(
            crate::profile::ProfileError::IssuerMismatch(
                "the validity was planned for a different level",
            ),
        ));
    }
    match (request.level.issuer_level(), issuer) {
        (None, None) => {
            if request.issuer_crl.is_some() {
                return Err(CertError::Request(
                    "the master carries no CRL address; give it to its children".into(),
                ));
            }
        }
        (Some(expected), Some(issuer)) => {
            if issuer.ca_level() != Some(expected) {
                return Err(CertError::Request(format!(
                    "a {} must be signed by the {}",
                    request.level.display_name(),
                    expected.display_name()
                )));
            }
            if issuer.subject_der == subject_der {
                return Err(CertError::Request(
                    "the subject name must differ from the issuer's name".into(),
                ));
            }
            if request.validity.not_after() > issuer.not_after {
                return Err(CertError::Profile(
                    crate::profile::ProfileError::OutlivesIssuer {
                        not_after: request.validity.not_after().to_string(),
                        issuer_not_after: issuer.not_after.to_string(),
                        max_years: 0,
                    },
                ));
            }
            if request.validity.not_before() < issuer.not_before {
                return Err(CertError::Request(
                    "the certificate would start before its issuer; check the clock".into(),
                ));
            }
            if issuer.subject_key_id.is_none() {
                return Err(CertError::Request(
                    "the issuer certificate has no subjectKeyIdentifier".into(),
                ));
            }
            if request.issuer_crl.is_none() {
                return Err(CertError::Request(
                    "choose the issuer's CRL address, or explicitly choose none (FR-18)".into(),
                ));
            }
        }
        (None, Some(_)) => {
            return Err(CertError::Request("the master must be self-signed".into()));
        }
        (Some(_), None) => {
            return Err(CertError::Request(
                "an intermediate needs its issuer's certificate".into(),
            ));
        }
    }
    match (profile.name_constraints, request.name_constraints) {
        (true, None) => Err(CertError::Profile(
            crate::profile::ProfileError::NameConstraintsRequired,
        )),
        (false, Some(_)) => Err(CertError::Profile(
            crate::profile::ProfileError::NameConstraintsNotAllowed,
        )),
        _ => Ok(()),
    }
}

fn ia5(text: &str) -> Result<Ia5String, CertError> {
    Ia5String::new(text).map_err(der_error("IA5String"))
}

fn subtree(base: GeneralName) -> GeneralSubtree {
    GeneralSubtree {
        base,
        minimum: 0,
        maximum: None,
    }
}

fn ip_name(bytes: Vec<u8>) -> Result<GeneralName, CertError> {
    Ok(GeneralName::IpAddress(
        OctetString::new(bytes).map_err(der_error("iPAddress"))?,
    ))
}

/// The nameConstraints value for a sub-intermediate (FR-21 AC2, AC3).
fn name_constraints_value(spec: &NameConstraintsSpec) -> Result<NameConstraints, CertError> {
    let mut permitted = Vec::new();
    for name in spec.permitted_dns() {
        permitted.push(subtree(GeneralName::DnsName(ia5(name.as_str())?)));
    }
    for range in spec.permitted_ip() {
        permitted.push(subtree(ip_name(range.constraint_bytes())?));
    }
    let mut excluded = Vec::new();
    if spec.excludes_all_ipv4() {
        excluded.push(subtree(ip_name(vec![0; 8])?));
    }
    if spec.excludes_all_ipv6() {
        excluded.push(subtree(ip_name(vec![0; 32])?));
    }
    excluded.push(subtree(GeneralName::Rfc822Name(ia5("")?)));
    excluded.push(subtree(GeneralName::UniformResourceIdentifier(ia5("")?)));
    Ok(NameConstraints {
        permitted_subtrees: Some(permitted),
        excluded_subtrees: Some(excluded),
    })
}

fn extensions_der(
    request: &CaCertificateRequest<'_>,
    issuer: Option<&CertificateInfo>,
) -> Result<Vec<u8>, CertError> {
    let profile = level_profile(request.level);
    let mut extensions = Vec::new();
    let basic = BasicConstraints {
        ca: true,
        path_len_constraint: profile.path_len_constraint,
    };
    extensions.push(extension(
        BasicConstraints::OID,
        true,
        basic.to_der().map_err(der_error("basicConstraints"))?,
    )?);
    let usage = KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign);
    extensions.push(extension(
        KeyUsage::OID,
        true,
        usage.to_der().map_err(der_error("keyUsage"))?,
    )?);
    let ski = key_identifier(request.subject_public_key_der)?;
    let ski = SubjectKeyIdentifier(OctetString::new(ski.to_vec()).map_err(der_error("SKI"))?);
    extensions.push(extension(
        SubjectKeyIdentifier::OID,
        false,
        ski.to_der().map_err(der_error("subjectKeyIdentifier"))?,
    )?);
    if let Some(issuer) = issuer {
        let issuer_ski = issuer.subject_key_id.clone().unwrap_or_default();
        let aki = AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(issuer_ski).map_err(der_error("AKI"))?),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };
        extensions.push(extension(
            AuthorityKeyIdentifier::OID,
            false,
            aki.to_der().map_err(der_error("authorityKeyIdentifier"))?,
        )?);
    }
    if let Some(CrlLocation::Url(url)) = request.issuer_crl {
        let points = CrlDistributionPoints(vec![DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![
                GeneralName::UniformResourceIdentifier(ia5(url.as_str())?),
            ])),
            reasons: None,
            crl_issuer: None,
        }]);
        extensions.push(extension(
            CrlDistributionPoints::OID,
            false,
            points
                .to_der()
                .map_err(der_error("cRLDistributionPoints"))?,
        )?);
    }
    if let Some(NameConstraintsChoice::Constrained(spec)) = request.name_constraints {
        let value = name_constraints_value(spec)?;
        extensions.push(extension(
            NameConstraints::OID,
            true,
            value.to_der().map_err(der_error("nameConstraints"))?,
        )?);
    }
    extensions.to_der().map_err(der_error("extensions"))
}

/// Builds, signs and verifies a CA certificate.
///
/// Before signing: the request is checked against the fixed profile and the
/// issuer (key size and exponent, issuer level, validity inside the issuer's,
/// subject differs from issuer, CRL address and name-constraints choices present
/// where required), and the signer's public key must be the issuer's.
/// After signing: the certificate is decoded with x509-cert's strict parser and its
/// signature is verified with OpenSSL against the issuer's public key; only then is
/// it returned.
pub fn issue_ca_certificate(
    request: &CaCertificateRequest<'_>,
    signer: &mut dyn Sha384Signer,
) -> Result<IssuedCertificate, CertError> {
    let issuer_info = match request.issuer {
        Issuer::SelfSigned => None,
        Issuer::Certificate(der) => Some(parse_certificate_der(der)?),
    };
    let subject_der = name_der(request.subject)?;
    check_request(request, issuer_info.as_ref(), &subject_der)?;
    let (issuer_name_der, issuer_spki) = match &issuer_info {
        None => (subject_der.clone(), request.subject_public_key_der.to_vec()),
        Some(info) => (info.issuer_name_for_children(), info.spki_der.clone()),
    };
    if signer.signer_public_key_der()? != issuer_spki {
        return Err(CertError::SignerKeyMismatch);
    }

    let mut tbs = explicit(0, 2u8.to_der().map_err(der_error("version"))?)?;
    let serial =
        SerialNumber::<x509_cert::certificate::Rfc5280>::new(request.serial.serial().as_bytes())
            .map_err(der_error("serial"))?;
    tbs.extend(serial.to_der().map_err(der_error("serial"))?);
    tbs.extend(signature_algorithm_der()?);
    tbs.extend(issuer_name_der);
    let mut validity = rfc5280_time(request.validity.not_before())?
        .to_der()
        .map_err(der_error("notBefore"))?;
    validity.extend(
        rfc5280_time(request.validity.not_after())?
            .to_der()
            .map_err(der_error("notAfter"))?,
    );
    tbs.extend(sequence(validity)?);
    tbs.extend(subject_der);
    tbs.extend_from_slice(request.subject_public_key_der);
    tbs.extend(explicit(3, extensions_der(request, issuer_info.as_ref())?)?);
    let tbs = sequence(tbs)?;

    let signature = signer.sign_sha384(&tbs)?;
    let mut cert = tbs;
    cert.extend(signature_algorithm_der()?);
    cert.extend(
        BitString::from_bytes(&signature)
            .map_err(der_error("signature"))?
            .to_der()
            .map_err(der_error("signature"))?,
    );
    let der = sequence(cert)?;

    let info = parse_certificate_der(&der)?;
    verify_certificate_signature(&der, &issuer_spki)?;
    if info.serial != request.serial.serial() {
        return Err(CertError::Encoding("serial changed during encoding".into()));
    }
    let pem = certificate_der_to_pem(&der)?;
    Ok(IssuedCertificate { der, pem, info })
}

impl CertificateInfo {
    /// The DER Name children of this CA carry as their issuer: exactly this
    /// certificate's subject bytes.
    fn issuer_name_for_children(&self) -> Vec<u8> {
        self.subject_der.clone()
    }
}
