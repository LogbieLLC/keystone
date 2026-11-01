//! DER building blocks shared by certificates and CRLs (RFC 5280).
//!
//! x509-cert 0.3.0 (default features off) has no public constructor for
//! `TbsCertificate`, so the outer SEQUENCEs are assembled here from x509-cert and
//! der component types, each encoded with `der`. The result is decoded again with
//! x509-cert's strict RFC 5280 parser before it is used (see `build.rs`).
#![forbid(unsafe_code)]

use std::time::Duration;

use time::OffsetDateTime;
use x509_cert::der::asn1::{Any, GeneralizedTime, Null, UtcTime};
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::oid::db::rfc4519;
use x509_cert::der::{DateTime, Encode, Tag, TagNumber};
use x509_cert::ext::Extension;
use x509_cert::name::{RdnSequence, RelativeDistinguishedName};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;

use super::CertError;
use crate::crypto::hash::sha1_for_key_identifier;
use crate::profile::{SIGNATURE_ALGORITHM_OID, ValidatedName};

/// sha384WithRSAEncryption (1.2.840.113549.1.1.12).
pub const SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap(SIGNATURE_ALGORITHM_OID);

pub(crate) fn der_error(context: &str) -> impl FnOnce(x509_cert::der::Error) -> CertError + '_ {
    move |error| CertError::Encoding(format!("{context}: {error}"))
}

/// The AlgorithmIdentifier for sha384WithRSAEncryption with NULL parameters
/// (RFC 4055 section 5).
pub fn signature_algorithm() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: SHA384_WITH_RSA,
        parameters: Some(Any::from(Null)),
    }
}

/// DER of the signature AlgorithmIdentifier.
pub(crate) fn signature_algorithm_der() -> Result<Vec<u8>, CertError> {
    signature_algorithm()
        .to_der()
        .map_err(der_error("signature algorithm"))
}

/// A time as RFC 5280 section 4.1.2.5 requires: UTCTime through 2049,
/// GeneralizedTime from 2050. Seconds precision, UTC ("Z").
pub fn rfc5280_time(value: OffsetDateTime) -> Result<Time, CertError> {
    let seconds = u64::try_from(value.unix_timestamp())
        .map_err(|_| CertError::Encoding("dates before 1970 are not supported".into()))?;
    let date_time =
        DateTime::from_unix_duration(Duration::from_secs(seconds)).map_err(der_error("date"))?;
    if date_time.year() < 2050 {
        Ok(Time::UtcTime(
            UtcTime::from_date_time(date_time).map_err(der_error("UTCTime"))?,
        ))
    } else {
        Ok(Time::GeneralTime(GeneralizedTime::from_date_time(
            date_time,
        )))
    }
}

/// Converts a decoded time back to `OffsetDateTime`.
pub fn time_to_offset(value: &Time) -> Result<OffsetDateTime, CertError> {
    let seconds = i64::try_from(value.to_unix_duration().as_secs())
        .map_err(|_| CertError::Parse("date out of range".into()))?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| CertError::Parse("date out of range".into()))
}

/// SEQUENCE { content }.
pub(crate) fn sequence(content: Vec<u8>) -> Result<Vec<u8>, CertError> {
    Any::new(Tag::Sequence, content)
        .map_err(der_error("sequence"))?
        .to_der()
        .map_err(der_error("sequence"))
}

/// [number] EXPLICIT { content } (content is already DER).
pub(crate) fn explicit(number: u32, content: Vec<u8>) -> Result<Vec<u8>, CertError> {
    let tag = Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(number),
    };
    Any::new(tag, content)
        .map_err(der_error("explicit tag"))?
        .to_der()
        .map_err(der_error("explicit tag"))
}

fn rdn(
    oid: ObjectIdentifier,
    tag: Tag,
    value: &str,
) -> Result<RelativeDistinguishedName, CertError> {
    let value = Any::new(tag, value.as_bytes()).map_err(der_error("name attribute"))?;
    RelativeDistinguishedName::try_from(vec![x509_cert::attr::AttributeTypeAndValue { oid, value }])
        .map_err(der_error("name attribute"))
}

/// The DER `Name` for validated name fields, in the order C, O, CN, with
/// PrintableString for C and UTF8String for O and CN (one attribute per RDN).
pub fn name_der(name: &ValidatedName) -> Result<Vec<u8>, CertError> {
    let mut rdns = Vec::with_capacity(3);
    if let Some(country) = name.country() {
        rdns.push(rdn(rfc4519::COUNTRY_NAME, Tag::PrintableString, country)?);
    }
    if let Some(organization) = name.organization() {
        rdns.push(rdn(
            rfc4519::ORGANIZATION_NAME,
            Tag::Utf8String,
            organization,
        )?);
    }
    rdns.push(rdn(
        rfc4519::COMMON_NAME,
        Tag::Utf8String,
        name.common_name(),
    )?);
    RdnSequence::from(rdns).to_der().map_err(der_error("name"))
}

/// One extension with its value already DER-encoded.
pub(crate) fn extension(
    oid: ObjectIdentifier,
    critical: bool,
    value_der: Vec<u8>,
) -> Result<Extension, CertError> {
    Ok(Extension {
        extn_id: oid,
        critical,
        extn_value: x509_cert::der::asn1::OctetString::new(value_der)
            .map_err(der_error("extension value"))?,
    })
}

/// RFC 5280 section 4.2.1.2 method (1): SHA-1 of the subjectPublicKey BIT STRING
/// value (without tag, length and unused-bits byte).
pub fn key_identifier(spki_der: &[u8]) -> Result<[u8; 20], CertError> {
    use x509_cert::der::Decode;
    let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(|e| CertError::Parse(format!("public key: {e}")))?;
    let bits = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| CertError::Parse("public key bit string has unused bits".into()))?;
    Ok(sha1_for_key_identifier(bits))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> OffsetDateTime {
        OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).unwrap()
    }

    #[test]
    fn fr10_rfc5280_time_switches_to_generalized_time_in_2050() {
        // Covers: FR-10 AC3, SEC-13
        let utc = rfc5280_time(at("2049-12-31T23:59:59Z")).unwrap();
        assert!(matches!(utc, Time::UtcTime(_)));
        assert_eq!(utc.to_der().unwrap()[0], 0x17);
        let general = rfc5280_time(at("2050-01-01T00:00:00Z")).unwrap();
        assert!(matches!(general, Time::GeneralTime(_)));
        assert_eq!(general.to_der().unwrap()[0], 0x18);
        assert_eq!(
            time_to_offset(&general).unwrap(),
            at("2050-01-01T00:00:00Z")
        );
        assert!(rfc5280_time(at("1969-12-31T23:59:59Z")).is_err());
    }

    #[test]
    fn signature_algorithm_has_null_parameters() {
        // Covers: FR-02 AC2
        assert_eq!(
            signature_algorithm_der().unwrap(),
            [
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05,
                0x00
            ]
        );
    }

    #[test]
    fn fr02_ac4_name_order_and_string_types() {
        // Covers: FR-02 AC4
        let name = ValidatedName::new(&crate::model::NameFields {
            common_name: "KEYSTONE TEST Root".into(),
            organization: Some("Org".into()),
            country: Some("us".into()),
        })
        .unwrap();
        let der = name_der(&name).unwrap();
        // C (2.5.4.6) PrintableString first, then O (2.5.4.10) UTF8String, then CN (2.5.4.3) UTF8String.
        let c = der
            .windows(5)
            .position(|w| w == [0x55, 0x04, 0x06, 0x13, 0x02])
            .unwrap();
        let o = der
            .windows(4)
            .position(|w| w == [0x55, 0x04, 0x0a, 0x0c])
            .unwrap();
        let cn = der
            .windows(4)
            .position(|w| w == [0x55, 0x04, 0x03, 0x0c])
            .unwrap();
        assert!(c < o && o < cn);
        assert!(der.windows(2).any(|w| w == b"US"));
    }
}
