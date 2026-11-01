//! Test-only certificate and CRL assembly with x509-cert, signed through Keystone's
//! crypto API.
//!
//! keystone-core can build only the three CA certificate levels (leaf issuance is a
//! version 1 non-goal), so the certificates tests need besides those (the
//! simulator's attestation hierarchy, test leaves, a sub-intermediate's own leaf
//! CRL) are assembled here. Every Common Name contains `KEYSTONE TEST` (TEST-11).
#![forbid(unsafe_code)]

use core::net::IpAddr;

use keystone_core::cert::encode::{key_identifier, rfc5280_time, signature_algorithm};
use keystone_core::cert::parse_certificate_der;
use keystone_core::crypto::RsaPrivateKey;
use keystone_core::crypto::rand::random_serial;
use keystone_core::model::Serial;
use time::{Duration, OffsetDateTime};
use x509_cert::Version;
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::der::asn1::{Any, BitString, Ia5String, ObjectIdentifier, OctetString, Uint};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::oid::db::{rfc4519, rfc5280};
use x509_cert::der::{Decode, Encode, Tag, TagNumber};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, CrlNumber, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;

use crate::TEST_CN_MARKER;

fn seq(content: Vec<u8>) -> Vec<u8> {
    Any::new(Tag::Sequence, content)
        .and_then(|any| any.to_der())
        .expect("DER sequence")
}

fn explicit(number: u32, content: Vec<u8>) -> Vec<u8> {
    let tag = Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(number),
    };
    Any::new(tag, content)
        .and_then(|any| any.to_der())
        .expect("DER explicit tag")
}

/// DER Name with a single UTF8String Common Name. Panics unless the CN carries
/// `KEYSTONE TEST` (TEST-11).
pub fn cn_name_der(common_name: &str) -> Vec<u8> {
    assert!(
        common_name.contains(TEST_CN_MARKER),
        "test CN {common_name:?} must contain {TEST_CN_MARKER:?}"
    );
    let value = Any::new(Tag::Utf8String, common_name.as_bytes()).expect("CN");
    let rdn = RelativeDistinguishedName::try_from(vec![x509_cert::attr::AttributeTypeAndValue {
        oid: rfc4519::COMMON_NAME,
        value,
    }])
    .expect("RDN");
    RdnSequence::from(vec![rdn]).to_der().expect("name")
}

/// An extension with a DER value.
pub fn extension(oid: ObjectIdentifier, critical: bool, value_der: Vec<u8>) -> Extension {
    Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value_der).expect("extension value"),
    }
}

/// An extension whose value is raw bytes (as Yubico's 3.3 and 3.8 extensions are).
pub fn raw_extension(oid: &str, value: Vec<u8>) -> Extension {
    extension(ObjectIdentifier::new_unwrap(oid), false, value)
}

/// Who signs a test certificate.
#[derive(Debug, Clone, Copy)]
pub struct TestIssuer<'a> {
    /// DER of the issuer's subject Name.
    pub name_der: &'a [u8],
    /// The issuer's key.
    pub key: &'a RsaPrivateKey,
}

/// A test certificate to build.
#[derive(Debug, Clone)]
pub struct TestCertSpec<'a> {
    /// DER subject Name.
    pub subject_der: Vec<u8>,
    /// DER SubjectPublicKeyInfo.
    pub subject_public_key_der: Vec<u8>,
    /// Issuer; `None` for self-signed with `self_key`.
    pub issuer: Option<TestIssuer<'a>>,
    /// The subject's own key, used when self-signed.
    pub self_key: Option<&'a RsaPrivateKey>,
    /// Validity.
    pub not_before: OffsetDateTime,
    /// Validity.
    pub not_after: OffsetDateTime,
    /// Extensions in order.
    pub extensions: Vec<Extension>,
}

/// Assembles, signs (sha384WithRSAEncryption) and returns a DER certificate.
pub fn build_test_certificate(spec: &TestCertSpec<'_>) -> Vec<u8> {
    let serial: Serial = random_serial().expect("random serial");
    let (issuer_name, key) = match (&spec.issuer, spec.self_key) {
        (Some(issuer), _) => (issuer.name_der.to_vec(), issuer.key),
        (None, Some(key)) => (spec.subject_der.clone(), key),
        (None, None) => panic!("a self-signed test certificate needs self_key"),
    };
    let mut tbs = explicit(0, 2u8.to_der().expect("version"));
    tbs.extend(
        SerialNumber::<x509_cert::certificate::Rfc5280>::new(serial.as_bytes())
            .and_then(|s| s.to_der())
            .expect("serial"),
    );
    tbs.extend(signature_algorithm().to_der().expect("algorithm"));
    tbs.extend(issuer_name);
    let mut validity = rfc5280_time(spec.not_before)
        .expect("time")
        .to_der()
        .expect("time");
    validity.extend(
        rfc5280_time(spec.not_after)
            .expect("time")
            .to_der()
            .expect("time"),
    );
    tbs.extend(seq(validity));
    tbs.extend(spec.subject_der.clone());
    tbs.extend(spec.subject_public_key_der.clone());
    if !spec.extensions.is_empty() {
        tbs.extend(explicit(3, spec.extensions.to_der().expect("extensions")));
    }
    let tbs = seq(tbs);
    let signature = key.sign_sha384_pkcs1(&tbs).expect("test signature");
    let mut cert = tbs;
    cert.extend(signature_algorithm().to_der().expect("algorithm"));
    cert.extend(
        BitString::from_bytes(&signature)
            .and_then(|b| b.to_der())
            .expect("signature"),
    );
    seq(cert)
}

/// basicConstraints, keyUsage and subjectKeyIdentifier for a test CA.
pub fn test_ca_extensions(subject_public_key_der: &[u8], path_len: Option<u8>) -> Vec<Extension> {
    vec![
        extension(
            BasicConstraints::OID,
            true,
            BasicConstraints {
                ca: true,
                path_len_constraint: path_len,
            }
            .to_der()
            .expect("bc"),
        ),
        extension(
            KeyUsage::OID,
            true,
            KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                .to_der()
                .expect("ku"),
        ),
        extension(
            SubjectKeyIdentifier::OID,
            false,
            SubjectKeyIdentifier(
                OctetString::new(
                    key_identifier(subject_public_key_der)
                        .expect("ski")
                        .to_vec(),
                )
                .expect("ski"),
            )
            .to_der()
            .expect("ski"),
        ),
    ]
}

fn aki_extension(issuer_cert_der: &[u8]) -> Extension {
    let issuer = parse_certificate_der(issuer_cert_der).expect("issuer certificate");
    let id = issuer.subject_key_id.expect("issuer SKI");
    extension(
        AuthorityKeyIdentifier::OID,
        false,
        AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(id).expect("aki")),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        }
        .to_der()
        .expect("aki"),
    )
}

/// A test TLS server leaf (FR-21 AC5): CN `KEYSTONE TEST leaf`, the given DNS and
/// IP subject alternative names, serverAuth, valid from an hour ago for 90 days,
/// signed by `issuer_key` under `issuer_cert_der`. Leaf issuance exists only here,
/// in the test kit, never in keystone-core.
pub fn issue_test_leaf(
    issuer_cert_der: &[u8],
    issuer_key: &RsaPrivateKey,
    leaf_key: &RsaPrivateKey,
    dns_names: &[&str],
    ips: &[IpAddr],
) -> Vec<u8> {
    let issuer = parse_certificate_der(issuer_cert_der).expect("issuer certificate");
    let spki = leaf_key.public_key_spki_der().expect("leaf key");
    let mut names: Vec<GeneralName> = dns_names
        .iter()
        .map(|name| GeneralName::DnsName(Ia5String::new(name).expect("dns name")))
        .collect();
    names.extend(ips.iter().map(|ip| GeneralName::from(*ip)));
    let now = OffsetDateTime::now_utc();
    let extensions = vec![
        extension(
            BasicConstraints::OID,
            true,
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_der()
            .expect("bc"),
        ),
        extension(
            KeyUsage::OID,
            true,
            KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment)
                .to_der()
                .expect("ku"),
        ),
        extension(
            ExtendedKeyUsage::OID,
            false,
            ExtendedKeyUsage(vec![rfc5280::ID_KP_SERVER_AUTH])
                .to_der()
                .expect("eku"),
        ),
        extension(
            SubjectAltName::OID,
            false,
            SubjectAltName(names).to_der().expect("san"),
        ),
        extension(
            SubjectKeyIdentifier::OID,
            false,
            SubjectKeyIdentifier(
                OctetString::new(key_identifier(&spki).expect("ski").to_vec()).expect("ski"),
            )
            .to_der()
            .expect("ski"),
        ),
        aki_extension(issuer_cert_der),
    ];
    build_test_certificate(&TestCertSpec {
        subject_der: cn_name_der("KEYSTONE TEST leaf"),
        subject_public_key_der: spki,
        issuer: Some(TestIssuer {
            name_der: &issuer.subject_der,
            key: issuer_key,
        }),
        self_key: None,
        not_before: now - Duration::hours(1),
        not_after: now + Duration::days(90),
        extensions,
    })
}

/// A test CRL signed by a sub-intermediate for its own leaves (what an issuing
/// system such as StarnetAuth would publish), so `openssl verify -crl_check_all`
/// has a CRL for every level. Keystone itself signs no sub-intermediate CRLs.
pub fn issue_test_leaf_crl(
    issuer_cert_der: &[u8],
    issuer_key: &RsaPrivateKey,
    revoked: &[Serial],
) -> Vec<u8> {
    let issuer = parse_certificate_der(issuer_cert_der).expect("issuer certificate");
    let now = OffsetDateTime::now_utc() - Duration::minutes(5);
    let revoked_certificates: Vec<RevokedCert> = revoked
        .iter()
        .map(|serial| RevokedCert {
            serial_number: SerialNumber::new(serial.as_bytes()).expect("serial"),
            revocation_date: rfc5280_time(now).expect("time"),
            crl_entry_extensions: None,
        })
        .collect();
    let tbs = TbsCertList {
        version: Version::V2,
        signature: signature_algorithm(),
        issuer: Name::from_der(&issuer.subject_der).expect("issuer name"),
        this_update: rfc5280_time(now).expect("time"),
        next_update: Some(rfc5280_time(now + Duration::days(7)).expect("time")),
        revoked_certificates: (!revoked_certificates.is_empty()).then_some(revoked_certificates),
        crl_extensions: Some(vec![
            aki_extension(issuer_cert_der),
            extension(
                CrlNumber::OID,
                false,
                CrlNumber(Uint::new(&[1]).expect("number"))
                    .to_der()
                    .expect("number"),
            ),
        ]),
    };
    let tbs_der = tbs.to_der().expect("tbs");
    let signature = issuer_key.sign_sha384_pkcs1(&tbs_der).expect("signature");
    CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: signature_algorithm(),
        signature: BitString::from_bytes(&signature).expect("signature"),
    }
    .to_der()
    .expect("crl")
}
