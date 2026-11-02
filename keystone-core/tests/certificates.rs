//! Certificate builder tests: profile conformance of every level, the rules of
//! FR-10, name constraints (FR-21) and chain files (FR-09 AC1).
#![forbid(unsafe_code)]

use std::sync::OnceLock;

use keystone_core::cert::{
    CaCertificateRequest, CertError, ConstraintName, Issuer, PlannedSerial, SoftwareSigner,
    chain_pem, issue_ca_certificate, parse_certificate_der, parse_certificate_pem, plan_serial,
};
use keystone_core::crypto::CryptoError;
use keystone_core::crypto::pkcs8::contains_plaintext_private_key;
use keystone_core::crypto::verify::{VerifyOptions, certificates_pem_to_der, verify_chain};
use keystone_core::model::{CaLevel, Serial};
use keystone_core::profile::{
    CrlLocation, CrlUrl, NameConstraintsChoice, NameConstraintsSpec, ProfileError, ValidatedName,
    plan_validity,
};
use keystone_core::token::TokenSigner;
use keystone_testkit::hierarchy::{HierarchyOptions, MAIN_CRL_URL, MASTER_CRL_URL, TestHierarchy};
use keystone_testkit::keys;
use keystone_testkit::names::{assert_test_cn, test_name, test_name_cn_only};
use time::OffsetDateTime;

const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_KEY_USAGE: &str = "2.5.29.15";
const OID_SKI: &str = "2.5.29.14";
const OID_AKI: &str = "2.5.29.35";
const OID_CDP: &str = "2.5.29.31";
const OID_NAME_CONSTRAINTS: &str = "2.5.29.30";

fn hierarchy() -> &'static TestHierarchy {
    static HIERARCHY: OnceLock<TestHierarchy> = OnceLock::new();
    HIERARCHY.get_or_init(|| TestHierarchy::build(&HierarchyOptions::default()))
}

fn fresh_serial() -> PlannedSerial {
    plan_serial(&mut |_| false).unwrap()
}

#[test]
fn fr02_ac2_ac3_master_certificate_profile() {
    // Covers: FR-02 AC2, FR-02 AC3, FR-10 AC3, FR-20 AC1
    let h = hierarchy();
    let info = &h.master.info;
    assert_eq!(info.version_raw, 2, "X.509 v3");
    assert!(info.signature_is_sha384_rsa);
    assert_eq!(info.signature_algorithm_oid, "1.2.840.113549.1.1.12");
    assert!(info.is_self_issued());
    let bc = info.basic_constraints.unwrap();
    assert!(bc.critical && bc.ca && bc.path_len.is_none());
    let ku = info.key_usage.unwrap();
    assert!(ku.critical && ku.key_cert_sign && ku.crl_sign && !ku.other_bits);
    assert_eq!(info.subject_key_id.as_ref().map(Vec::len), Some(20));
    assert!(info.authority_key_id.is_none());
    assert!(!info.has_crl_distribution_points);
    assert!(info.name_constraints.is_none());
    assert_eq!(
        info.extension_oids,
        [OID_BASIC_CONSTRAINTS, OID_KEY_USAGE, OID_SKI]
    );
    // Default validity 20 years (FR-02 AC2).
    assert_eq!(info.not_after.year() - info.not_before.year(), 20);
    assert_eq!(info.ca_level(), Some(CaLevel::Master));
    assert_test_cn(info.subject_common_name.as_deref().unwrap());
    assert_eq!(info.fingerprint.to_fingerprint_string().len(), 95);
    assert!(h.master.pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    let (der, again) = parse_certificate_pem(h.master.pem.as_bytes()).unwrap();
    assert_eq!(der, h.master.der);
    assert_eq!(&again, info);
}

#[test]
fn fr02_ac4_subject_order_is_c_o_cn() {
    // Covers: FR-02 AC4
    let subject = &hierarchy().master.info.subject;
    // RFC 4514 text lists RDNs in reverse order: CN first, C last.
    assert!(
        subject.starts_with("CN=KEYSTONE TEST A Master,O=KEYSTONE TEST,C=US"),
        "{subject}"
    );
}

#[test]
fn fr07_ac3_main_certificate_is_stored_in_the_slot() {
    // Covers: FR-07 AC3
    let h = hierarchy();
    let mut token = h.token.reopen();
    assert_eq!(
        token.read_signing_certificate().unwrap(),
        Some(h.main.der.clone())
    );
    let status = token
        .slot_status(keystone_core::token::SIGNING_SLOT)
        .unwrap();
    assert_eq!(status.certificate_der, Some(h.main.der.clone()));
    assert_eq!(status.key.unwrap().public_key_der, h.main.info.spki_der);
}

#[test]
fn fr07_ac2_main_intermediate_profile() {
    // Covers: FR-07 AC2, FR-18 AC1
    let h = hierarchy();
    let info = &h.main.info;
    assert_eq!(info.version_raw, 2);
    assert!(info.signature_is_sha384_rsa);
    let bc = info.basic_constraints.unwrap();
    assert!(bc.critical && bc.ca);
    assert_eq!(bc.path_len, Some(1));
    let ku = info.key_usage.unwrap();
    assert!(ku.critical && ku.key_cert_sign && ku.crl_sign && !ku.other_bits);
    assert!(info.subject_key_id.is_some());
    assert_eq!(info.authority_key_id, h.master.info.subject_key_id);
    assert_eq!(info.issuer_der, h.master.info.subject_der);
    assert_eq!(info.crl_distribution_urls, [MASTER_CRL_URL]);
    assert!(info.name_constraints.is_none());
    assert_eq!(info.not_after.year() - info.not_before.year(), 10);
    assert_eq!(info.ca_level(), Some(CaLevel::MainIntermediate));
    assert_eq!(
        info.extension_oids,
        [
            OID_BASIC_CONSTRAINTS,
            OID_KEY_USAGE,
            OID_SKI,
            OID_AKI,
            OID_CDP
        ]
    );
}

#[test]
fn fr08_ac2_sub_intermediate_profile() {
    // Covers: FR-08 AC2, FR-18 AC1, FR-21 AC2, FR-21 AC3, SEC-14, SEC-21
    let h = hierarchy();
    let info = &h.sub.info;
    let bc = info.basic_constraints.unwrap();
    assert!(bc.critical && bc.ca);
    assert_eq!(bc.path_len, Some(0));
    let ku = info.key_usage.unwrap();
    assert!(ku.critical && ku.key_cert_sign && ku.crl_sign && !ku.other_bits);
    assert!(info.subject_key_id.is_some());
    assert_eq!(info.authority_key_id, h.main.info.subject_key_id);
    assert_eq!(info.crl_distribution_urls, [MAIN_CRL_URL]);
    assert_eq!(info.not_after.year() - info.not_before.year(), 5);
    assert_eq!(info.ca_level(), Some(CaLevel::SubIntermediate));
    let nc = info.name_constraints.as_ref().unwrap();
    assert!(nc.critical, "FR-21 AC2: critical");
    // ADR 0001: email and URI names are blocked by permitting only the reserved
    // `.keystone.invalid` domain (RFC 2606/6761), never by a zero-length exclusion.
    assert_eq!(
        nc.permitted,
        [
            ConstraintName::Dns("starnet".into()),
            ConstraintName::Email(".keystone.invalid".into()),
            ConstraintName::Uri(".keystone.invalid".into()),
        ]
    );
    assert_eq!(
        nc.excluded,
        [
            ConstraintName::Ip(vec![0; 8]),
            ConstraintName::Ip(vec![0; 32])
        ]
    );
    assert_eq!(
        info.extension_oids,
        [
            OID_BASIC_CONSTRAINTS,
            OID_KEY_USAGE,
            OID_SKI,
            OID_AKI,
            OID_CDP,
            OID_NAME_CONSTRAINTS
        ]
    );
}

#[test]
fn fr21_ac3_permitted_ip_ranges_replace_the_family_exclusion() {
    // Covers: FR-21 AC2, FR-21 AC3
    let h = TestHierarchy::build(&HierarchyOptions {
        label: "IP".into(),
        permitted_dns: vec!["starnet".into(), "pki.example.test".into()],
        permitted_ip: vec!["10.0.0.0/8".into()],
        sub_key_index: 1,
        ..HierarchyOptions::default()
    });
    let nc = h.sub.info.name_constraints.unwrap();
    assert_eq!(
        nc.permitted,
        [
            ConstraintName::Dns("starnet".into()),
            ConstraintName::Dns("pki.example.test".into()),
            ConstraintName::Ip(vec![10, 0, 0, 0, 255, 0, 0, 0]),
            ConstraintName::Email(".keystone.invalid".into()),
            ConstraintName::Uri(".keystone.invalid".into()),
        ]
    );
    assert_eq!(nc.excluded, [ConstraintName::Ip(vec![0; 32])]);
}

#[test]
fn fr21_ac3_ranges_for_both_families_leave_no_empty_excluded_subtrees() {
    // Covers: FR-21 AC2, FR-21 AC3
    // GeneralSubtrees is SIZE (1..MAX): with nothing to exclude the field is omitted,
    // and email and URI names stay blocked through permittedSubtrees (ADR 0001).
    let h = TestHierarchy::build(&HierarchyOptions {
        label: "IP46".into(),
        permitted_ip: vec!["10.0.0.0/8".into(), "2001:db8::/32".into()],
        sub_key_index: 5,
        ..HierarchyOptions::default()
    });
    let nc = h.sub.info.name_constraints.as_ref().unwrap();
    assert!(nc.critical);
    assert!(nc.excluded.is_empty(), "{nc:?}");
    assert!(
        nc.permitted
            .contains(&ConstraintName::Email(".keystone.invalid".into()))
    );
    assert!(
        nc.permitted
            .contains(&ConstraintName::Uri(".keystone.invalid".into()))
    );
    // The excludedSubtrees field is absent, not an empty SEQUENCE.
    use x509_cert::der::Decode;
    use x509_cert::der::oid::AssociatedOid;
    let cert = x509_cert::Certificate::from_der(&h.sub.der).unwrap();
    let (_, value) = cert
        .tbs_certificate()
        .get_extension::<x509_cert::ext::pkix::NameConstraints>()
        .unwrap()
        .unwrap();
    assert_eq!(
        x509_cert::ext::pkix::NameConstraints::OID.to_string(),
        OID_NAME_CONSTRAINTS
    );
    assert!(value.excluded_subtrees.is_none());
    let options = VerifyOptions::at(OffsetDateTime::now_utc());
    verify_chain(&h.sub.der, &[&h.main.der], &[&h.master.der], &[], &options).unwrap();
}

#[test]
fn fr21_ac1_explicitly_unconstrained_sub_has_no_name_constraints() {
    // Covers: FR-21 AC1
    let h = TestHierarchy::build(&HierarchyOptions {
        label: "Open".into(),
        unconstrained_sub: true,
        sub_key_index: 3,
        ..HierarchyOptions::default()
    });
    assert!(h.sub.info.name_constraints.is_none());
    assert!(
        !h.sub
            .info
            .extension_oids
            .iter()
            .any(|oid| oid == OID_NAME_CONSTRAINTS)
    );
}

fn sub_request<'a>(
    h: &'a TestHierarchy,
    name: &'a ValidatedName,
    spki: &'a [u8],
    crl: Option<&'a CrlLocation>,
    nc: Option<&'a NameConstraintsChoice>,
) -> CaCertificateRequest<'a> {
    CaCertificateRequest {
        level: CaLevel::SubIntermediate,
        subject: name,
        subject_public_key_der: spki,
        validity: plan_validity(
            CaLevel::SubIntermediate,
            5,
            OffsetDateTime::now_utc(),
            Some(h.main.info.not_after),
        )
        .unwrap(),
        serial: fresh_serial(),
        issuer: Issuer::Certificate(&h.main.der),
        issuer_crl: crl,
        name_constraints: nc,
    }
}

#[test]
fn fr10_ac3_structure_cannot_be_changed() {
    // Covers: FR-10 AC3, FR-18 AC1, FR-21 AC1
    let h = hierarchy();
    let main_spki = h.main.info.spki_der.clone();
    let mut main_signer = SoftwareSigner::new(h.master_key);
    let name = ValidatedName::new(&test_name("Wrong")).unwrap();
    let sub_spki = keys::rsa4096(4).public_key_spki_der().unwrap();
    let crl = CrlLocation::ExplicitlyNone;
    let nc = NameConstraintsChoice::Constrained(
        NameConstraintsSpec::new(&["starnet"], &[] as &[&str]).unwrap(),
    );

    // Wrong key size for the level: a 2,048-bit key cannot become a sub-intermediate.
    let small = keys::rsa2048(2).public_key_spki_der().unwrap();
    let request = sub_request(h, &name, &small, Some(&crl), Some(&nc));
    assert!(matches!(
        issue_ca_certificate(&request, &mut main_signer),
        Err(CertError::WrongKeySize {
            expected: 4096,
            actual: 2048,
            ..
        })
    ));
    // A master-sized key cannot be a main intermediate either.
    let big = h.master_key.public_key_spki_der().unwrap();
    let request = CaCertificateRequest {
        level: CaLevel::MainIntermediate,
        subject: &name,
        subject_public_key_der: &big,
        validity: plan_validity(
            CaLevel::MainIntermediate,
            10,
            OffsetDateTime::now_utc(),
            Some(h.master.info.not_after),
        )
        .unwrap(),
        serial: fresh_serial(),
        issuer: Issuer::Certificate(&h.master.der),
        issuer_crl: Some(&crl),
        name_constraints: None,
    };
    assert!(matches!(
        issue_ca_certificate(&request, &mut main_signer),
        Err(CertError::WrongKeySize { .. })
    ));
    // A sub-intermediate needs an explicit name-constraints choice and CRL choice.
    let request = sub_request(h, &name, &sub_spki, Some(&crl), None);
    assert!(matches!(
        issue_ca_certificate(&request, &mut main_signer),
        Err(CertError::Profile(ProfileError::NameConstraintsRequired))
    ));
    let request = sub_request(h, &name, &sub_spki, None, Some(&nc));
    assert!(matches!(
        issue_ca_certificate(&request, &mut main_signer),
        Err(CertError::Request(_))
    ));
    // A sub-intermediate must be signed by the main intermediate, not the master.
    let mut request = sub_request(h, &name, &sub_spki, Some(&crl), Some(&nc));
    request.issuer = Issuer::Certificate(&h.master.der);
    assert!(matches!(
        issue_ca_certificate(&request, &mut main_signer),
        Err(CertError::Request(_))
    ));
    // The signer must hold the issuer's key: the master key cannot sign as main.
    let request = sub_request(h, &name, &sub_spki, Some(&crl), Some(&nc));
    assert!(matches!(
        issue_ca_certificate(&request, &mut main_signer),
        Err(CertError::SignerKeyMismatch)
    ));
    // A validity planned for another level is refused.
    let mut request = sub_request(h, &name, &sub_spki, Some(&crl), Some(&nc));
    request.validity = plan_validity(
        CaLevel::MainIntermediate,
        10,
        OffsetDateTime::now_utc(),
        Some(h.master.info.not_after),
    )
    .unwrap();
    assert!(issue_ca_certificate(&request, &mut SoftwareSigner::new(keys::rsa4096(4))).is_err());
    // The child's name must differ from its issuer's.
    let same = ValidatedName::new(&test_name("A Main")).unwrap();
    let request = sub_request(h, &same, &sub_spki, Some(&crl), Some(&nc));
    assert!(matches!(
        issue_ca_certificate(&request, &mut SoftwareSigner::new(keys::rsa4096(4))),
        Err(CertError::Request(_)) | Err(CertError::SignerKeyMismatch)
    ));
    assert!(!main_spki.is_empty());
}

#[test]
fn fr10_ac1_child_never_outlives_issuer() {
    // Covers: FR-10 AC1
    let h = hierarchy();
    // Planning more than the issuer allows is refused before anything is signed.
    let far_future = h.main.info.not_after - time::Duration::days(365);
    let error = plan_validity(
        CaLevel::SubIntermediate,
        5,
        far_future,
        Some(h.main.info.not_after),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ProfileError::OutlivesIssuer { max_years: 0, .. }
    ));
}

#[test]
fn fr10_ac2_serial_hook_rejects_known_serials() {
    // Covers: FR-10 AC2
    let mut asked = Vec::new();
    let planned = plan_serial(&mut |candidate: &Serial| {
        asked.push(*candidate);
        asked.len() < 3
    })
    .unwrap();
    assert_eq!(asked.len(), 3, "the first two candidates were 'known'");
    assert_eq!(planned.serial(), asked[2]);
    assert!(matches!(
        plan_serial(&mut |_| true),
        Err(CertError::SerialSpaceExhausted)
    ));
    let h = hierarchy();
    let serials = [h.master.info.serial, h.main.info.serial, h.sub.info.serial];
    for serial in serials {
        assert_eq!(serial.as_bytes()[0] & 0x80, 0, "positive");
    }
    assert_ne!(serials[0], serials[1]);
    assert_ne!(serials[1], serials[2]);
}

#[test]
fn fr09_ac1_chain_file_order_and_checks() {
    // Covers: FR-09 AC1
    let h = hierarchy();
    let chain = chain_pem(&h.sub.der, &h.main.der, &h.master.der).unwrap();
    let ders = certificates_pem_to_der(chain.as_bytes()).unwrap();
    assert_eq!(
        ders,
        [h.sub.der.clone(), h.main.der.clone(), h.master.der.clone()]
    );
    assert!(chain_pem(&h.main.der, &h.sub.der, &h.master.der).is_err());
    assert!(chain_pem(&h.master.der, &h.main.der, &h.sub.der).is_err());
    let other = TestHierarchy::build(&HierarchyOptions {
        label: "Other".into(),
        sub_key_index: 2,
        ..HierarchyOptions::default()
    });
    assert!(chain_pem(&other.sub.der, &h.main.der, &h.master.der).is_err());
    assert!(!contains_plaintext_private_key(chain.as_bytes()));
}

#[test]
fn sec13_openssl_verifies_every_level_strictly() {
    // Covers: SEC-13, FR-09 AC2
    let h = hierarchy();
    let now = OffsetDateTime::now_utc();
    let options = VerifyOptions::at(now);
    verify_chain(&h.master.der, &[], &[&h.master.der], &[], &options).unwrap();
    verify_chain(&h.main.der, &[], &[&h.master.der], &[], &options).unwrap();
    verify_chain(&h.sub.der, &[&h.main.der], &[&h.master.der], &[], &options).unwrap();
    // Without the intermediate the chain cannot be built.
    let error = verify_chain(&h.sub.der, &[], &[&h.master.der], &[], &options).unwrap_err();
    assert!(matches!(error, CryptoError::ChainInvalid { .. }));
    // A certificate after its validity is refused.
    let later = VerifyOptions::at(h.sub.info.not_after + time::Duration::days(1));
    assert!(verify_chain(&h.sub.der, &[&h.main.der], &[&h.master.der], &[], &later).is_err());
}

#[test]
fn sec08_certificate_parser_rejects_garbage_and_oversize() {
    // Covers: SEC-08
    assert!(parse_certificate_der(&[0x30, 0x00]).is_err());
    assert!(matches!(
        parse_certificate_der(&vec![0x30; keystone_core::limits::MAX_CERT_DER_BYTES + 1]),
        Err(CertError::Crypto(CryptoError::InputTooLarge { .. }))
    ));
    let mut trailing = hierarchy().master.der.clone();
    trailing.push(0);
    assert!(parse_certificate_der(&trailing).is_err());
}

#[test]
fn master_with_only_common_name() {
    // Covers: FR-02 AC4
    let key = keys::master(0);
    let spki = key.public_key_spki_der().unwrap();
    let name = ValidatedName::new(&test_name_cn_only("CN only")).unwrap();
    let issued = issue_ca_certificate(
        &CaCertificateRequest {
            level: CaLevel::Master,
            subject: &name,
            subject_public_key_der: &spki,
            validity: plan_validity(CaLevel::Master, 25, OffsetDateTime::now_utc(), None).unwrap(),
            serial: fresh_serial(),
            issuer: Issuer::SelfSigned,
            issuer_crl: None,
            name_constraints: None,
        },
        &mut SoftwareSigner::new(key),
    )
    .unwrap();
    assert_eq!(issued.info.subject, "CN=KEYSTONE TEST CN only");
    // 25 years from 2026 ends after 2049, so GeneralizedTime is used (RFC 5280 4.1.2.5).
    assert!(issued.info.not_after.year() >= 2050);
    let encoded = &issued.der;
    assert!(
        encoded.windows(2).any(|w| w == [0x18, 0x0f]),
        "GeneralizedTime present"
    );
    // A master carries no CRL address.
    let url = CrlLocation::Url(CrlUrl::parse("http://crl.keystone.test/x.crl").unwrap());
    let refused = issue_ca_certificate(
        &CaCertificateRequest {
            level: CaLevel::Master,
            subject: &name,
            subject_public_key_der: &spki,
            validity: plan_validity(CaLevel::Master, 20, OffsetDateTime::now_utc(), None).unwrap(),
            serial: fresh_serial(),
            issuer: Issuer::SelfSigned,
            issuer_crl: Some(&url),
            name_constraints: None,
        },
        &mut SoftwareSigner::new(key),
    );
    assert!(refused.is_err());
}
