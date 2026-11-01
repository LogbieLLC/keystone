//! Property tests for the certificate rules of FR-10 (SEC-13).
//!
//! proptest's failure-persistence files are turned off so that no test writes
//! outside a temporary directory (TEST-12); a failing case is printed instead and
//! becomes an explicit regression test (TEST-03).
#![forbid(unsafe_code)]

use std::sync::OnceLock;

use keystone_core::cert::{CaCertificateRequest, Issuer, issue_ca_certificate, plan_serial};
use keystone_core::crypto::verify::{VerifyOptions, verify_chain};
use keystone_core::model::{CaLevel, NameFields};
use keystone_core::profile::{
    CrlLocation, NameConstraintsChoice, NameConstraintsSpec, ProfileError, ValidatedName,
    level_profile, max_validity_years, plan_validity,
};
use keystone_core::token::TokenCaSigner;
use keystone_testkit::hierarchy::{HierarchyOptions, TestHierarchy, test_pin};
use keystone_testkit::keys;
use proptest::prelude::*;
use time::OffsetDateTime;

fn config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn level() -> impl Strategy<Value = CaLevel> {
    prop_oneof![
        Just(CaLevel::Master),
        Just(CaLevel::MainIntermediate),
        Just(CaLevel::SubIntermediate)
    ]
}

/// 1970 to 2090, in whole and fractional seconds.
fn instant() -> impl Strategy<Value = OffsetDateTime> {
    (0i64..3_786_912_000, 0u32..1_000_000_000).prop_map(|(seconds, nanos)| {
        OffsetDateTime::from_unix_timestamp(seconds).unwrap()
            + time::Duration::nanoseconds(i64::from(nanos))
    })
}

proptest! {
    #![proptest_config(config(512))]

    #[test]
    fn fr10_ac1_planned_validity_never_outlives_the_issuer(
        level in level(),
        years in 0u8..=30,
        now in instant(),
        issuer_offset_days in -400i64..=12_000,
    ) {
        // Covers: FR-10 AC1, FR-10 AC3, SEC-13
        let issuer_end = (level != CaLevel::Master).then(|| now + time::Duration::days(issuer_offset_days));
        let profile = level_profile(level);
        match plan_validity(level, years, now, issuer_end) {
            Ok(validity) => {
                prop_assert!((profile.min_validity_years..=profile.max_validity_years).contains(&years));
                prop_assert_eq!(validity.level(), level);
                prop_assert_eq!(validity.not_before().unix_timestamp(), now.unix_timestamp());
                prop_assert_eq!(validity.not_before().nanosecond(), 0);
                prop_assert!(validity.not_after() > validity.not_before());
                if let Some(end) = issuer_end {
                    prop_assert!(validity.not_after() <= end);
                }
            }
            Err(ProfileError::ValidityOutOfBounds { .. }) => {
                prop_assert!(!(profile.min_validity_years..=profile.max_validity_years).contains(&years));
            }
            Err(ProfileError::OutlivesIssuer { max_years, .. }) => {
                prop_assert!(max_years < years);
                prop_assert_eq!(max_years, max_validity_years(level, now, issuer_end));
                if max_years > 0 {
                    prop_assert!(plan_validity(level, max_years, now, issuer_end).is_ok());
                }
                if max_years < profile.max_validity_years {
                    prop_assert!(plan_validity(level, max_years + 1, now, issuer_end).is_err());
                }
            }
            Err(other) => prop_assert!(false, "unexpected error {other:?}"),
        }
    }

    #[test]
    fn fr02_ac4_name_validation_accepts_exactly_the_rules(
        cn in "[A-Za-z0-9 .,'()&é-]{0,70}",
        org in proptest::option::of("[A-Za-z0-9 .-]{0,70}"),
        country in proptest::option::of("[A-Za-z0-9]{0,3}"),
    ) {
        // Covers: FR-02 AC4
        let fields = NameFields { common_name: cn.clone(), organization: org.clone(), country: country.clone() };
        let text_ok = |value: &str| value.trim() == value && value.chars().count() <= 64;
        let cn_ok = !cn.is_empty() && text_ok(&cn);
        let org_ok = org.as_deref().is_none_or(|o| o.is_empty() || text_ok(o));
        let country_ok = country
            .as_deref()
            .is_none_or(|c| c.is_empty() || (c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic())));
        let result = ValidatedName::new(&fields);
        prop_assert_eq!(result.is_ok(), cn_ok && org_ok && country_ok, "{:?}", result);
        if let Ok(name) = result {
            prop_assert_eq!(name.common_name(), cn.as_str());
            if let Some(c) = name.country() {
                prop_assert_eq!(c, c.to_ascii_uppercase());
            }
        }
    }
}

fn hierarchy() -> &'static TestHierarchy {
    static H: OnceLock<TestHierarchy> = OnceLock::new();
    H.get_or_init(|| {
        TestHierarchy::build(&HierarchyOptions {
            label: "Properties".into(),
            ..HierarchyOptions::default()
        })
    })
}

fn name_fields() -> impl Strategy<Value = NameFields> {
    (
        "[A-Za-z0-9][A-Za-z0-9 .-]{0,30}[A-Za-z0-9]",
        proptest::option::of("[A-Za-z][A-Za-z0-9 ]{0,20}[A-Za-z0-9]"),
        proptest::option::of("[A-Z]{2}"),
    )
        .prop_map(|(cn, organization, country)| NameFields {
            common_name: format!("KEYSTONE TEST {cn}"),
            organization,
            country,
        })
}

proptest! {
    #![proptest_config(config(24))]

    #[test]
    fn fr10_ac3_sub_intermediates_always_have_the_fixed_structure(
        fields in name_fields(),
        years in 1u8..=10,
        dns in proptest::collection::vec("[a-z][a-z0-9-]{0,10}[a-z0-9](\\.[a-z][a-z0-9]{0,8}){0,2}", 1..4),
    ) {
        // Covers: FR-10 AC3, FR-08 AC2, FR-21 AC2, SEC-13, SEC-14
        let h = hierarchy();
        let mut dns = dns;
        dns.sort();
        dns.dedup();
        prop_assume!(dns.iter().all(|d| !d.rsplit('.').next().unwrap().bytes().all(|b| b.is_ascii_digit())));
        let name = ValidatedName::new(&fields).unwrap();
        let spki = keys::rsa4096(5).public_key_spki_der().unwrap();
        let choice = NameConstraintsChoice::Constrained(NameConstraintsSpec::new(&dns, &[] as &[&str]).unwrap());
        let crl = CrlLocation::ExplicitlyNone;
        let now = OffsetDateTime::now_utc();
        let validity = plan_validity(CaLevel::SubIntermediate, years, now, Some(h.main.info.not_after));
        prop_assume!(validity.is_ok());
        let pin = test_pin();
        let mut token = h.token.reopen();
        let issued = issue_ca_certificate(
            &CaCertificateRequest {
                level: CaLevel::SubIntermediate,
                subject: &name,
                subject_public_key_der: &spki,
                validity: validity.unwrap(),
                serial: plan_serial(&mut |_| false).unwrap(),
                issuer: Issuer::Certificate(&h.main.der),
                issuer_crl: Some(&crl),
                name_constraints: Some(&choice),
            },
            &mut TokenCaSigner::new(&mut token, &pin),
        )
        .unwrap();
        let info = &issued.info;
        prop_assert_eq!(info.version_raw, 2);
        prop_assert!(info.signature_is_sha384_rsa);
        let bc = info.basic_constraints.unwrap();
        prop_assert!(bc.critical && bc.ca && bc.path_len == Some(0));
        let ku = info.key_usage.unwrap();
        prop_assert!(ku.critical && ku.key_cert_sign && ku.crl_sign && !ku.other_bits);
        prop_assert!(info.name_constraints.as_ref().unwrap().critical);
        prop_assert!(!info.has_crl_distribution_points, "explicitly no CRL address");
        prop_assert_eq!(info.subject_common_name.as_deref(), Some(name.common_name()));
        prop_assert!(info.not_after <= h.main.info.not_after);
        prop_assert_eq!(info.serial.as_bytes()[0] & 0x80, 0);
        verify_chain(&issued.der, &[&h.main.der], &[&h.master.der], &[], &VerifyOptions::at(now))
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
    }
}
