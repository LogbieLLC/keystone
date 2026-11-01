//! CRL tests: issuers, v2 structure, refresh, and revocation seen by OpenSSL's
//! verifier (FR-13 AC1, AC2, AC4, AC6).
#![forbid(unsafe_code)]

use std::sync::OnceLock;

use keystone_core::cert::SoftwareSigner;
use keystone_core::crl::{
    CrlError, CrlRequest, RevokedEntry, build_crl, crl_with_revocation, parse_crl_der,
    parse_crl_pem, refresh_crl,
};
use keystone_core::crypto::verify::{
    RevocationCheck, VerifyOptions, verify_chain, verify_crl_signature,
};
use keystone_core::model::RevocationReason;
use keystone_core::token::TokenCaSigner;
use keystone_testkit::hierarchy::{HierarchyOptions, TestHierarchy, test_pin};
use keystone_testkit::keys;
use keystone_testkit::x509::{issue_test_leaf, issue_test_leaf_crl};
use time::{Duration, OffsetDateTime};

fn hierarchy() -> &'static TestHierarchy {
    static HIERARCHY: OnceLock<TestHierarchy> = OnceLock::new();
    HIERARCHY.get_or_init(|| {
        TestHierarchy::build(&HierarchyOptions {
            label: "CRL".into(),
            ..HierarchyOptions::default()
        })
    })
}

#[test]
fn fr13_ac1_ac2_ac6_first_crls_are_empty_v2_with_number_and_aki() {
    // Covers: FR-13 AC1, FR-13 AC2, FR-13 AC6
    let h = hierarchy();
    for (crl, issuer, days) in [
        (&h.master_crl, &h.master, 365..=366),
        (&h.main_crl, &h.main, 90..=90),
    ] {
        let info = &crl.info;
        assert_eq!(info.version_raw, 1, "X.509 CRL v2");
        assert_eq!(info.crl_number, 1);
        assert!(info.revoked.is_empty());
        assert_eq!(info.authority_key_id, issuer.info.subject_key_id);
        assert_eq!(info.issuer_der, issuer.info.subject_der);
        assert!(info.signature_is_sha384_rsa);
        assert!(days.contains(&(info.next_update - info.this_update).whole_days()));
        verify_crl_signature(&crl.der, &issuer.info.spki_der).unwrap();
        let (der, again) = parse_crl_pem(crl.pem.as_bytes()).unwrap();
        assert_eq!(der, crl.der);
        assert_eq!(&again, info);
    }
    // The master's CRL is not signed by the main intermediate and vice versa.
    assert!(verify_crl_signature(&h.master_crl.der, &h.main.info.spki_der).is_err());
}

#[test]
fn fr13_ac1_sub_intermediates_sign_no_keystone_crl() {
    // Covers: FR-13 AC1
    let h = hierarchy();
    let now = OffsetDateTime::now_utc();
    let result = build_crl(
        &CrlRequest {
            issuer_certificate_der: &h.sub.der,
            crl_number: 1,
            this_update: now,
            next_update: now + Duration::days(7),
            revoked: &[],
        },
        &mut SoftwareSigner::new(h.sub_key),
    );
    assert!(matches!(result, Err(CrlError::Request(_))));
}

#[test]
fn fr13_ac1_revocation_entries_and_reasons() {
    // Covers: FR-13 AC1, FR-11 AC1
    let h = hierarchy();
    let now = OffsetDateTime::now_utc();
    let mut signer = SoftwareSigner::new(h.master_key);
    let revoked = crl_with_revocation(
        &h.master_crl.der,
        &h.master.der,
        RevokedEntry {
            serial: h.main.info.serial,
            revocation_date: now - Duration::minutes(1),
            reason: RevocationReason::KeyCompromise,
        },
        now,
        &mut signer,
    )
    .unwrap();
    assert_eq!(revoked.info.crl_number, 2);
    assert_eq!(revoked.info.revoked.len(), 1);
    assert_eq!(revoked.info.revoked[0].serial, h.main.info.serial);
    assert_eq!(
        revoked.info.revoked[0].reason,
        RevocationReason::KeyCompromise
    );
    // "unspecified" is written without a reasonCode extension (RFC 5280 5.3.1).
    let other_serial = keystone_core::cert::plan_serial(&mut |_| false)
        .unwrap()
        .serial();
    let unspecified = crl_with_revocation(
        &revoked.der,
        &h.master.der,
        RevokedEntry {
            serial: other_serial,
            revocation_date: now,
            reason: RevocationReason::Unspecified,
        },
        now,
        &mut signer,
    )
    .unwrap();
    assert_eq!(unspecified.info.revoked.len(), 2);
    assert_eq!(
        unspecified.info.revoked[1].reason,
        RevocationReason::Unspecified
    );
    assert_eq!(
        unspecified
            .der
            .windows(5)
            .filter(|w| *w == [0x06, 0x03, 0x55, 0x1d, 0x15])
            .count(),
        1,
        "exactly one reasonCode extension"
    );
    // The same serial cannot be revoked twice.
    assert!(
        crl_with_revocation(
            &unspecified.der,
            &h.master.der,
            RevokedEntry {
                serial: other_serial,
                revocation_date: now,
                reason: RevocationReason::Superseded,
            },
            now,
            &mut signer,
        )
        .is_err()
    );
}

#[test]
fn fr13_ac4_refresh_keeps_entries_and_raises_number() {
    // Covers: FR-13 AC4
    let h = TestHierarchy::build(&HierarchyOptions {
        label: "Refresh".into(),
        sub_key_index: 1,
        ..HierarchyOptions::default()
    });
    let now = OffsetDateTime::now_utc();
    let pin = test_pin();
    let mut token = h.token.reopen();
    let revoked = crl_with_revocation(
        &h.main_crl.der,
        &h.main.der,
        RevokedEntry {
            serial: h.sub.info.serial,
            revocation_date: now,
            reason: RevocationReason::CessationOfOperation,
        },
        now,
        &mut TokenCaSigner::new(&mut token, &pin),
    )
    .unwrap();
    let later = now + Duration::days(70);
    let refreshed = refresh_crl(
        &revoked.der,
        &h.main.der,
        later,
        &mut TokenCaSigner::new(&mut token, &pin),
    )
    .unwrap();
    assert!(refreshed.info.crl_number > revoked.info.crl_number);
    assert_eq!(refreshed.info.crl_number, 3);
    assert_eq!(refreshed.info.revoked, revoked.info.revoked);
    assert!(refreshed.info.this_update > revoked.info.this_update);
    assert_eq!(
        (refreshed.info.next_update - refreshed.info.this_update).whole_days(),
        90
    );
    // A clock earlier than the current CRL is refused.
    assert!(
        refresh_crl(
            &refreshed.der,
            &h.main.der,
            now,
            &mut TokenCaSigner::new(&mut token, &pin)
        )
        .is_err()
    );
    // The current CRL must belong to this issuer.
    assert!(
        refresh_crl(
            &h.master_crl.der,
            &h.main.der,
            later,
            &mut TokenCaSigner::new(&mut token, &pin)
        )
        .is_err()
    );
    // Refreshing with the wrong key is refused before signing.
    assert!(
        refresh_crl(
            &revoked.der,
            &h.main.der,
            later,
            &mut SoftwareSigner::new(keys::rsa4096(5))
        )
        .is_err()
    );
}

#[test]
fn fr13_revocation_is_enforced_by_openssl_at_depth_1_and_2() {
    // Covers: FR-13 AC1, FR-13 AC5
    // Local CRL files only; the StarnetAuth download part is BLOCKED (interop/blocked.rs).
    // Scenario A: revoke only the sub-intermediate (depth 1), on its own hierarchy.
    let a = TestHierarchy::build(&HierarchyOptions {
        label: "Scenario A".into(),
        sub_key_index: 2,
        ..HierarchyOptions::default()
    });
    let leaf_key = keys::rsa2048(0);
    let leaf = issue_test_leaf(&a.sub.der, a.sub_key, leaf_key, &["host.starnet"], &[]);
    let leaf_crl = issue_test_leaf_crl(&a.sub.der, a.sub_key, &[]);
    let options = VerifyOptions {
        at: OffsetDateTime::now_utc(),
        revocation: RevocationCheck::CrlCheckAll,
        strict: false,
    };
    let untrusted: [&[u8]; 2] = [&a.sub.der, &a.main.der];
    verify_chain(
        &leaf,
        &untrusted,
        &[&a.master.der],
        &[&a.master_crl.der, &a.main_crl.der, &leaf_crl],
        &options,
    )
    .expect("leaf verifies before revocation");
    let pin = test_pin();
    let mut token = a.token.reopen();
    let now = OffsetDateTime::now_utc();
    let main_crl = crl_with_revocation(
        &a.main_crl.der,
        &a.main.der,
        RevokedEntry {
            serial: a.sub.info.serial,
            revocation_date: now - Duration::seconds(1),
            reason: RevocationReason::KeyCompromise,
        },
        now,
        &mut TokenCaSigner::new(&mut token, &pin),
    )
    .unwrap();
    let error = verify_chain(
        &leaf,
        &untrusted,
        &[&a.master.der],
        &[&a.master_crl.der, &main_crl.der, &leaf_crl],
        &options,
    )
    .unwrap_err();
    assert!(error.is_revoked_at(1), "{error}");

    // Scenario B: revoke only the main intermediate (depth 2), on a fresh hierarchy.
    let b = TestHierarchy::build(&HierarchyOptions {
        label: "Scenario B".into(),
        master_key_index: 1,
        sub_key_index: 3,
        ..HierarchyOptions::default()
    });
    let leaf = issue_test_leaf(&b.sub.der, b.sub_key, leaf_key, &["host.starnet"], &[]);
    let leaf_crl = issue_test_leaf_crl(&b.sub.der, b.sub_key, &[]);
    let untrusted: [&[u8]; 2] = [&b.sub.der, &b.main.der];
    verify_chain(
        &leaf,
        &untrusted,
        &[&b.master.der],
        &[&b.master_crl.der, &b.main_crl.der, &leaf_crl],
        &options,
    )
    .expect("leaf verifies before revocation");
    let master_crl = crl_with_revocation(
        &b.master_crl.der,
        &b.master.der,
        RevokedEntry {
            serial: b.main.info.serial,
            revocation_date: now - Duration::seconds(1),
            reason: RevocationReason::CaCompromise,
        },
        now,
        &mut SoftwareSigner::new(b.master_key),
    )
    .unwrap();
    let error = verify_chain(
        &leaf,
        &untrusted,
        &[&b.master.der],
        &[&master_crl.der, &b.main_crl.der, &leaf_crl],
        &options,
    )
    .unwrap_err();
    assert!(error.is_revoked_at(2), "{error}");
    // Without CRL checking the same chain still verifies: revocation needs the check.
    let plain = VerifyOptions {
        revocation: RevocationCheck::None,
        ..options
    };
    verify_chain(&leaf, &untrusted, &[&b.master.der], &[], &plain).unwrap();
}

#[test]
fn crl_request_rules() {
    // Covers: FR-13 AC2
    let h = hierarchy();
    let now = OffsetDateTime::now_utc();
    let mut signer = SoftwareSigner::new(h.master_key);
    let base = CrlRequest {
        issuer_certificate_der: &h.master.der,
        crl_number: 5,
        this_update: now,
        next_update: now + Duration::days(10),
        revoked: &[],
    };
    assert!(
        build_crl(
            &CrlRequest {
                crl_number: 0,
                ..base
            },
            &mut signer
        )
        .is_err()
    );
    assert!(
        build_crl(
            &CrlRequest {
                next_update: now,
                ..base
            },
            &mut signer
        )
        .is_err()
    );
    let future_revocation = [RevokedEntry {
        serial: h.main.info.serial,
        revocation_date: now + Duration::days(1),
        reason: RevocationReason::Superseded,
    }];
    assert!(
        build_crl(
            &CrlRequest {
                revoked: &future_revocation,
                ..base
            },
            &mut signer
        )
        .is_err()
    );
    let duplicate = [future_revocation[0], future_revocation[0]].map(|mut e| {
        e.revocation_date = now;
        e
    });
    assert!(
        build_crl(
            &CrlRequest {
                revoked: &duplicate,
                ..base
            },
            &mut signer
        )
        .is_err()
    );
    // 2050 and later use GeneralizedTime in the CRL too.
    let later = build_crl(
        &CrlRequest {
            next_update: OffsetDateTime::parse(
                "2051-01-01T00:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap(),
            ..base
        },
        &mut signer,
    )
    .unwrap();
    assert!(later.der.windows(2).any(|w| w == [0x18, 0x0f]));
    assert_eq!(parse_crl_der(&later.der).unwrap().crl_number, 5);
}
