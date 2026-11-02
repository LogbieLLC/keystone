//! Flow E: replace a lost YubiKey with the old token absent (FR-15 AC1, SEC-12).
#![forbid(unsafe_code)]

use keystone_core::crypto::CancelFlag;
use keystone_core::crypto::verify::{VerifyOptions, verify_chain};
use keystone_core::model::RevocationReason;
use keystone_core::ops::{
    CrlPlanKind, IssuerUnlock, MainIntermediateRequest, NoProgress, StartupWarning,
    SubIntermediateRequest, testing,
};
use keystone_core::store::{AuditAction, CertStatus};
use keystone_testkit::keys;
use keystone_testkit::names::test_name;
use keystone_testkit::x509::{issue_test_leaf, issue_test_leaf_crl};
use time::Duration;

use crate::support::*;

#[test]
fn fr15_ac1_replace_a_lost_yubikey_with_the_old_token_removed() {
    // Covers: FR-15 AC1, SEC-12, FR-13 AC1, FR-13 AC5, FR-18 AC1
    let (mut test, mut old_token, old_controller) = ca_with_main("E1", 50_000_001);
    let (first, _) = run_flow_c(&mut test, &mut old_token, "E1 one", 1, false).unwrap();
    let (second, _) = run_flow_c(&mut test, &mut old_token, "E1 two", 2, false).unwrap();
    let state = test.ca.state().unwrap();
    let old_main = state.active_main(test.now).unwrap().clone();
    let master = state.master().unwrap().clone();
    let old_main_crl = state.current_crl(old_main.serial()).unwrap().der.clone();
    let first_cert = state.certificate(first.serial).unwrap().clone();
    let leaf = issue_test_leaf(
        &first_cert.der,
        keys::rsa4096(1),
        keys::rsa2048(2),
        &["host.starnet"],
        &[],
    );
    let leaf_crl = issue_test_leaf_crl(&first_cert.der, keys::rsa4096(1), &[]);

    // The YubiKey is lost: it is not connected for any step of Flow E.
    old_controller.remove();
    let signatures = old_controller.signature_count();

    // Steps 1 and 2: the master revokes the old main intermediate, new master CRL.
    let time = test.tick();
    let plan = test
        .ca
        .plan_replace_yubikey(RevocationReason::KeyCompromise, time)
        .unwrap();
    assert!(
        matches!(plan.kind(), CrlPlanKind::ReplaceYubikey { old_main: s, .. } if s == old_main.serial())
    );
    assert!(plan.needs_master());
    let marked = plan
        .review()
        .value("Marked revoked by ancestor")
        .unwrap()
        .to_owned();
    assert!(marked.contains("E1 one") && marked.contains("E1 two"));
    let master_words = test.master_entered();
    let outcome = plan
        .execute(
            &test.ca,
            IssuerUnlock::Master(&master_words),
            Some(test.export()),
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    assert_eq!(outcome.revoked, Some(old_main.serial()));
    let mut cut_off = outcome.revoked_by_ancestor.clone();
    cut_off.sort();
    let mut expected = vec![first.serial, second.serial];
    expected.sort();
    assert_eq!(cut_off, expected);

    // Step 4: every sub-intermediate under it is marked "revoked by ancestor".
    let state = test.ca.state().unwrap();
    for serial in [first.serial, second.serial] {
        assert!(matches!(
            state.record().get(serial).unwrap().status,
            CertStatus::RevokedByAncestor { ancestor, .. } if ancestor == old_main.serial()
        ));
    }
    assert!(matches!(
        state.record().get(old_main.serial()).unwrap().status,
        CertStatus::Revoked {
            reason: RevocationReason::KeyCompromise,
            ..
        }
    ));
    let log = test.ca.drive_set().audit_log().unwrap();
    assert!(log.entries().iter().any(|e| e.action == AuditAction::ReplaceYubikey && e.serial == Some(old_main.serial())));
    let new_master_crl = state.current_crl(master.serial()).unwrap().der.clone();
    // Clients checking CRLs reject the old sub-intermediates: revoked at depth 2.
    let at = test.now + Duration::minutes(30);
    let error = verify_with_crls(
        &leaf,
        &[&first_cert.der, &old_main.der],
        &master.der,
        &[&new_master_crl, &old_main_crl, &leaf_crl],
        at,
    )
    .unwrap_err();
    assert!(error.is_revoked_at(2), "{error}");
    let reissue: Vec<_> = state
        .reissue_candidates(test.now)
        .iter()
        .map(|c| c.serial())
        .collect();
    assert_eq!(reissue.len(), 2);
    let report = test.ca.startup_report(test.now).unwrap();
    assert!(
        report
            .warnings
            .iter()
            .any(|w| matches!(w, StartupWarning::ReissueNeeded(list) if list.len() == 2))
    );
    assert!(report.hierarchy.active_main.is_none());
    // The old main intermediate's CRL can no longer be refreshed.
    let time = test.tick();
    assert!(test.ca.plan_refresh_crl(old_main.serial(), time).is_err());

    // Step 3: Flow B on a new YubiKey; the master's CRL address is reused.
    let (mut new_token, _) = token(50_000_002);
    let time = test.tick();
    let request = MainIntermediateRequest::new(test_name("E1 New Main"), None);
    let plan = test
        .ca
        .plan_yubikey_setup(&mut new_token, &request, time)
        .unwrap();
    assert_eq!(
        plan.review().value("Master CRL address"),
        Some(MASTER_CRL_URL)
    );
    let trust = new_token.attestation_trust();
    let new_main = plan
        .execute(
            &test.ca,
            &mut new_token,
            &fresh_secrets(&master_words),
            &trust,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();

    // Re-issue one sub-intermediate under the new main intermediate (Flow C).
    let state = test.ca.state().unwrap();
    let candidate = state.certificate(first.serial).unwrap();
    let time = test.tick();
    let request = SubIntermediateRequest::new(
        keystone_core::model::NameFields {
            common_name: candidate.record.subject.common_name.clone(),
            organization: candidate.record.subject.organization.clone(),
            country: candidate.record.subject.country.clone(),
        },
        constrained(&["starnet"]),
        Some(main_crl()),
    );
    let plan = test.ca.plan_sub_intermediate(&request, time).unwrap();
    let (passphrase, _) = sub_passphrase();
    testing::supply_generated_key(keys::rsa4096(3));
    let reissued = plan
        .execute(
            &test.ca,
            &mut new_token,
            &s(PIN),
            &passphrase,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    let state = test.ca.state().unwrap();
    let reissue: Vec<_> = state
        .reissue_candidates(test.now)
        .iter()
        .map(|c| c.serial())
        .collect();
    assert_eq!(reissue, [second.serial]);
    let new_main_cert = state.certificate(new_main.serial).unwrap();
    let reissued_cert = state.certificate(reissued.serial).unwrap();
    verify_chain(
        &reissued_cert.der,
        &[&new_main_cert.der],
        &[&master.der],
        &[],
        &VerifyOptions::at(test.now),
    )
    .unwrap();
    let new_main_crl = state.current_crl(new_main.serial).unwrap().der.clone();
    let new_leaf = issue_test_leaf(
        &reissued_cert.der,
        keys::rsa4096(3),
        keys::rsa2048(3),
        &["host.starnet"],
        &[],
    );
    let new_leaf_crl = issue_test_leaf_crl(&reissued_cert.der, keys::rsa4096(3), &[]);
    verify_with_crls(
        &new_leaf,
        &[&reissued_cert.der, &new_main_cert.der],
        &master.der,
        &[&new_master_crl, &new_main_crl, &new_leaf_crl],
        test.now + Duration::minutes(30),
    )
    .expect("the re-issued chain verifies with CRL checks");
    // No signature was ever needed from the lost YubiKey.
    assert_eq!(old_controller.signature_count(), signatures);
    assert_consistent(&test.ca);
}
