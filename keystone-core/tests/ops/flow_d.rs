//! Flow D (revoke and publish a CRL) and Refresh CRL (FR-11, FR-13 AC1 to AC4, FR-14).
#![forbid(unsafe_code)]

use keystone_core::crl::{CrlFreshness, parse_crl_der};
use keystone_core::crypto::CancelFlag;
use keystone_core::crypto::verify::verify_crl_signature;
use keystone_core::model::RevocationReason;
use keystone_core::ops::{
    CrlPlanKind, ExportStatus, IssuerUnlock, NoProgress, OpsError, StartupWarning,
};
use keystone_core::store::{AuditAction, CertStatus, OperationState};
use keystone_testkit::keys;
use keystone_testkit::x509::{issue_test_leaf, issue_test_leaf_crl};
use time::Duration;

use crate::support::*;

#[test]
fn flow_d_revoking_a_sub_intermediate_makes_its_leaf_fail_at_depth_1() {
    // Covers: FR-13 AC1, FR-13 AC2, FR-13 AC5, FR-11 AC1, FR-14 AC1
    let (mut test, mut token, controller) = ca_with_main("D1", 40_000_001);
    let (sub, _) = run_flow_c(&mut test, &mut token, "D1", 1, false).unwrap();
    let state = test.ca.state().unwrap();
    let (master, main) = (
        state.master().unwrap(),
        state.active_main(test.now).unwrap(),
    );
    let sub_cert = state.certificate(sub.serial).unwrap();
    let leaf = issue_test_leaf(
        &sub_cert.der,
        keys::rsa4096(1),
        keys::rsa2048(0),
        &["host.starnet"],
        &[],
    );
    let leaf_crl = issue_test_leaf_crl(&sub_cert.der, keys::rsa4096(1), &[]);
    let master_crl = state.current_crl(master.serial()).unwrap().der.clone();
    let first_main_crl = state.current_crl(main.serial()).unwrap().der.clone();
    let at = test.now + Duration::minutes(30);
    let untrusted: [&[u8]; 2] = [&sub_cert.der, &main.der];
    verify_with_crls(
        &leaf,
        &untrusted,
        &master.der,
        &[&master_crl, &first_main_crl, &leaf_crl],
        at,
    )
    .expect("verifies before revocation");

    let time = test.tick();
    let plan = test
        .ca
        .plan_revoke(sub.serial, RevocationReason::KeyCompromise, time)
        .unwrap();
    assert!(!plan.needs_master());
    assert!(
        plan.review()
            .value("Signed by")
            .unwrap()
            .contains("YubiKey")
    );
    assert!(plan.review().value("New CRL").unwrap().contains("number 2"));
    let touches = controller.touch_requests();
    let pin = s(PIN);
    let outcome = plan
        .execute(
            &test.ca,
            IssuerUnlock::YubiKey {
                token: &mut token,
                pin: &pin,
            },
            Some(test.export()),
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    assert_eq!(controller.touch_requests(), touches + 1);
    assert_eq!(outcome.crl_number, 2);
    assert_eq!(outcome.revoked, Some(sub.serial));
    assert!(outcome.revoked_by_ancestor.is_empty());
    let state = test.ca.state().unwrap();
    let crl = state.current_crl(main.serial()).unwrap();
    assert_eq!(crl.info.revoked.len(), 1);
    assert_eq!(crl.info.revoked[0].serial, sub.serial);
    assert_eq!(crl.info.revoked[0].reason, RevocationReason::KeyCompromise);
    verify_crl_signature(&crl.der, &main.info.spki_der).unwrap();
    let ExportStatus::Written(files) = &outcome.export else {
        panic!("{:?}", outcome.export);
    };
    assert_eq!(std::fs::read(&files[0].path).unwrap(), crl.der);
    // FR-13 AC5 (local CRLs): the failure is "certificate revoked" at depth 1.
    let error = verify_with_crls(
        &leaf,
        &untrusted,
        &master.der,
        &[&master_crl, &crl.der, &leaf_crl],
        at,
    )
    .unwrap_err();
    assert!(error.is_revoked_at(1), "{error}");
    // FR-11 AC1: status, date and reason recorded; FR-14 AC1: audited.
    let recorded = state.record().get(sub.serial).unwrap();
    assert!(matches!(
        recorded.status,
        CertStatus::Revoked {
            reason: RevocationReason::KeyCompromise,
            ..
        }
    ));
    let log = test.ca.drive_set().audit_log().unwrap();
    let entry = log
        .entries()
        .iter()
        .find(|e| e.action == AuditAction::Revoke)
        .unwrap();
    assert_eq!(entry.serial, Some(sub.serial));
    let details = entry.details.as_ref().unwrap();
    assert_eq!(
        details.revocation_reason,
        Some(RevocationReason::KeyCompromise)
    );
    assert_eq!(details.crl_number, Some(2));
    // Revoking again is refused.
    let time = test.tick();
    assert!(
        test.ca
            .plan_revoke(sub.serial, RevocationReason::Superseded, time)
            .is_err()
    );
    assert_consistent(&test.ca);
}

#[test]
fn flow_d_revoking_the_main_intermediate_is_signed_by_the_master_and_cuts_off_its_children() {
    // Covers: FR-13 AC1, FR-13 AC5, FR-15 AC1, FR-11 AC1
    let (mut test, mut token, _) = ca_with_main("D2", 40_000_002);
    let (sub, _) = run_flow_c(&mut test, &mut token, "D2", 2, false).unwrap();
    let state = test.ca.state().unwrap();
    let (master, main) = (
        state.master().unwrap(),
        state.active_main(test.now).unwrap().clone(),
    );
    let sub_cert = state.certificate(sub.serial).unwrap().clone();
    let leaf = issue_test_leaf(
        &sub_cert.der,
        keys::rsa4096(2),
        keys::rsa2048(1),
        &["host.starnet"],
        &[],
    );
    let leaf_crl = issue_test_leaf_crl(&sub_cert.der, keys::rsa4096(2), &[]);
    let main_crl = state.current_crl(main.serial()).unwrap().der.clone();

    let time = test.tick();
    let plan = test
        .ca
        .plan_revoke(main.serial(), RevocationReason::CaCompromise, time)
        .unwrap();
    assert!(plan.needs_master());
    assert!(
        plan.review()
            .value("Marked revoked by ancestor")
            .unwrap()
            .contains("D2 Sub")
    );
    // The YubiKey cannot sign the master's CRL.
    let pin = s(PIN);
    let error = test
        .ca
        .plan_revoke(main.serial(), RevocationReason::CaCompromise, time)
        .unwrap()
        .execute(
            &test.ca,
            IssuerUnlock::YubiKey {
                token: &mut token,
                pin: &pin,
            },
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("signed by the master"),
        "{error}"
    );
    let master_words = test.master_entered();
    let outcome = plan
        .execute(
            &test.ca,
            IssuerUnlock::Master(&master_words),
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    assert_eq!(outcome.revoked_by_ancestor, [sub.serial]);
    let state = test.ca.state().unwrap();
    let new_master_crl = state.current_crl(master.serial()).unwrap();
    assert_eq!(new_master_crl.info.crl_number, 2);
    assert!(matches!(
        state.record().get(sub.serial).unwrap().status,
        CertStatus::RevokedByAncestor { ancestor, .. } if ancestor == main.serial()
    ));
    let at = test.now + Duration::minutes(30);
    let error = verify_with_crls(
        &leaf,
        &[&sub_cert.der, &main.der],
        &master.der,
        &[&new_master_crl.der, &main_crl, &leaf_crl],
        at,
    )
    .unwrap_err();
    assert!(error.is_revoked_at(2), "{error}");
    // A revoked main intermediate's CRL can no longer be refreshed, and the sub is cut off.
    let time = test.tick();
    let error = test.ca.plan_refresh_crl(main.serial(), time).unwrap_err();
    assert!(
        error.to_string().contains("can no longer be refreshed"),
        "{error}"
    );
    let error = test
        .ca
        .plan_revoke(sub.serial, RevocationReason::Superseded, time)
        .unwrap_err();
    assert!(error.to_string().contains("cut off"), "{error}");
    assert!(
        test.ca
            .plan_revoke(master.serial(), RevocationReason::Superseded, time)
            .is_err()
    );
    assert_consistent(&test.ca);
}

#[test]
fn fr04_ac3_a_wrong_master_passphrase_stops_a_revocation_without_any_change() {
    // Covers: FR-04 AC3, FR-16 AC2
    let (mut test, _token, _) = ca_with_main("D3", 40_000_003);
    let main = test
        .ca
        .state()
        .unwrap()
        .active_main(test.now)
        .unwrap()
        .serial();
    let time = test.tick();
    let plan = test
        .ca
        .plan_revoke(main, RevocationReason::Superseded, time)
        .unwrap();
    let (_, wrong) = master_passphrase();
    let wrong = entered(&wrong);
    let error = plan
        .execute(
            &test.ca,
            IssuerUnlock::Master(&wrong),
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err();
    let OpsError::Stopped { operation, .. } = &error else {
        panic!("{error}");
    };
    assert!(error.to_string().contains("passphrase is wrong"));
    let journal = test.ca.drive_set().drives()[0]
        .operation_journal(*operation)
        .unwrap()
        .unwrap();
    assert_eq!(journal.state(), OperationState::Cancelled);
    assert_eq!(
        test.ca.state().unwrap().record().get(main).unwrap().status,
        CertStatus::Valid
    );
    assert_consistent(&test.ca);
}

#[test]
fn fr13_ac3_ac4_refresh_warning_and_refresh_crl() {
    // Covers: FR-13 AC3, FR-13 AC4, FR-13 AC2
    let (mut test, mut token, _) = ca_with_main("D4", 40_000_004);
    let state = test.ca.state().unwrap();
    let main = state.active_main(test.now).unwrap().clone();
    let master = state.master().unwrap().clone();
    let first = state.current_crl(main.serial()).unwrap().clone();
    // 90-day main CRL: no warning now, a warning 30 days before nextUpdate, expired after.
    let report = test.ca.startup_report(test.now).unwrap();
    assert!(
        !report
            .warnings
            .iter()
            .any(|w| matches!(w, StartupWarning::CrlRefresh(_)))
    );
    let soon = test.now + Duration::days(61);
    let report = test.ca.startup_report(soon).unwrap();
    let warning = report
        .warnings
        .iter()
        .find_map(|w| match w {
            StartupWarning::CrlRefresh(warning) => Some(warning.clone()),
            _ => None,
        })
        .expect("refresh warning");
    assert_eq!(warning.issuer_serial, main.serial());
    assert!(matches!(
        warning.freshness,
        CrlFreshness::RefreshSoon { days_left: 28 | 29 }
    ));
    let report = test
        .ca
        .startup_report(test.now + Duration::days(91))
        .unwrap();
    assert!(report.warnings.iter().any(
        |w| matches!(w, StartupWarning::CrlRefresh(c) if c.freshness == CrlFreshness::Expired)
    ));

    // The warning opens Refresh CRL: same entries, new dates, a higher number, exported.
    test.now = soon;
    let time = test.tick();
    let plan = test
        .ca
        .plan_refresh_crl(warning.issuer_serial, time)
        .unwrap();
    assert_eq!(plan.kind(), CrlPlanKind::Refresh);
    let pin = s(PIN);
    let outcome = plan
        .execute(
            &test.ca,
            IssuerUnlock::YubiKey {
                token: &mut token,
                pin: &pin,
            },
            Some(test.export()),
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    assert_eq!(outcome.crl_number, 2);
    assert!(outcome.this_update > first.info.this_update);
    assert_eq!((outcome.next_update - outcome.this_update).whole_days(), 90);
    let ExportStatus::Written(files) = &outcome.export else {
        panic!("{:?}", outcome.export);
    };
    let exported = parse_crl_der(&std::fs::read(&files[0].path).unwrap()).unwrap();
    assert_eq!(exported.crl_number, 2);
    assert_eq!(exported.revoked, first.info.revoked);
    let report = test.ca.startup_report(test.now).unwrap();
    assert!(
        !report.warnings.iter().any(
            |w| matches!(w, StartupWarning::CrlRefresh(c) if c.issuer_serial == main.serial())
        )
    );
    // The master's CRL is refreshed with its passphrase (1 year).
    let time = test.tick();
    let master_words = test.master_entered();
    let outcome = test
        .ca
        .plan_refresh_crl(master.serial(), time)
        .unwrap()
        .execute(
            &test.ca,
            IssuerUnlock::Master(&master_words),
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    assert_eq!(outcome.crl_number, 2);
    assert!((365..=366).contains(&(outcome.next_update - outcome.this_update).whole_days()));
    // An export retried later writes nothing twice and refuses nothing it already has.
    let time = test.tick();
    let files = test
        .ca
        .export_operation(outcome.operation, test.export(), time)
        .unwrap();
    let again = test
        .ca
        .export_operation(outcome.operation, test.export(), time)
        .unwrap();
    assert_eq!(files, again);
    assert_consistent(&test.ca);
}
