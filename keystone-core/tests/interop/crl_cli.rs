//! `openssl verify -crl_check_all` with local CRL files: revocation works at
//! depth 1 (sub-intermediate) and depth 2 (main intermediate), each scenario on its
//! own fresh hierarchy (FR-13 AC5, local part; the StarnetAuth `-crl_download`
//! part is in `blocked`).
#![forbid(unsafe_code)]

use keystone_core::cert::SoftwareSigner;
use keystone_core::crl::{RevokedEntry, crl_with_revocation};
use keystone_core::crypto::verify::crl_der_to_pem;
use keystone_core::model::RevocationReason;
use keystone_core::token::TokenCaSigner;
use keystone_testkit::hierarchy::{HierarchyOptions, TestHierarchy, test_pin};
use keystone_testkit::keys;
use keystone_testkit::x509::{issue_test_leaf, issue_test_leaf_crl};
use time::{Duration, OffsetDateTime};

use crate::support::{Workspace, openssl, text};

/// Every "error N at D depth lookup" line of `openssl verify`.
fn verify_errors(output: &str) -> Vec<(u32, u32)> {
    output
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("error ")?;
            let (code, rest) = rest.split_once(" at ")?;
            let (depth, _) = rest.split_once(" depth lookup")?;
            Some((code.parse().ok()?, depth.parse().ok()?))
        })
        .collect()
}

struct Files {
    workspace: Workspace,
}

impl Files {
    fn new(h: &TestHierarchy, leaf: &[u8], sub_crl: &[u8]) -> Files {
        let workspace = Workspace::new();
        workspace.write("master.crt", &h.master.pem);
        workspace.write_certs("untrusted.pem", &[&h.sub.der, &h.main.der]);
        workspace.write_certs("leaf.crt", &[leaf]);
        workspace.write("master.crl", &h.master_crl.pem);
        workspace.write("main.crl", &h.main_crl.pem);
        workspace.write("sub.crl", crl_der_to_pem(sub_crl).unwrap());
        Files { workspace }
    }

    fn verify(&self) -> (bool, String) {
        let output = openssl(
            self.workspace.path(),
            &[
                "verify",
                "-crl_check_all",
                "-CAfile",
                "master.crt",
                "-untrusted",
                "untrusted.pem",
                "-CRLfile",
                "master.crl",
                "-CRLfile",
                "main.crl",
                "-CRLfile",
                "sub.crl",
                "leaf.crt",
            ],
        );
        (output.status.success(), text(&output))
    }
}

fn build(
    label: &str,
    master_key_index: usize,
    sub_key_index: usize,
) -> (TestHierarchy, Vec<u8>, Vec<u8>) {
    let h = TestHierarchy::build(&HierarchyOptions {
        label: label.into(),
        master_key_index,
        sub_key_index,
        ..HierarchyOptions::default()
    });
    let leaf = issue_test_leaf(
        &h.sub.der,
        h.sub_key,
        keys::rsa2048(1),
        &["www.starnet"],
        &[],
    );
    let sub_crl = issue_test_leaf_crl(&h.sub.der, h.sub_key, &[]);
    (h, leaf, sub_crl)
}

#[test]
fn fr13_ac5_scenario_a_revoked_sub_intermediate_fails_at_depth_1() {
    // Covers: FR-13 AC5, FR-13 AC1, SEC-12, SEC-14
    // Before revocation the chain passes -crl_check_all with each issuer's first,
    // empty CRL. That an issuer gets that CRL in the operation that creates it, and
    // cannot sign a child before (FR-13 AC6), is shown by the Flow A, Flow B and
    // recovery tests in tests/ops.
    let (h, leaf, sub_crl) = build("CLI Scenario A", 0, 4);
    let files = Files::new(&h, &leaf, &sub_crl);
    let (ok, output) = files.verify();
    assert!(ok, "the leaf verifies before revocation: {output}");

    let now = OffsetDateTime::now_utc();
    let pin = test_pin();
    let mut token = h.token.reopen();
    let crl = crl_with_revocation(
        &h.main_crl.der,
        &h.main.der,
        RevokedEntry {
            serial: h.sub.info.serial,
            revocation_date: now - Duration::seconds(1),
            reason: RevocationReason::KeyCompromise,
        },
        now,
        &mut TokenCaSigner::new(&mut token, &pin),
    )
    .unwrap();
    files.workspace.write("main.crl", &crl.pem);
    let (ok, output) = files.verify();
    assert!(!ok, "{output}");
    assert_eq!(
        verify_errors(&output),
        [(23, 1)],
        "only 'certificate revoked' at depth 1: {output}"
    );
    assert!(output.contains("certificate revoked"), "{output}");
}

#[test]
fn fr13_ac5_scenario_b_revoked_main_intermediate_fails_at_depth_2() {
    // Covers: FR-13 AC5, FR-13 AC1, SEC-12
    // As in scenario A, the first CRLs alone pass -crl_check_all before revocation;
    // FR-13 AC6 itself is shown by the tests in tests/ops.
    let (h, leaf, sub_crl) = build("CLI Scenario B", 1, 5);
    let files = Files::new(&h, &leaf, &sub_crl);
    let (ok, output) = files.verify();
    assert!(ok, "the leaf verifies before revocation: {output}");

    let now = OffsetDateTime::now_utc();
    let crl = crl_with_revocation(
        &h.master_crl.der,
        &h.master.der,
        RevokedEntry {
            serial: h.main.info.serial,
            revocation_date: now - Duration::seconds(1),
            reason: RevocationReason::CaCompromise,
        },
        now,
        &mut SoftwareSigner::new(h.master_key),
    )
    .unwrap();
    files.workspace.write("master.crl", &crl.pem);
    let (ok, output) = files.verify();
    assert!(!ok, "{output}");
    assert_eq!(
        verify_errors(&output),
        [(23, 2)],
        "only 'certificate revoked' at depth 2: {output}"
    );
    assert!(output.contains("certificate revoked"), "{output}");
}
