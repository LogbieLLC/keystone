//! `openssl verify` on a Keystone hierarchy (FR-09 AC2, SEC-13).
#![forbid(unsafe_code)]

use keystone_core::cert::chain_pem;
use keystone_testkit::hierarchy::{HierarchyOptions, TestHierarchy};

use crate::support::{Workspace, openssl_cli, text};

#[test]
fn fr09_ac2_openssl_verify_sub_against_master_with_main_untrusted() {
    // Covers: FR-09 AC2, FR-09 AC1, SEC-13
    let h = TestHierarchy::build(&HierarchyOptions {
        label: "Verify".into(),
        ..HierarchyOptions::default()
    });
    let workspace = Workspace::new();
    workspace.write("master.crt", &h.master.pem);
    workspace.write("main.crt", &h.main.pem);
    workspace.write("sub.crt", &h.sub.pem);
    workspace.write(
        "sub-chain.pem",
        chain_pem(&h.sub.der, &h.main.der, &h.master.der).unwrap(),
    );

    let output = openssl_cli(
        workspace.path(),
        &[
            "verify",
            "-CAfile",
            "master.crt",
            "-untrusted",
            "main.crt",
            "sub.crt",
        ],
    );
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "sub.crt: OK"
    );

    // RFC 5280 strict mode and the chain file as the untrusted set also pass.
    for args in [
        &[
            "verify",
            "-x509_strict",
            "-CAfile",
            "master.crt",
            "-untrusted",
            "main.crt",
            "sub.crt",
        ][..],
        &[
            "verify",
            "-x509_strict",
            "-CAfile",
            "master.crt",
            "-untrusted",
            "sub-chain.pem",
            "sub.crt",
        ][..],
        &[
            "verify",
            "-x509_strict",
            "-CAfile",
            "master.crt",
            "main.crt",
        ][..],
        &[
            "verify",
            "-x509_strict",
            "-CAfile",
            "master.crt",
            "master.crt",
        ][..],
    ] {
        let output = openssl_cli(workspace.path(), args);
        assert!(output.status.success(), "{args:?}: {}", text(&output));
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .ends_with(": OK")
        );
    }

    // Without the main intermediate the sub-intermediate cannot be verified.
    let output = openssl_cli(
        workspace.path(),
        &["verify", "-CAfile", "master.crt", "sub.crt"],
    );
    assert!(!output.status.success());
}
