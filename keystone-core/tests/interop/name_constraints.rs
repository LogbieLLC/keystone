//! Name constraints enforced by real verifiers: `openssl verify` and Go's
//! crypto/x509 (FR-21 AC5, SEC-21).
#![forbid(unsafe_code)]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use keystone_testkit::hierarchy::{HierarchyOptions, TestHierarchy};
use keystone_testkit::keys;
use keystone_testkit::x509::{issue_test_leaf, issue_test_leaf_with_email};

use crate::support::{Workspace, go_verify, openssl, text};

/// Permitted DNS name `starnet`, no IP range (all IPs excluded).
fn dns_only() -> &'static TestHierarchy {
    static H: OnceLock<TestHierarchy> = OnceLock::new();
    H.get_or_init(|| {
        TestHierarchy::build(&HierarchyOptions {
            label: "NC DNS".into(),
            sub_key_index: 1,
            ..HierarchyOptions::default()
        })
    })
}

/// Permitted DNS name `starnet` and IPv4 range 10.0.0.0/8 (IPv6 still excluded).
fn dns_and_ip() -> &'static TestHierarchy {
    static H: OnceLock<TestHierarchy> = OnceLock::new();
    H.get_or_init(|| {
        TestHierarchy::build(&HierarchyOptions {
            label: "NC IP".into(),
            sub_key_index: 2,
            permitted_ip: vec!["10.0.0.0/8".into()],
            ..HierarchyOptions::default()
        })
    })
}

struct Verdicts {
    openssl_ok: bool,
    openssl_output: String,
    go_ok: bool,
    go_output: String,
}

fn verify_both(h: &TestHierarchy, leaf: &[u8]) -> Verdicts {
    let workspace = Workspace::new();
    let roots = workspace.write("master.crt", &h.master.pem);
    let intermediates = workspace.write_certs("intermediates.pem", &[&h.sub.der, &h.main.der]);
    let leaf_path = workspace.write_certs("leaf.crt", &[leaf]);
    let output = openssl(
        workspace.path(),
        &[
            "verify",
            "-CAfile",
            "master.crt",
            "-untrusted",
            "intermediates.pem",
            "leaf.crt",
        ],
    );
    let (go_ok, go_output) = go_verify(&workspace, &roots, &intermediates, &leaf_path);
    Verdicts {
        openssl_ok: output.status.success(),
        openssl_output: text(&output),
        go_ok,
        go_output,
    }
}

fn leaf(h: &TestHierarchy, dns: &[&str], ips: &[IpAddr]) -> Vec<u8> {
    issue_test_leaf(&h.sub.der, h.sub_key, keys::rsa2048(2), dns, ips)
}

fn assert_accepted(h: &TestHierarchy, dns: &[&str], ips: &[IpAddr]) {
    let v = verify_both(h, &leaf(h, dns, ips));
    assert!(
        v.openssl_ok,
        "openssl rejected {dns:?} {ips:?}: {}",
        v.openssl_output
    );
    assert!(v.go_ok, "Go rejected {dns:?} {ips:?}: {}", v.go_output);
}

fn assert_rejected_by_constraints(h: &TestHierarchy, dns: &[&str], ips: &[IpAddr]) {
    let v = verify_both(h, &leaf(h, dns, ips));
    assert!(!v.openssl_ok, "openssl accepted {dns:?} {ips:?}");
    assert!(
        v.openssl_output.contains("subtree violation"),
        "openssl must fail on the name constraints: {}",
        v.openssl_output
    );
    assert!(!v.go_ok, "Go accepted {dns:?} {ips:?}");
    assert!(
        v.go_output.contains("not authorized to sign for this name")
            || v.go_output.contains("constraint"),
        "Go must fail on the name constraints: {}",
        v.go_output
    );
}

const TEST_NET_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
const PERMITTED_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
const DOC_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));

#[test]
fn fr21_ac5_permitted_names_verify_with_openssl_and_go() {
    // Covers: FR-21 AC5, FR-21 AC1, SEC-21
    let h = dns_only();
    assert_accepted(h, &["host.starnet"], &[]);
    assert_accepted(h, &["starnet"], &[]);
    assert_accepted(h, &["a.b.starnet", "starnet"], &[]);
}

#[test]
fn fr21_ac5_other_dns_names_fail_with_openssl_and_go() {
    // Covers: FR-21 AC5, SEC-21
    let h = dns_only();
    assert_rejected_by_constraints(h, &["host.example.com"], &[]);
    assert_rejected_by_constraints(h, &["notstarnet"], &[]);
    assert_rejected_by_constraints(h, &["host.starnet", "evil.example"], &[]);
}

#[test]
fn fr21_ac5_ip_addresses_are_excluded_without_permitted_ranges() {
    // Covers: FR-21 AC5, FR-21 AC3, SEC-21
    let h = dns_only();
    assert_rejected_by_constraints(h, &["host.starnet"], &[TEST_NET_V4]);
    assert_rejected_by_constraints(h, &["host.starnet"], &[DOC_V6]);
}

#[test]
fn fr21_ac5_only_permitted_ip_ranges_verify() {
    // Covers: FR-21 AC5, FR-21 AC3, SEC-21
    let h = dns_and_ip();
    assert_accepted(h, &["host.starnet"], &[PERMITTED_V4]);
    assert_rejected_by_constraints(h, &["host.starnet"], &[TEST_NET_V4]);
    assert_rejected_by_constraints(h, &["host.starnet"], &[DOC_V6]);
}

#[test]
fn fr21_ac3_go_rejects_email_names_under_the_zero_length_exclusion() {
    // Covers: FR-21 AC3
    // Go (like NSS) treats the zero-length rfc822Name exclusion as "all email".
    // OpenSSL compares it literally and does not reject on it (see profile.rs).
    let h = dns_only();
    let leaf = issue_test_leaf_with_email(
        &h.sub.der,
        h.sub_key,
        keys::rsa2048(2),
        &["host.starnet"],
        &[],
        &["ops@starnet"],
    );
    let v = verify_both(h, &leaf);
    assert!(!v.go_ok, "Go accepted an email name: {}", v.go_output);
    assert!(
        v.go_output.contains("excluded") || v.go_output.contains("constraint"),
        "{}",
        v.go_output
    );
}
