//! SEC-04: every file Keystone writes for a hierarchy is free of plaintext private
//! keys, checked with the Rust helper and with `scripts/scan-plaintext-keys.sh`.
#![forbid(unsafe_code)]

use std::process::Command;

use keystone_core::cert::chain_pem;
use keystone_core::crypto::pem;
use keystone_core::crypto::pkcs8::{
    contains_plaintext_private_key, encrypt_master_key_pem, encrypt_sub_key_pem,
};
use keystone_core::crypto::secret::SecretString;
use keystone_testkit::hierarchy::{HierarchyOptions, TestHierarchy};

use crate::support::{Workspace, text};

fn scan_script(dir: &std::path::Path) -> (bool, String) {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scripts/scan-plaintext-keys.sh"
    );
    let output = Command::new("bash")
        .arg(script)
        .arg(dir)
        .output()
        .expect("bash must be installed");
    (output.status.success(), text(&output))
}

#[test]
fn sec04_no_output_file_contains_a_plaintext_private_key() {
    // Covers: SEC-04, SEC-15, FR-09 AC1
    let h = TestHierarchy::build(&HierarchyOptions {
        label: "Scan".into(),
        sub_key_index: 3,
        ..HierarchyOptions::default()
    });
    let words = SecretString::from_str_copy("KEYSTONE TEST scan words for the test only").unwrap();
    let workspace = Workspace::new();
    let files = [
        ("master.crt", h.master.pem.clone()),
        (
            "master.key",
            encrypt_master_key_pem(h.master_key, &words).unwrap(),
        ),
        ("master.crl", h.master_crl.pem.clone()),
        ("main.crt", h.main.pem.clone()),
        ("main.crl", h.main_crl.pem.clone()),
        ("sub.crt", h.sub.pem.clone()),
        ("sub.key", encrypt_sub_key_pem(h.sub_key, &words).unwrap()),
        (
            "sub-chain.pem",
            chain_pem(&h.sub.der, &h.main.der, &h.master.der).unwrap(),
        ),
    ];
    for (name, contents) in &files {
        workspace.write(name, contents);
        assert!(
            !contains_plaintext_private_key(contents.as_bytes()),
            "{name}"
        );
    }
    workspace.write("master.der", &h.master.der);
    workspace.write("main.crl.der", &h.main_crl.der);
    assert!(!contains_plaintext_private_key(&h.master.der));
    assert!(!contains_plaintext_private_key(&h.main_crl.der));
    let (clean, output) = scan_script(workspace.path());
    assert!(clean, "{output}");

    // Negative control: the scanners do flag a plaintext private-key file.
    let control = Workspace::new();
    let fake = pem::encode("PRIVATE KEY", &[0x30, 0x03, 0x02, 0x01, 0x00]);
    control.write("leaked.key", &fake);
    assert!(contains_plaintext_private_key(fake.as_bytes()));
    let (clean, _) = scan_script(control.path());
    assert!(!clean, "the scanner script must flag a plaintext key label");
}
