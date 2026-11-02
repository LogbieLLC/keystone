//! Writes a complete synthetic KEYSTONE TEST hierarchy to a folder, for the CI jobs
//! that lint every certificate and CRL (FR-10 AC4, SEC-13) and scan every output
//! for plaintext private keys (SEC-04).
//!
//! Usage: cargo run -p keystone-testkit --example generate_samples -- <empty output dir>
//!
//! Development tool only: it uses synthetic test keys from keystone-testkit
//! (TEST-11) and is never part of a production build.
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use keystone_core::cert::{SoftwareSigner, chain_pem};
use keystone_core::crl::{RevokedEntry, crl_with_revocation};
use keystone_core::crypto::pkcs8::{encrypt_master_key_pem, encrypt_sub_key_pem};
use keystone_core::crypto::secret::SecretString;
use keystone_core::model::RevocationReason;
use keystone_testkit::hierarchy::{HierarchyOptions, TestHierarchy};

fn main() {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: generate_samples <empty output dir>");
    fs::create_dir_all(&output).expect("create output dir");
    assert!(
        fs::read_dir(&output)
            .expect("read output dir")
            .next()
            .is_none(),
        "output dir must be empty"
    );

    let constrained = TestHierarchy::build(&HierarchyOptions::default());
    write_hierarchy(&output.join("constrained"), &constrained);

    let unconstrained = TestHierarchy::build(&HierarchyOptions {
        unconstrained_sub: true,
        label: "unconstrained".to_owned(),
        ..HierarchyOptions::default()
    });
    write_hierarchy(&output.join("unconstrained"), &unconstrained);
}

fn write_hierarchy(dir: &Path, hierarchy: &TestHierarchy) {
    fs::create_dir_all(dir).expect("create hierarchy dir");
    let write = |name: &str, contents: &[u8]| {
        fs::write(dir.join(name), contents).expect("write sample");
    };
    write("master.crt", hierarchy.master.pem.as_bytes());
    write("main.crt", hierarchy.main.pem.as_bytes());
    write("sub.crt", hierarchy.sub.pem.as_bytes());
    write("master.crl", hierarchy.master_crl.pem.as_bytes());
    write("main.crl", hierarchy.main_crl.pem.as_bytes());
    let chain = chain_pem(
        &hierarchy.sub.der,
        &hierarchy.main.der,
        &hierarchy.master.der,
    )
    .expect("chain");
    write("sub-chain.pem", chain.as_bytes());

    // A master CRL that revokes the main intermediate, signed by the master key.
    let mut master_signer = SoftwareSigner::new(hierarchy.master_key);
    let revoked = crl_with_revocation(
        &hierarchy.master_crl.der,
        &hierarchy.master.der,
        RevokedEntry {
            serial: hierarchy.main.info.serial,
            revocation_date: hierarchy.master_crl.info.this_update,
            reason: RevocationReason::KeyCompromise,
        },
        hierarchy.master_crl.info.this_update,
        &mut master_signer,
    )
    .expect("revocation CRL");
    write("master-revoked.crl", revoked.pem.as_bytes());

    // Encrypted keys (the only form a private key is ever written in, SEC-04).
    let passphrase =
        SecretString::from_str_copy("keystone test sample passphrase only").expect("locked memory");
    let master_key = encrypt_master_key_pem(hierarchy.master_key, &passphrase).expect("encrypt");
    write("master.key", master_key.as_bytes());
    let sub_key = encrypt_sub_key_pem(hierarchy.sub_key, &passphrase).expect("encrypt");
    write("sub.key", sub_key.as_bytes());
}
