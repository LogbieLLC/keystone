//! `openssl pkey` and `openssl asn1parse` on Keystone's encrypted keys (FR-04).
#![forbid(unsafe_code)]

use keystone_core::crypto::pem;
use keystone_core::crypto::pkcs8::{
    contains_plaintext_private_key, encrypt_master_key_pem, encrypt_sub_key_pem,
};
use keystone_core::crypto::secret::SecretString;
use keystone_testkit::keys;

use crate::support::{Workspace, openssl_cli, text};

const PASSPHRASE: &str = "KEYSTONE TEST abacus bamboo cactus dolphin eagle falcon garden harbor";

fn passphrase() -> SecretString {
    SecretString::from_str_copy(PASSPHRASE).unwrap()
}

/// (type, value) of every primitive line of `openssl asn1parse`, in order.
fn primitives(asn1parse: &str) -> Vec<(String, String)> {
    asn1parse
        .lines()
        .filter_map(|line| line.split_once("prim:"))
        .map(|(_, rest)| match rest.split_once(':') {
            Some((kind, value)) => (kind.trim().to_owned(), value.trim().to_owned()),
            None => (rest.trim().to_owned(), String::new()),
        })
        .collect()
}

fn asn1parse(workspace: &Workspace, file: &str) -> Vec<(String, String)> {
    let output = openssl_cli(workspace.path(), &["asn1parse", "-in", file]);
    assert!(output.status.success(), "{}", text(&output));
    primitives(&String::from_utf8_lossy(&output.stdout))
}

fn assert_octets(entry: &(String, String), bytes: usize) {
    assert!(entry.0.starts_with("OCTET STRING"), "{entry:?}");
    assert_eq!(entry.1.len(), bytes * 2, "{entry:?}");
}

fn check_pkey_decrypts(workspace: &Workspace, key_pem: &str, expected_spki: &[u8]) {
    workspace.write("key.pem", key_pem);
    workspace.write("pass.txt", format!("{PASSPHRASE}\n"));
    // Only the public key is printed, so no plaintext key reaches any output.
    let output = openssl_cli(
        workspace.path(),
        &[
            "pkey",
            "-in",
            "key.pem",
            "-passin",
            "file:pass.txt",
            "-pubout",
        ],
    );
    assert!(
        output.status.success(),
        "openssl pkey failed: {}",
        text(&output)
    );
    let public = pem::decode_one(&output.stdout, "PUBLIC KEY", 1 << 20).unwrap();
    assert_eq!(public, expected_spki);
    assert!(!contains_plaintext_private_key(&output.stdout));
    workspace.write("wrong.txt", "KEYSTONE TEST wrong words\n");
    let wrong = openssl_cli(
        workspace.path(),
        &[
            "pkey",
            "-in",
            "key.pem",
            "-passin",
            "file:wrong.txt",
            "-noout",
        ],
    );
    assert!(!wrong.status.success(), "a wrong passphrase must fail");
}

#[test]
fn fr04_ac2_openssl_pkey_decrypts_the_master_key() {
    // Covers: FR-04 AC2, FR-04 AC1
    let key = keys::master(0);
    let workspace = Workspace::new();
    let pem = encrypt_master_key_pem(key, &passphrase()).unwrap();
    check_pkey_decrypts(&workspace, &pem, &key.public_key_spki_der().unwrap());
}

#[test]
fn fr04_ac2_openssl_pkey_decrypts_a_sub_intermediate_key() {
    // Covers: FR-04 AC2, FR-04 AC1, SEC-15
    let key = keys::rsa4096(0);
    let workspace = Workspace::new();
    let pem = encrypt_sub_key_pem(key, &passphrase()).unwrap();
    check_pkey_decrypts(&workspace, &pem, &key.public_key_spki_der().unwrap());
}

#[test]
fn fr04_ac1_asn1parse_shows_pbes2_scrypt_aes256cbc_for_the_master() {
    // Covers: FR-04 AC1, SEC-04
    let workspace = Workspace::new();
    workspace.write(
        "key.pem",
        encrypt_master_key_pem(keys::master(0), &passphrase()).unwrap(),
    );
    let fields = asn1parse(&workspace, "key.pem");
    assert_eq!(fields.len(), 9, "{fields:#?}");
    assert_eq!(fields[0], ("OBJECT".into(), "PBES2".into()));
    assert_eq!(fields[1], ("OBJECT".into(), "scrypt".into()));
    assert_octets(&fields[2], 16);
    assert_eq!(fields[3], ("INTEGER".into(), "4000".into()), "N = 2^14");
    assert_eq!(fields[4], ("INTEGER".into(), "08".into()), "r = 8");
    assert_eq!(fields[5], ("INTEGER".into(), "01".into()), "p = 1");
    assert_eq!(fields[6], ("OBJECT".into(), "aes-256-cbc".into()));
    assert_octets(&fields[7], 16);
    assert!(fields[8].0.starts_with("OCTET STRING"));
}

#[test]
fn fr04_ac1_asn1parse_shows_pbkdf2_sha256_600000_aes256cbc_for_a_sub() {
    // Covers: FR-04 AC1, SEC-04
    let workspace = Workspace::new();
    workspace.write(
        "key.pem",
        encrypt_sub_key_pem(keys::rsa4096(0), &passphrase()).unwrap(),
    );
    let fields = asn1parse(&workspace, "key.pem");
    assert_eq!(fields.len(), 9, "{fields:#?}");
    assert_eq!(fields[0], ("OBJECT".into(), "PBES2".into()));
    assert_eq!(fields[1], ("OBJECT".into(), "PBKDF2".into()));
    assert_octets(&fields[2], 16);
    assert_eq!(
        fields[3],
        ("INTEGER".into(), "0927C0".into()),
        "600,000 iterations"
    );
    assert_eq!(fields[4], ("OBJECT".into(), "hmacWithSHA256".into()));
    assert_eq!(fields[5].0, "NULL");
    assert_eq!(fields[6], ("OBJECT".into(), "aes-256-cbc".into()));
    assert_octets(&fields[7], 16);
    assert!(fields[8].0.starts_with("OCTET STRING"));
    assert_eq!(i64::from_str_radix(&fields[3].1, 16).unwrap(), 600_000);
}
