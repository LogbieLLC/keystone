//! `scripts/check-boundaries.sh` catches the known ways around it (SEC-18, SECP-06;
//! review finding N2).
//!
//! Each case builds a small synthetic repository in a `tempfile` directory (TEST-12):
//! the boundary script, a crate root that denies `unsafe_code`, a crypto module with
//! the one allowed FFI file, and one ordinary file. The clean tree must pass; each
//! case then adds one bypass and the script must fail with the matching message.
//! The script needs `bash`, `git`, `perl`, `grep` and `sed`, as in CI.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The baseline tree: (path, contents).
const BASELINE: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        "[workspace]\nmembers = [\"keystone-core\"]\n\n[workspace.dependencies]\nopenssl = \"=0.10.81\"\nopenssl-sys = \"=0.9.117\"\n",
    ),
    (
        "keystone-core/Cargo.toml",
        "[package]\nname = \"keystone-core\"\n\n[dependencies]\nopenssl.workspace = true\nopenssl-sys.workspace = true\n",
    ),
    (
        "keystone-core/src/lib.rs",
        "//! KEYSTONE TEST crate root.\n#![deny(unsafe_code)]\n\npub mod crypto;\npub mod other;\n",
    ),
    (
        "keystone-core/src/crypto/mod.rs",
        "//! KEYSTONE TEST crypto module.\n\n#[allow(unsafe_code)]\nmod ffi;\npub mod rand;\n",
    ),
    (
        "keystone-core/src/crypto/ffi.rs",
        "//! KEYSTONE TEST FFI module.\nuse openssl_sys as sys;\n\npub(crate) fn read(p: *const u8) -> u8 {\n    // SAFETY: test only.\n    unsafe { *p }\n}\n",
    ),
    (
        "keystone-core/src/crypto/rand.rs",
        "#![forbid(unsafe_code)]\n\npub fn fill(buf: &mut [u8]) {\n    openssl::rand::rand_bytes(buf).unwrap();\n}\n",
    ),
    (
        "keystone-core/src/other.rs",
        "#![forbid(unsafe_code)]\n//! Mentions unsafe code and openssl::rand in a comment only.\n\n/* unsafe { openssl::x() } in a block comment */\npub fn message() -> &'static str {\n    \"unsafe openssl_sys::x() in a string\"\n}\n\npub fn quote() -> char {\n    '\"'\n}\n",
    ),
];

/// Writes the baseline with `changes` applied (a `None` body deletes the file) and
/// runs the boundary script. Returns (passed, stderr).
fn run(changes: &[(&str, Option<&str>)]) -> (bool, String) {
    let dir = tempfile::tempdir().expect("temporary directory");
    let root = dir.path();
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("scripts")
        .join("check-boundaries.sh");
    write(
        root,
        "scripts/check-boundaries.sh",
        &std::fs::read_to_string(script).expect("script"),
    );
    for (path, contents) in BASELINE {
        if !changes.iter().any(|(changed, _)| changed == path) {
            write(root, path, contents);
        }
    }
    for (path, contents) in changes {
        if let Some(contents) = contents {
            write(root, path, contents);
        }
    }
    let git = Command::new("git")
        .args(["init", "-q"])
        .current_dir(root)
        .output()
        .expect("git must be installed");
    assert!(git.status.success(), "git init failed");
    let output = Command::new("bash")
        .arg("scripts/check-boundaries.sh")
        .current_dir(root)
        .output()
        .expect("bash must be installed");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn write(root: &Path, path: &str, contents: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("create directory");
    std::fs::write(path, contents).expect("write test file");
}

/// Asserts that the script fails on `changes` with a message containing `expected`.
fn caught(changes: &[(&str, Option<&str>)], expected: &str) {
    let (passed, stderr) = run(changes);
    assert!(!passed, "bypass not caught: {changes:?}");
    assert!(
        stderr.contains(expected),
        "expected {expected:?} for {changes:?}, got:\n{stderr}"
    );
}

const OTHER: &str = "keystone-core/src/other.rs";
const ROOT: &str = "keystone-core/src/lib.rs";

fn other(body: &str) -> String {
    format!("#![forbid(unsafe_code)]\n\n{body}\n")
}

#[test]
fn sec18_the_clean_tree_passes_and_comments_or_strings_are_not_code() {
    // Covers: SEC-18
    let (passed, stderr) = run(&[]);
    assert!(passed, "{stderr}");
}

#[test]
fn sec18_openssl_outside_crypto_is_caught_in_every_spelling() {
    // Covers: SEC-18
    for body in [
        "use openssl as ossl;\npub fn f(b: &mut [u8]) { ossl::rand::rand_bytes(b).unwrap(); }",
        "pub fn f(b: &mut [u8]) { ::openssl::rand::rand_bytes(b).unwrap(); }",
        "extern crate openssl;",
        "extern crate openssl as ossl;",
        "use openssl;",
        "use {openssl::rand as r};",
        "pub fn f() { unsafe_free(openssl_sys::EVP_PKEY_new()); }",
        "use openssl_sys as s;",
    ] {
        caught(
            &[(OTHER, Some(&other(body)))],
            "names the OpenSSL crate outside keystone-core/src/crypto/",
        );
    }
    // The same outside keystone-core, in a fuzz target.
    caught(
        &[(
            "fuzz/fuzz_targets/x.rs",
            Some("#![forbid(unsafe_code)]\nuse openssl as o;\n"),
        )],
        "names the OpenSSL crate",
    );
}

#[test]
fn sec18_openssl_reexported_or_renamed_is_caught() {
    // Covers: SEC-18
    caught(
        &[(
            "keystone-core/src/crypto/rand.rs",
            Some("#![forbid(unsafe_code)]\npub use openssl as ossl;\n"),
        )],
        "re-exports OpenSSL",
    );
    caught(
        &[(
            "keystone-core/src/crypto/rand.rs",
            Some(
                "#![forbid(unsafe_code)]\npub(crate) type Key = openssl::pkey::PKey<openssl::pkey::Private>;\n",
            ),
        )],
        "re-exports OpenSSL",
    );
    caught(
        &[(
            "keystone-core/Cargo.toml",
            Some(
                "[package]\nname = \"keystone-core\"\n\n[dependencies]\nossl = { package = \"openssl\", version = \"=0.10.81\" }\n",
            ),
        )],
        "renames the openssl crate",
    );
    caught(
        &[(
            "keystone-gui/Cargo.toml",
            Some(
                "[package]\nname = \"keystone-gui\"\n\n[dependencies]\nopenssl-sys.workspace = true\n",
            ),
        )],
        "keystone-gui/Cargo.toml depends on OpenSSL",
    );
}

#[test]
fn sec18_any_attribute_naming_unsafe_code_is_caught() {
    // Covers: SEC-18
    for attribute in [
        "#[allow(unsafe_code)]",
        "#[allow(unsafe_code, reason = \"KEYSTONE TEST\")]",
        "#[allow(dead_code, unsafe_code)]",
        "#[expect(unsafe_code)]",
        "#[warn(unsafe_code)]",
        "#[cfg_attr(test, allow(unsafe_code))]",
        "#[allow(\n    unsafe_code\n)]",
    ] {
        let root = format!(
            "#![deny(unsafe_code)]\n\npub mod crypto;\npub mod other;\n\n{attribute}\npub fn f() {{}}\n"
        );
        caught(&[(ROOT, Some(&root))], "names the unsafe_code lint");
    }
    caught(
        &[(
            OTHER,
            Some("#![forbid(unsafe_code)]\n#![allow(unsafe_code)]\n"),
        )],
        "names the unsafe_code lint",
    );
    // A second allow in crypto/mod.rs, on another module.
    caught(
        &[(
            "keystone-core/src/crypto/mod.rs",
            Some("#[allow(unsafe_code)]\nmod ffi;\n#[allow(unsafe_code)]\npub mod rand;\n"),
        )],
        "must allow unsafe_code exactly once",
    );
}

#[test]
fn sec18_unsafe_after_a_block_comment_is_caught() {
    // Covers: SEC-18
    for body in [
        "pub fn f(p: *const u8) -> u8 { /* x */ unsafe { *p } }",
        "pub fn f(p: *const u8) -> u8 {\n    /* SAFETY: */ unsafe { *p }\n}",
        "pub fn f(p: *const u8) -> u8 { g(1, unsafe { *p }) }",
        "pub struct S;\n/* x */ unsafe impl Send for S {}",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn f() {}",
    ] {
        caught(&[(OTHER, Some(&other(body)))], "uses 'unsafe' outside");
    }
    // A #![forbid(unsafe_code)] that is only inside a block comment does not count.
    caught(
        &[(
            OTHER,
            Some("/*\n#![forbid(unsafe_code)]\n*/\npub fn f() {}\n"),
        )],
        "is missing #![forbid(unsafe_code)]",
    );
}

#[test]
fn sec18_the_reviewers_bypass_is_caught() {
    // Covers: SEC-18
    // Review finding N2: a new module using `use openssl as ossl`, and an allowed
    // unsafe block after a block comment in the crate root. Both passed before.
    let root = "#![deny(unsafe_code)]\n\npub mod crypto;\npub mod other;\nmod zz_bypass;\n\n#[allow(unsafe_code, reason = \"KEYSTONE TEST\")]\npub fn read(p: *const u8) -> u8 {\n    /* x */ unsafe { *p }\n}\n";
    let bypass = "#![forbid(unsafe_code)]\n\nuse openssl as ossl;\n\npub fn fill(buf: &mut [u8]) {\n    ossl::rand::rand_bytes(buf).unwrap();\n}\n";
    let (passed, stderr) = run(&[
        (ROOT, Some(root)),
        ("keystone-core/src/zz_bypass.rs", Some(bypass)),
    ]);
    assert!(!passed, "{stderr}");
    for expected in [
        "keystone-core/src/lib.rs uses 'unsafe' outside",
        "keystone-core/src/lib.rs names the unsafe_code lint",
        "keystone-core/src/zz_bypass.rs names the OpenSSL crate",
    ] {
        assert!(stderr.contains(expected), "{expected:?} missing:\n{stderr}");
    }
}

#[test]
fn sec18_an_unsafe_block_in_ffi_needs_a_safety_comment() {
    // Covers: SEC-18
    for body in [
        "pub(crate) fn read(p: *const u8) -> u8 {\n    unsafe { *p }\n}\n",
        "pub(crate) fn read(p: *const u8) -> u8 {\n    g(1, /* x */ unsafe { *p })\n}\n",
        "pub(crate) struct S;\nunsafe impl Send for S {}\n",
    ] {
        caught(
            &[("keystone-core/src/crypto/ffi.rs", Some(body))],
            "unsafe block without a // SAFETY: comment",
        );
    }
}
