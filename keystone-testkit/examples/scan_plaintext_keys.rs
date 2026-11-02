//! Plaintext private-key scanner for CI (PRD SEC-04).
//!
//! Walks every file under the given paths — text and binary — and fails if any file
//! contains an unencrypted private key, either as a PEM label (`PRIVATE KEY`,
//! `RSA PRIVATE KEY`, …) or as DER-encoded PKCS#8 / PKCS#1 key material, using
//! keystone-core's detector. Encrypted PKCS#8 is allowed.
//!
//! Usage: cargo run -p keystone-testkit --example scan_plaintext_keys -- <path> [<path> ...]
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use keystone_core::crypto::pkcs8::contains_plaintext_private_key;

fn main() -> ExitCode {
    let roots: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    if roots.is_empty() {
        eprintln!("usage: scan_plaintext_keys <path> [<path> ...]");
        return ExitCode::from(2);
    }
    let mut scanned = 0usize;
    let mut hits = Vec::new();
    for root in &roots {
        if let Err(error) = scan(root, &mut scanned, &mut hits) {
            eprintln!("cannot scan {}: {error}", root.display());
            return ExitCode::from(2);
        }
    }
    if hits.is_empty() {
        println!("No plaintext private keys in {scanned} files.");
        ExitCode::SUCCESS
    } else {
        eprintln!("PLAINTEXT PRIVATE KEY FOUND (SEC-04):");
        for hit in &hits {
            eprintln!("  {}", hit.display());
        }
        ExitCode::FAILURE
    }
}

fn scan(path: &Path, scanned: &mut usize, hits: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.is_dir() {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Build output and VCS internals are not Keystone output.
        if name == ".git" || name == "target" {
            return Ok(());
        }
        let mut entries: Vec<PathBuf> = fs::read_dir(path)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<_, _>>()?;
        entries.sort();
        for entry in entries {
            scan(&entry, scanned, hits)?;
        }
    } else if meta.is_file() {
        *scanned += 1;
        if contains_plaintext_private_key(&fs::read(path)?) {
            hits.push(path.to_path_buf());
        }
    }
    Ok(())
}
