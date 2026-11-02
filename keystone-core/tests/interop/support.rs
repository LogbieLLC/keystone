//! Helpers: temporary workspaces and the external verifiers.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use keystone_core::crypto::verify::certificate_der_to_pem;

/// A temporary directory for one test (TEST-12).
pub struct Workspace {
    dir: tempfile::TempDir,
}

impl Workspace {
    pub fn new() -> Self {
        Workspace {
            dir: tempfile::tempdir().expect("temporary directory"),
        }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.dir.path().join(name);
        std::fs::write(&path, contents).expect("write test file");
        path
    }

    /// Writes one or more DER certificates as a PEM file.
    pub fn write_certs(&self, name: &str, ders: &[&[u8]]) -> PathBuf {
        let pem: String = ders
            .iter()
            .map(|der| certificate_der_to_pem(der).expect("PEM"))
            .collect();
        self.write(name, pem)
    }
}

pub fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Runs the `openssl` command line in `dir`.
pub fn openssl_cli(dir: &Path, args: &[&str]) -> Output {
    Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("the openssl command line must be installed for interoperability tests")
}

fn go_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("KEYSTONE_GO") {
        return PathBuf::from(path);
    }
    let installed = Path::new("/usr/local/go/bin/go");
    if installed.exists() {
        installed.to_path_buf()
    } else {
        PathBuf::from("go")
    }
}

/// Runs `tests/interop/verify_chain.go` with `go run`. Returns (verified, output).
///
/// The Go build cache lives under Cargo's per-target test directory, the Go temp
/// directory is the test's own workspace, module downloads are disabled
/// (`GOPROXY=off`) and the local toolchain is used (`GOTOOLCHAIN=local`), so the
/// verifier needs nothing but the standard library and opens no network connection.
pub fn go_verify(
    workspace: &Workspace,
    roots: &Path,
    intermediates: &Path,
    leaf: &Path,
) -> (bool, String) {
    let program = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/interop/verify_chain.go");
    let cache = Path::new(env!("CARGO_TARGET_TMPDIR")).join("go-build-cache");
    let gopath = Path::new(env!("CARGO_TARGET_TMPDIR")).join("go-path");
    let output = Command::new(go_binary())
        .arg("run")
        .arg(program)
        .arg(roots)
        .arg(intermediates)
        .arg(leaf)
        .current_dir(workspace.path())
        .env("GOCACHE", cache)
        .env("GOPATH", gopath)
        .env("GOTMPDIR", workspace.path())
        .env("GOTOOLCHAIN", "local")
        .env("GOPROXY", "off")
        .env("GOFLAGS", "")
        .output()
        .expect(
            "Go must be installed (set KEYSTONE_GO or put go on PATH) for interoperability tests",
        );
    let all = text(&output);
    let code = output.status.code();
    assert!(
        code == Some(0) || code == Some(1),
        "the Go verifier could not run: {all}"
    );
    (code == Some(0) && all.trim() == "OK", all)
}
