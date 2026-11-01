//! Production hardening: network refusal, seccomp socket filter, inherited-socket check,
//! binary self-check and core dumps (FR-01, SEC-03, SEC-07, SEC-19). Sensitive code
//! (GOVERNANCE.md section 3: the network guard, the seccomp filter and all code behind
//! the `production` feature).
//!
//! FR-01 AC2: the network guard, the seccomp filter, the inherited-socket check and the
//! binary self-check are compiled only with the `production` Cargo feature (and in this
//! crate's own unit tests, so they can be tested); ordinary development and test builds
//! omit them. Disabling core dumps (SEC-07) is compiled into every build.
//!
//! # Startup order in the production `main`
//! 1. [`harden_at_startup`] as the very first action, before GTK, OpenSSL or PC/SC
//!    start: installs the socket filter, disables core dumps, refuses inherited network
//!    sockets and refuses to run while a network interface is up (the error names it).
//! 2. After the CA drives are opened: `selfcheck::check_running_binary` (SEC-19), shown
//!    as a warning if the binary's SHA-256 differs from the value recorded at install.
#![forbid(unsafe_code)]

use std::path::PathBuf;

mod process;

#[cfg(any(feature = "production", test))]
pub mod network;
#[cfg(any(feature = "production", test))]
pub mod seccomp;
#[cfg(any(feature = "production", test))]
pub mod selfcheck;
#[cfg(any(feature = "production", test))]
pub mod sockets;

pub use process::{core_dumps_disabled, disable_core_dumps};

/// True when the network guard, socket filter and binary self-check are compiled into
/// this build (FR-01 AC2): production builds, and this crate's own unit tests.
pub const PRODUCTION_GUARDS_COMPILED: bool = cfg!(any(feature = "production", test));

/// Errors from this module. Each one names what to fix.
#[derive(Debug, thiserror::Error)]
pub enum HardeningError {
    /// FR-01 AC1: a network interface other than loopback is up.
    #[error(
        "Keystone will not start while a network interface is up: {}. Switch networking off (unplug the cable, turn off Wi-Fi and Bluetooth, or disable the device), then start Keystone again.",
        .interfaces.join(", ")
    )]
    NetworkInterfaceUp {
        /// Names of the interfaces that are up.
        interfaces: Vec<String>,
    },
    /// The interface state could not be read, so it cannot be shown to be off.
    #[error("Keystone will not start: cannot read network interface state from {path}: {reason}")]
    NetworkStateUnreadable {
        /// What could not be read.
        path: PathBuf,
        /// Why.
        reason: String,
    },
    /// SEC-03: the socket filter could not be built or installed.
    #[error("Keystone will not start: cannot install the socket filter: {0}")]
    Seccomp(String),
    /// SEC-03: the process inherited a socket that is not AF_UNIX.
    #[error(
        "Keystone will not start: it was started with open network sockets (file descriptors {}). Start it again from the desktop.",
        .descriptors.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
    )]
    InheritedSocket {
        /// File descriptor numbers of the non-AF_UNIX sockets.
        descriptors: Vec<u32>,
    },
    /// `/proc` could not be read, so inherited sockets cannot be ruled out.
    #[error("Keystone will not start: cannot read {path}: {reason}")]
    ProcUnreadable {
        /// What could not be read.
        path: PathBuf,
        /// Why.
        reason: String,
    },
    /// SEC-07: core dumps could not be disabled.
    #[error("Keystone will not start: cannot disable core dumps: {0}")]
    CoreDumps(String),
    /// SEC-19: the running program could not be read for its self-check.
    #[error("cannot read the running program {path} to check its SHA-256: {reason}")]
    BinaryUnreadable {
        /// The program file.
        path: PathBuf,
        /// Why.
        reason: String,
    },
}

/// The first call in the production `main` (SEC-03, SEC-07, FR-01): installs the socket
/// filter, disables core dumps, refuses inherited network sockets, and refuses to run
/// while any network interface other than loopback is up.
#[cfg(any(feature = "production", test))]
pub fn harden_at_startup() -> Result<(), HardeningError> {
    seccomp::install_socket_filter()?;
    disable_core_dumps()?;
    sockets::check_no_inherited_network_sockets(std::path::Path::new(sockets::PROC_ROOT))?;
    network::check_no_active_network(std::path::Path::new(network::SYSFS_CLASS_NET))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Child half of `sec03_startup_installs_the_filter_first`.
    #[test]
    fn startup_child() {
        let Some(dir) = child::child_dir() else {
            assert!(sockets::non_unix_sockets(std::path::Path::new(sockets::PROC_ROOT)).is_ok());
            return;
        };
        let result = harden_at_startup();
        let outcome = match &result {
            Ok(()) => "ok".to_string(),
            Err(HardeningError::NetworkInterfaceUp { interfaces }) => {
                format!("network_up:{}", interfaces.join(","))
            }
            Err(other) => format!("error:{other}"),
        };
        let report = format!(
            "outcome={outcome}\nseccomp={}\ncore_dumps_disabled={}\n",
            seccomp::seccomp_mode().expect("mode"),
            core_dumps_disabled().expect("core")
        );
        std::fs::write(dir.join("startup.txt"), report).expect("write");
    }

    #[test]
    fn sec03_startup_installs_the_filter_first() {
        // Covers: SEC-03, SEC-07, FR-01 AC1
        let dir = tempfile::tempdir().expect("tempdir");
        child::run("hardening::tests::startup_child", dir.path());
        let report = std::fs::read_to_string(dir.path().join("startup.txt")).expect("report");
        // The filter and core-dump settings are in place whatever the network state.
        assert!(report.contains("seccomp=2"), "{report}");
        assert!(report.contains("core_dumps_disabled=true"), "{report}");
        // The result matches this machine: refused with the interface names when one is up.
        let expected = network::active_interfaces(std::path::Path::new(network::SYSFS_CLASS_NET))
            .expect("interfaces");
        if expected.is_empty() {
            assert!(report.contains("outcome=ok"), "{report}");
        } else {
            let names: Vec<String> = expected.into_iter().map(|i| i.name).collect();
            assert!(
                report.contains(&format!("outcome=network_up:{}", names.join(","))),
                "{report}"
            );
        }
    }
}

/// Runs one test of this test binary in a fresh child process, for checks that change
/// the whole process (a seccomp filter, core-dump settings) and must not affect the
/// other tests.
#[cfg(test)]
pub(crate) mod child {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    /// Environment variable naming the folder a child test writes its results to.
    pub(crate) const DIR_VAR: &str = "KEYSTONE_HARDENING_CHILD_DIR";

    /// The results folder when this process is the child, else `None`.
    pub(crate) fn child_dir() -> Option<PathBuf> {
        std::env::var_os(DIR_VAR).map(PathBuf::from)
    }

    /// Runs the test `name` (full path, for example `hardening::seccomp::tests::x`)
    /// alone in a child process with [`DIR_VAR`] set to `dir`, and checks it passed.
    pub(crate) fn run(name: &str, dir: &Path) -> Output {
        let exe = std::env::current_exe().expect("test binary path");
        let output = Command::new(exe)
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(DIR_VAR, dir)
            .output()
            .expect("start child test process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "child test {name} failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }
}
