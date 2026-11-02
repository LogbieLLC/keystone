//! Keystone desktop application (GTK4 + libadwaita): a thin layer over keystone-core.
//!
//! Start-up order (SEC-03, SEC-07, FR-01):
//! 1. Production builds call `keystone_core::hardening::harden_at_startup()` before
//!    anything else: before GTK, OpenSSL or PC/SC are initialised. It installs the
//!    socket filter, disables core dumps, refuses inherited network sockets and refuses
//!    to run while a network interface other than loopback is up. On failure Keystone
//!    shows only the error (naming the interface) and exits; it touches no drive.
//!    Other builds disable core dumps first (SEC-07; compiled into every build), and
//!    install the socket filter only when started with `--harden` (the SEC-03 strace
//!    E2E run).
//! 2. `keystone_core::crypto::init()` creates OpenSSL's locked secure heap for private
//!    keys (SEC-07), once, before any thread starts. If the memory cannot be locked,
//!    Keystone refuses to start the same way.
//! 3. The command line is read (development builds only, see `cli`).
//! 4. The GTK application starts.
#![forbid(unsafe_code)]

#[cfg(all(feature = "production", feature = "simulator"))]
compile_error!("the YubiKey simulator must never be part of a production build (NFR-08)");

mod backend;
mod cli;
mod secrets;
mod token;
mod ui;
mod vm;
mod worker;

use std::io::Write;
use std::process::ExitCode;

use keystone_core::crypto::CryptoError;

fn harden(args: &[String]) -> Result<(), String> {
    #[cfg(feature = "production")]
    {
        let _ = args;
        keystone_core::hardening::harden_at_startup().map_err(|e| e.to_string())
    }
    #[cfg(not(feature = "production"))]
    {
        if cli::wants_hardening(args, false) {
            keystone_core::hardening::install_socket_guard().map_err(|e| e.to_string())?;
        }
        keystone_core::hardening::disable_core_dumps()
            .map_err(|e| format!("Keystone will not start: {e}"))
    }
}

/// Everything before the GUI starts, in order: hardening, OpenSSL's secure heap, then
/// the command line. Any failure is one message for the refusal window.
fn startup(
    args: &[String],
    harden: impl FnOnce(&[String]) -> Result<(), String>,
    init_crypto: impl FnOnce() -> Result<(), CryptoError>,
) -> Result<cli::Options, String> {
    harden(args)?;
    init_crypto().map_err(|e| format!("Keystone will not start: {e}"))?;
    cli::parse(args, keystone_core::build_info::is_production_build()).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    // Reading the arguments opens nothing; hardening is still the first action that
    // changes the process (SEC-03).
    let args: Vec<String> = std::env::args().skip(1).collect();
    match startup(&args, harden, keystone_core::crypto::init) {
        Ok(options) => ui::run(options),
        Err(message) => {
            // FR-01 AC1: show the error (it names the interface) and do nothing else.
            let _ = writeln!(std::io::stderr(), "{message}");
            ui::run_error_only(&message);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn sec07_secure_heap_failure_refuses_to_start_like_a_hardening_error() {
        // Covers: SEC-07, SEC-03 (start-up order: hardening, then the secure heap)
        let order = RefCell::new(Vec::new());
        let result = startup(
            &[],
            |_| {
                order.borrow_mut().push("harden");
                Ok(())
            },
            || {
                order.borrow_mut().push("crypto");
                Err(CryptoError::SecureHeapUnavailable { bytes: 1 << 20 })
            },
        );
        let message = result.expect_err("refused");
        assert!(
            message.starts_with("Keystone will not start: "),
            "{message}"
        );
        assert!(message.contains("1048576 bytes"), "{message}");
        assert!(message.contains("RLIMIT_MEMLOCK"), "{message}");
        assert_eq!(*order.borrow(), ["harden", "crypto"]);
    }

    #[test]
    fn sec03_a_hardening_error_stops_before_the_secure_heap() {
        // Covers: SEC-03, FR-01 AC1
        let called = RefCell::new(false);
        let result = startup(
            &[],
            |_| Err("Keystone will not start while a network interface is up: eth0.".into()),
            || {
                *called.borrow_mut() = true;
                Ok(())
            },
        );
        assert!(result.expect_err("refused").contains("eth0"));
        assert!(!*called.borrow(), "nothing runs after a hardening refusal");
    }

    #[test]
    fn sec03_an_inherited_io_uring_instance_refuses_to_start() {
        // Covers: SEC-03 (HardeningError::InheritedIoUring is shown like every refusal)
        let refusal = keystone_core::hardening::HardeningError::InheritedIoUring {
            descriptors: vec![7],
        };
        let result = startup(&[], |_| Err(refusal.to_string()), || Ok(()));
        let message = result.expect_err("refused");
        assert!(message.contains("io_uring"), "{message}");
        assert!(message.contains("file descriptors 7"), "{message}");
    }

    #[test]
    fn startup_reads_the_command_line_last() {
        let options = startup(
            &["--primary".to_string(), "/tmp/a".to_string()],
            |_| Ok(()),
            || Ok(()),
        )
        .expect("starts");
        assert_eq!(options.primary, Some(std::path::PathBuf::from("/tmp/a")));
        // The real secure heap can be created in this test process.
        assert!(keystone_core::crypto::init().is_ok());
    }
}
