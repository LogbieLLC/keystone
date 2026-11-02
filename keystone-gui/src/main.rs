//! Keystone desktop application (GTK4 + libadwaita): a thin layer over keystone-core.
//!
//! Start-up order (SEC-03, SEC-07, FR-01):
//! 1. Production builds call `keystone_core::hardening::harden_at_startup()` before
//!    anything else: before GTK, OpenSSL or PC/SC are initialised. It installs the
//!    socket filter, disables core dumps, refuses inherited network sockets and refuses
//!    to run while a network interface other than loopback is up. On failure Keystone
//!    shows only the error (naming the interface) and exits; it touches no drive.
//!    Other builds disable core dumps first (SEC-07; compiled into every build).
//! 2. The command line is read (development builds only, see `cli`).
//! 3. The GTK application starts.
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

fn harden() -> Result<(), String> {
    #[cfg(feature = "production")]
    {
        keystone_core::hardening::harden_at_startup().map_err(|e| e.to_string())
    }
    #[cfg(not(feature = "production"))]
    {
        keystone_core::hardening::disable_core_dumps()
            .map_err(|e| format!("Keystone will not start: {e}"))
    }
}

fn main() -> ExitCode {
    // SEC-03: the very first action, before GTK, OpenSSL or PC/SC initialisation.
    let startup = harden().and_then(|()| {
        let args: Vec<String> = std::env::args().skip(1).collect();
        cli::parse(&args, keystone_core::build_info::is_production_build())
            .map_err(|e| e.to_string())
    });
    match startup {
        Ok(options) => ui::run(options),
        Err(message) => {
            // FR-01 AC1: show the error (it names the interface) and do nothing else.
            let _ = writeln!(std::io::stderr(), "{message}");
            ui::run_error_only(&message);
            ExitCode::FAILURE
        }
    }
}
