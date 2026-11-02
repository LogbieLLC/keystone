//! Keystone desktop application (GTK4 + libadwaita): a thin layer over keystone-core.
//!
//! This step adds the tested, display-free parts of the GUI; the screens that use them
//! follow in the next commit.
#![forbid(unsafe_code)]

#[cfg(all(feature = "production", feature = "simulator"))]
compile_error!("the YubiKey simulator must never be part of a production build (NFR-08)");

mod backend;
mod cli;
mod secrets;
mod token;
mod vm;
mod worker;

fn main() {}
