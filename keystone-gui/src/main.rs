//! Keystone desktop application (GTK4 + libadwaita): a thin layer over keystone-core.
#![forbid(unsafe_code)]

#[cfg(all(feature = "production", feature = "simulator"))]
compile_error!("the YubiKey simulator must never be part of a production build (NFR-08)");

fn main() {}
