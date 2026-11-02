//! Embeds the build date used by the clock sanity checks (FR-17 AC2).
//!
//! Reproducible builds (SEC-02) take the date from `SOURCE_DATE_EPOCH`, which the
//! release pipeline sets to the commit time. A production build without it fails,
//! so a production binary can never carry an accidental or unknown build date.
#![forbid(unsafe_code)]

/// 2026-11-01T00:00:00Z: used only for development builds without SOURCE_DATE_EPOCH.
const DEVELOPMENT_FALLBACK_EPOCH: i64 = 1_793_491_200;

fn main() {
    // `cargo fuzz` builds with `--cfg fuzzing`; the fuzzing entry point in
    // `crypto::pkcs8` exists only then. Declared so the cfg is not an unknown one.
    println!("cargo::rustc-check-cfg=cfg(fuzzing)");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let production = std::env::var_os("CARGO_FEATURE_PRODUCTION").is_some();
    let epoch = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => match value.trim().parse::<i64>() {
            Ok(epoch) if epoch > 0 => epoch,
            _ => panic!("SOURCE_DATE_EPOCH must be a positive integer number of seconds"),
        },
        Err(_) if production => {
            panic!("a production build requires SOURCE_DATE_EPOCH (FR-17 AC2, SEC-02)")
        }
        Err(_) => DEVELOPMENT_FALLBACK_EPOCH,
    };
    println!("cargo:rustc-env=KEYSTONE_BUILD_EPOCH={epoch}");
}
