//! FR-01 AC2: the network guard, socket filter and binary self-check are compiled in only
//! with the `production` feature. This integration test links the library as a normal
//! (non-unit-test) build, so it sees exactly what a development or production build gets.
#![forbid(unsafe_code)]

#[test]
fn fr01_ac2_network_guard_is_compiled_only_with_the_production_feature() {
    // Covers: FR-01 AC2, SEC-03
    assert_eq!(
        keystone_core::hardening::PRODUCTION_GUARDS_COMPILED,
        cfg!(feature = "production")
    );
    assert_eq!(
        keystone_core::build_info::is_production_build(),
        cfg!(feature = "production")
    );
}
