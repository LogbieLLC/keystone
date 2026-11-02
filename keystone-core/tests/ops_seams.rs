//! The operations layer's test seams (fault points, cached test keys, serial
//! candidates) exist only in non-production builds. This test links the library as a
//! normal build, so it sees exactly what a development or production build gets.
#![forbid(unsafe_code)]

#[test]
fn fr22_ac6_test_seams_cannot_be_enabled_in_a_production_build() {
    // Covers: FR-22 AC6, SEC-18
    assert_eq!(
        keystone_core::ops::TEST_SEAMS_COMPILED,
        !cfg!(feature = "production")
    );
}
