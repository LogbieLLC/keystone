//! FR-01 AC2: the network guard, socket filter and binary self-check are compiled in only
//! with the `production` feature. This integration test links the library as a normal
//! (non-unit-test) build, so it sees exactly what a development or production build gets.
//!
//! SEC-03: the socket guard (seccomp filter plus the inherited-socket and io_uring
//! refusal) is also callable in development builds, where nothing installs it unless
//! asked (`keystone --harden`, used by the strace E2E run).
#![forbid(unsafe_code)]

use std::process::Command;

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

/// Environment variable that makes `socket_guard_child` the child half.
const CHILD_VAR: &str = "KEYSTONE_SOCKET_GUARD_CHILD_DIR";

/// Child half of `sec03_socket_guard_can_be_installed_in_a_development_build`: installs
/// the guard and reports the seccomp mode. In the normal run it only checks that the
/// filter policy builds.
#[test]
fn socket_guard_child() {
    let Some(dir) = std::env::var_os(CHILD_VAR).map(std::path::PathBuf::from) else {
        assert_eq!(
            keystone_core::hardening::seccomp::socket_filter_programs()
                .expect("policy")
                .len(),
            2
        );
        return;
    };
    let result = keystone_core::hardening::install_socket_guard();
    let mode = keystone_core::hardening::seccomp::seccomp_mode().expect("mode");
    std::fs::write(
        dir.join("guard.txt"),
        format!("result={}\nmode={mode}\n", result.is_ok()),
    )
    .expect("write report");
}

#[test]
fn sec03_socket_guard_can_be_installed_in_a_development_build() {
    // Covers: SEC-03 (the filter used by the strace E2E run with `keystone --harden`)
    let dir = tempfile::tempdir().expect("tempdir");
    let exe = std::env::current_exe().expect("test binary");
    let output = Command::new(exe)
        .args([
            "--exact",
            "socket_guard_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_VAR, dir.path())
        .output()
        .expect("start child");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report = std::fs::read_to_string(dir.path().join("guard.txt")).expect("report");
    assert!(report.contains("result=true"), "{report}");
    assert!(report.contains("mode=2"), "seccomp filter mode: {report}");
}
