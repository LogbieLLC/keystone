//! SEC-03: seccomp filter allowing only local (AF_UNIX) sockets. Sensitive code.
//!
//! The policy is fixed in Rust (no JSON) and built with `seccompiler`:
//! - `socket()` and `socketpair()` fail with `EAFNOSUPPORT` for every address family
//!   except `AF_UNIX`, which PC/SC (pcscd), Wayland and D-Bus need. Only the low 32 bits
//!   of the family are compared, exactly as the kernel reads the `int` argument;
//! - `io_uring_setup()` fails with `ENOSYS`: io_uring can create sockets without calling
//!   `socket()`;
//! - `pidfd_getfd()` fails with `ENOSYS`: it could copy a socket out of another process;
//! - the same four calls through the x32 ABI (syscall number + `0x4000_0000`) fail with
//!   `ENOSYS`;
//! - any system call from another architecture (for example 32-bit `int 0x80`) kills the
//!   process (seccompiler's architecture check).
//!
//! Everything else is allowed. The filter is installed for all threads (TSYNC) with
//! `no_new_privs`, and is inherited by every child process.
//!
//! Residual paths, covered elsewhere: a socket already open when Keystone starts is
//! refused by [`super::sockets`]; a socket passed over an AF_UNIX connection
//! (`SCM_RIGHTS`) cannot be filtered without breaking D-Bus and PC/SC, and is covered by
//! the strace E2E run (SEC-03) and FR-01's refusal to run with an interface up.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use super::HardeningError;

/// `AF_UNIX`: the only address family allowed.
pub const AF_UNIX: u64 = 1;
/// errno returned by a refused `socket()` / `socketpair()`.
pub const EAFNOSUPPORT: u32 = 97;
/// errno returned by refused io_uring / pidfd_getfd / x32 calls.
pub const ENOSYS: u32 = 38;

/// x86_64 system call numbers used by the policy.
pub const SYS_SOCKET: i64 = 41;
/// `socketpair`.
pub const SYS_SOCKETPAIR: i64 = 53;
/// `io_uring_setup`.
pub const SYS_IO_URING_SETUP: i64 = 425;
/// `pidfd_getfd`.
pub const SYS_PIDFD_GETFD: i64 = 438;
/// Bit that marks x32-ABI system calls on x86_64.
pub const X32_SYSCALL_BIT: i64 = 0x4000_0000;

fn seccomp_err(error: impl std::fmt::Display) -> HardeningError {
    HardeningError::Seccomp(error.to_string())
}

/// The two BPF programs of the policy: socket families, then the other blocked calls.
pub fn socket_filter_programs() -> Result<Vec<BpfProgram>, HardeningError> {
    let not_unix = || -> Result<Vec<SeccompRule>, HardeningError> {
        let condition =
            SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, AF_UNIX)
                .map_err(seccomp_err)?;
        Ok(vec![
            SeccompRule::new(vec![condition]).map_err(seccomp_err)?,
        ])
    };
    let families = SeccompFilter::new(
        BTreeMap::from([(SYS_SOCKET, not_unix()?), (SYS_SOCKETPAIR, not_unix()?)]),
        SeccompAction::Allow,
        SeccompAction::Errno(EAFNOSUPPORT),
        TargetArch::x86_64,
    )
    .map_err(seccomp_err)?;
    let mut blocked = BTreeMap::new();
    for call in [SYS_IO_URING_SETUP, SYS_PIDFD_GETFD] {
        blocked.insert(call, Vec::new());
    }
    for call in [
        SYS_SOCKET,
        SYS_SOCKETPAIR,
        SYS_IO_URING_SETUP,
        SYS_PIDFD_GETFD,
    ] {
        blocked.insert(call | X32_SYSCALL_BIT, Vec::new());
    }
    let others = SeccompFilter::new(
        blocked,
        SeccompAction::Allow,
        SeccompAction::Errno(ENOSYS),
        TargetArch::x86_64,
    )
    .map_err(seccomp_err)?;
    Ok(vec![
        families.try_into().map_err(seccomp_err)?,
        others.try_into().map_err(seccomp_err)?,
    ])
}

/// SEC-03: installs the filter on every thread of this process. Call it as the first
/// action of the production `main`, before GTK, OpenSSL or PC/SC start. It cannot be
/// removed again.
pub fn install_socket_filter() -> Result<(), HardeningError> {
    for program in socket_filter_programs()? {
        seccompiler::apply_filter_all_threads(&program).map_err(seccomp_err)?;
    }
    Ok(())
}

/// The process's seccomp mode from `/proc/self/status` (0 none, 2 filter), so a test can
/// confirm the filter is active before the first GTK call.
pub fn seccomp_mode() -> Result<u8, HardeningError> {
    let path = std::path::Path::new("/proc/self/status");
    let status = std::fs::read_to_string(path).map_err(|e| HardeningError::ProcUnreadable {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp:"))
        .and_then(|value| value.trim().parse().ok())
        .ok_or_else(|| HardeningError::ProcUnreadable {
            path: path.to_path_buf(),
            reason: "no Seccomp field".to_string(),
        })
}

#[cfg(test)]
mod tests;
