//! Tests for the SEC-03 socket filter.
//!
//! Two levels:
//! 1. Policy tests run the generated BPF programs in a small interpreter for many system
//!    calls, families and architectures (no kernel involved).
//! 2. A kernel test installs the real filter in a child process and runs a probe written
//!    in Perl (part of every Ubuntu install as `perl-base`) that tries to create sockets.
//!    Keystone's Rust code itself never creates a socket.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::process::Command;

use seccompiler::sock_filter;

use super::*;
use crate::hardening::child;

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const AUDIT_ARCH_I386: u32 = 0x4000_0003;
const RET_ALLOW: u32 = 0x7FFF_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;

const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const AF_NETLINK: u64 = 16;
const AF_PACKET: u64 = 17;
const AF_BLUETOOTH: u64 = 31;
const AF_VSOCK: u64 = 40;

/// Runs one classic-BPF seccomp program on `seccomp_data` (nr, arch, args).
fn run(program: &[sock_filter], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&nr.to_le_bytes());
    data.extend_from_slice(&arch.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    for arg in args {
        data.extend_from_slice(&arg.to_le_bytes());
    }
    let mut acc: u32 = 0;
    let mut pc = 0usize;
    loop {
        let insn = &program[pc];
        pc += 1;
        match insn.code {
            // BPF_LD | BPF_W | BPF_ABS
            0x20 => {
                let at = insn.k as usize;
                acc = u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"));
            }
            // BPF_RET | BPF_K
            0x06 => return insn.k,
            // BPF_JMP | BPF_JA
            0x05 => pc += insn.k as usize,
            // BPF_JMP | BPF_JEQ / BPF_JGT / BPF_JGE / BPF_JSET with BPF_K
            0x15 | 0x25 | 0x35 | 0x45 => {
                let taken = match insn.code {
                    0x15 => acc == insn.k,
                    0x25 => acc > insn.k,
                    0x35 => acc >= insn.k,
                    _ => acc & insn.k != 0,
                };
                pc += usize::from(if taken { insn.jt } else { insn.jf });
            }
            // BPF_ALU | BPF_AND | BPF_K
            0x54 => acc &= insn.k,
            other => panic!("unsupported BPF instruction {other:#x}"),
        }
    }
}

/// Seccomp result of all programs: the kernel applies the most restrictive action.
fn verdict(nr: i64, arch: u32, first_arg: u64) -> u32 {
    let programs = socket_filter_programs().expect("policy");
    let nr = u32::try_from(nr).expect("syscall number");
    let results: Vec<u32> = programs
        .iter()
        .map(|program| run(program, nr, arch, [first_arg, 0, 0, 0, 0, 0]))
        .collect();
    // KILL_PROCESS > ERRNO > ALLOW for the actions this policy uses.
    let rank = |r: u32| match r & 0xFFFF_0000 {
        RET_KILL_PROCESS => 3,
        RET_ERRNO => 2,
        _ => 1,
    };
    *results.iter().max_by_key(|r| rank(**r)).expect("results")
}

fn errno(code: u32) -> u32 {
    RET_ERRNO | code
}

#[test]
fn sec03_only_af_unix_sockets_are_allowed() {
    // Covers: SEC-03
    for call in [SYS_SOCKET, SYS_SOCKETPAIR] {
        assert_eq!(verdict(call, AUDIT_ARCH_X86_64, AF_UNIX), RET_ALLOW);
        for family in [
            AF_INET,
            AF_INET6,
            AF_PACKET,
            AF_NETLINK,
            AF_BLUETOOTH,
            AF_VSOCK,
            0,
            2_000_000,
        ] {
            assert_eq!(
                verdict(call, AUDIT_ARCH_X86_64, family),
                errno(EAFNOSUPPORT),
                "call {call}, family {family}"
            );
        }
        // The kernel reads the family as a 32-bit int; so does the filter.
        assert_eq!(
            verdict(call, AUDIT_ARCH_X86_64, (7 << 32) | AF_UNIX),
            RET_ALLOW
        );
        assert_eq!(
            verdict(call, AUDIT_ARCH_X86_64, (1 << 32) | AF_INET),
            errno(EAFNOSUPPORT)
        );
    }
}

#[test]
fn sec03_alternative_socket_paths_are_blocked() {
    // Covers: SEC-03
    // io_uring: setting up an instance, and using or extending one (an inherited
    // instance could create sockets with IORING_OP_SOCKET; review finding 12).
    for call in [
        SYS_IO_URING_SETUP,
        SYS_IO_URING_ENTER,
        SYS_IO_URING_REGISTER,
    ] {
        assert_eq!(verdict(call, AUDIT_ARCH_X86_64, 1), errno(ENOSYS), "{call}");
    }
    assert_eq!(
        verdict(SYS_PIDFD_GETFD, AUDIT_ARCH_X86_64, 3),
        errno(ENOSYS)
    );
    for call in [
        SYS_SOCKET,
        SYS_SOCKETPAIR,
        SYS_IO_URING_SETUP,
        SYS_IO_URING_ENTER,
        SYS_IO_URING_REGISTER,
        SYS_PIDFD_GETFD,
    ] {
        // x32 ABI: blocked even for AF_UNIX.
        assert_eq!(
            verdict(call | X32_SYSCALL_BIT, AUDIT_ARCH_X86_64, AF_UNIX),
            errno(ENOSYS)
        );
    }
    // Another architecture (32-bit int 0x80 calls) kills the process.
    assert_eq!(verdict(359, AUDIT_ARCH_I386, AF_INET), RET_KILL_PROCESS);
    assert_eq!(verdict(102, AUDIT_ARCH_I386, 1), RET_KILL_PROCESS);
}

#[test]
fn sec03_everything_else_is_allowed() {
    // Covers: SEC-03
    // read, write, openat, mmap, ioctl, connect, sendmsg, recvmsg, clone, execve, exit_group
    for call in [0, 1, 257, 9, 16, 42, 46, 47, 56, 59, 231] {
        assert_eq!(
            verdict(call, AUDIT_ARCH_X86_64, 0),
            RET_ALLOW,
            "syscall {call}"
        );
    }
}

/// Probe run in the child: tries each kind of socket and prints `name=ok` or `name=<errno>`.
const PROBE: &str = r#"
use strict; use warnings;
use Socket qw(AF_INET AF_INET6 AF_UNIX SOCK_STREAM SOCK_DGRAM SOCK_RAW PF_UNSPEC);
sub try_socket {
    my ($name, $domain, $type) = @_;
    my $ok = socket(my $s, $domain, $type, 0);
    print "$name=", ($ok ? "ok" : ($! + 0)), "\n";
    close($s) if $ok;
}
try_socket("inet", AF_INET, SOCK_DGRAM);
try_socket("inet6", AF_INET6, SOCK_DGRAM);
try_socket("packet", 17, SOCK_RAW);
try_socket("netlink", 16, SOCK_RAW);
try_socket("unix", AF_UNIX, SOCK_STREAM);
my $pair = socketpair(my $a, my $b, AF_UNIX, SOCK_STREAM, PF_UNSPEC);
print "unixpair=", ($pair ? "ok" : ($! + 0)), "\n";
my $ipair = socketpair(my $c, my $d, AF_INET, SOCK_STREAM, PF_UNSPEC);
print "inetpair=", ($ipair ? "ok" : ($! + 0)), "\n";
my $ring = syscall(425, 1, 0);
print "io_uring=", ($ring >= 0 ? "ok" : ($! + 0)), "\n";
my $enter = syscall(426, -1, 0, 0, 0, 0, 0);
print "io_uring_enter=", ($enter >= 0 ? "ok" : ($! + 0)), "\n";
my $register = syscall(427, -1, 0, 0, 0);
print "io_uring_register=", ($register >= 0 ? "ok" : ($! + 0)), "\n";
# An invalid socket type: the kernel refuses it with EINVAL before it looks the family up,
# so the result without the filter does not depend on which families this kernel has; the
# filter answers EAFNOSUPPORT before the kernel runs. A baseline for every family.
for my $family (2, 10, 17, 16, 31, 40) {
    my $ok = socket(my $s, $family, 999, 0);
    print "family$family=", ($ok ? "ok" : ($! + 0)), "\n";
}
"#;

fn probe() -> BTreeMap<String, String> {
    let output = Command::new("perl")
        .args(["-e", PROBE])
        .output()
        .expect("perl (Ubuntu's perl-base) must be installed to run the SEC-03 kernel test");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Child half of `sec03_filter_blocks_network_sockets_in_a_child_process`. As the child it
/// installs the real filter and runs the probe; in the normal test run it only checks
/// that the policy builds.
#[test]
fn sec03_filter_child() {
    let Some(dir) = child::child_dir() else {
        assert_eq!(socket_filter_programs().expect("policy").len(), 2);
        return;
    };
    let before = seccomp_mode().expect("mode");
    install_socket_filter().expect("install");
    let after = seccomp_mode().expect("mode");
    let mut report: Vec<String> = probe()
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    report.push(format!("mode_before={before}"));
    report.push(format!("mode_after={after}"));
    // FR-01 AC3: the interface check still works with every non-local socket refused.
    let network = super::super::network::active_interfaces(std::path::Path::new(
        super::super::network::SYSFS_CLASS_NET,
    ));
    report.push(format!("fr01_under_filter={}", network.is_ok()));
    std::fs::write(dir.join("probe.txt"), report.join("\n")).expect("write report");
}

/// Every family the filter must refuse, as the probe's `family<N>` key.
const REFUSED_FAMILIES: [u64; 6] = [
    AF_INET,
    AF_INET6,
    AF_PACKET,
    AF_NETLINK,
    AF_BLUETOOTH,
    AF_VSOCK,
];

/// The control run (no filter) must give, for every refusal the test asserts, a result
/// that differs from the filter's answer; otherwise the assertion would pass without
/// the filter. A probe whose control result equals the refusal fails the test loudly:
/// on such a kernel the filter's effect cannot be shown (review: SEC-03 kernel test).
fn assert_control_baselines(control: &BTreeMap<String, String>) {
    let get = |key: &str| {
        control
            .get(key)
            .map(String::as_str)
            .unwrap_or_else(|| panic!("the control probe printed no {key}: {control:?}"))
    };
    assert_eq!(
        get("unix"),
        "ok",
        "AF_UNIX must work without the filter: {control:?}"
    );
    assert_eq!(
        get("inet"),
        "ok",
        "AF_INET must work without the filter: {control:?}"
    );
    assert_ne!(get("inetpair"), "97", "{control:?}");
    for family in REFUSED_FAMILIES {
        assert_eq!(
            get(&format!("family{family}")),
            "22",
            "without the filter, socket(family {family}, invalid type) must fail with EINVAL; otherwise the refusal of family {family} cannot be told apart from the kernel's own answer: {control:?}"
        );
    }
    for call in ["io_uring", "io_uring_enter", "io_uring_register"] {
        assert_ne!(
            get(call),
            "38",
            "{call} is not available on this kernel (ENOSYS without the filter), so the test cannot show that the filter blocks it; run the SEC-03 kernel test on a kernel with io_uring: {control:?}"
        );
    }
}

#[test]
fn sec03_filter_blocks_network_sockets_in_a_child_process() {
    // Covers: SEC-03, FR-01 AC3
    // Control: without the filter every refusal asserted below has a different result,
    // so the results come from the filter and not from the environment (a kernel without
    // IPv6 or io_uring cannot make the test pass by itself).
    let control = probe();
    assert_control_baselines(&control);

    let dir = tempfile::tempdir().expect("tempdir");
    child::run("hardening::seccomp::tests::sec03_filter_child", dir.path());
    let text = std::fs::read_to_string(dir.path().join("probe.txt")).expect("report");
    let report: BTreeMap<&str, &str> = text.lines().filter_map(|l| l.split_once('=')).collect();
    // Seccomp mode 2 (filter). A CI container may already filter before, so mode_before
    // is reported but not asserted.
    assert_eq!(
        report.get("mode_after"),
        Some(&"2"),
        "filter active: {text}"
    );
    for refused in ["inet", "inet6", "packet", "netlink", "inetpair"] {
        assert_eq!(
            report.get(refused),
            Some(&"97"),
            "{refused} must fail with EAFNOSUPPORT: {text}"
        );
    }
    for family in REFUSED_FAMILIES {
        assert_eq!(
            report.get(format!("family{family}").as_str()),
            Some(&"97"),
            "family {family} must be refused by the filter (EAFNOSUPPORT, not the kernel's EINVAL): {text}"
        );
    }
    for call in ["io_uring", "io_uring_enter", "io_uring_register"] {
        assert_eq!(report.get(call), Some(&"38"), "{call}: {text}");
    }
    assert_eq!(
        report.get("unix"),
        Some(&"ok"),
        "AF_UNIX must keep working: {text}"
    );
    assert_eq!(report.get("unixpair"), Some(&"ok"), "{text}");
    assert_eq!(report.get("fr01_under_filter"), Some(&"true"), "{text}");
}
