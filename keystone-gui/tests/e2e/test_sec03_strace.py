"""SEC-03 under strace: with the socket filter on, no network socket is ever opened,
and the GUI and the (simulated) YubiKey still work (keyboard only).

The development build runs with `--harden`, which installs the same socket guard as
the production start (seccomp filter refusing every socket family except AF_UNIX,
blocking io_uring; inherited network sockets refused), under
`strace -f -e trace=network,io_uring_setup,io_uring_enter,io_uring_register`. One
flow is driven: the start-up checks, the recovery screen (which reads the YubiKey)
and "Finish from primary drive" (which writes both drives).

Then every traced `socket` and `socketpair` call of every thread and child is
checked: AF_UNIX (D-Bus, AT-SPI, X11) may succeed; any other family must have failed
with EAFNOSUPPORT (or never be attempted). No io_uring call succeeded. While the
window was up, the Keystone process ran in seccomp filter mode.

The FR-01 network-interface check is production-only (FR-01 AC2) and is not part of
this run; it has its own tests.

# Covers: SEC-03, FR-01 AC3, NFR-08
"""

import glob
import os
import re
import shutil
import time

from keystone_e2e import TMP, Keystone, check, drive_args, make_dirs, prepare, run

CALL = re.compile(r"^(?:\d+ +)?(socket|socketpair|io_uring_setup|io_uring_enter|io_uring_register)\((.*)\) += (-?\d+)(?: (\w+))?")


def seccomp_mode(parent_pid):
    """Seccomp mode of the keystone process started by `parent_pid` (strace)."""
    for status in glob.glob("/proc/[0-9]*/status"):
        try:
            with open(status) as handle:
                fields = dict(
                    line.split(":", 1) for line in handle.read().splitlines() if ":" in line
                )
        except OSError:
            continue
        if fields.get("Name", "").strip() == "keystone" and fields.get("PPid", "").strip() == str(parent_pid):
            return fields.get("Seccomp", "").strip()
    return None


def test():
    check(shutil.which("strace") is not None, "strace is not installed (needed for SEC-03)")
    primary, backup, export = make_dirs("primary", "backup", "export")
    prepare("pending", primary, backup)
    traces = os.path.join(TMP, f"strace-{time.monotonic_ns()}")
    os.makedirs(traces)
    wrapper = [
        "strace",
        "-f",
        "-ff",
        "-qq",
        "-o",
        os.path.join(traces, "trace"),
        "-e",
        "trace=network,io_uring_setup,io_uring_enter,io_uring_register",
    ]
    with Keystone(*drive_args(primary, backup, export), "--harden", wrapper=wrapper) as keystone:
        keystone.wait_heading("Choose the CA drives")
        mode = seccomp_mode(keystone.process.pid)
        check(mode == "2", f"the socket filter is not active (Seccomp: {mode})")
        keystone.activate("Check drives")
        keystone.wait_heading("Start-up checks")
        keystone.activate("Open recovery screen")
        keystone.wait_heading("Recover an interrupted operation")
        # The YubiKey works with the filter on (the simulator in this build).
        keystone.wait_label("Note: YubiKey serial number 31415926, firmware 5.7.4.")
        group = keystone.wait_label("Recovery actions").parent
        finish = [
            n.name for n in group.findChildren(lambda n: n.roleName == "push button" and n.showing)
        ][0]
        keystone.activate(finish)
        keystone.wait_heading(finish)
        keystone.tab_to(finish, "push button")
        keystone.press("space")
        keystone.wait_heading("Operation 1 was finished", timeout=120)
    unix_ok = 0
    refused = []
    problems = []
    files = glob.glob(os.path.join(traces, "trace*"))
    check(files, "strace wrote no trace")
    for path in files:
        with open(path, errors="replace") as handle:
            for line in handle:
                match = CALL.match(line.strip())
                if not match:
                    continue
                call, args, result, errno = match.groups()
                if call.startswith("io_uring"):
                    if int(result) >= 0:
                        problems.append(line.strip())
                    continue
                family = args.split(",", 1)[0].strip()
                if family in ("AF_UNIX", "AF_LOCAL", "PF_UNIX", "PF_LOCAL"):
                    if int(result) >= 0:
                        unix_ok += 1
                elif int(result) == -1 and errno == "EAFNOSUPPORT":
                    refused.append(family)
                else:
                    problems.append(line.strip())
    print(f"AF_UNIX sockets: {unix_ok}; refused other families: {sorted(set(refused))}")
    check(not problems, f"network sockets or io_uring calls not refused: {problems}")
    check(unix_ok > 0, "no AF_UNIX socket was traced: the trace is not complete")


if __name__ == "__main__":
    run(test)
