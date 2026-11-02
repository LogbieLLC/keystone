"""A behind drive is repaired only after the operator confirms (keyboard only).

Three CA drives; the second backup missed one audit entry. The start-up checks list
what is missing and block continuing; the copy button stays disabled until the
operator ticks that they checked the list. After the copy (core DriveSet::repair,
with the time checked first), the checks run again and every drive holds the same
history.

# Covers: FR-12 AC3, FR-19 AC1, SEC-09, SEC-11, NFR-04
"""

import os

from keystone_e2e import Keystone, check, make_dirs, prepare, run


def audit_lines(drive):
    with open(os.path.join(drive, "keystone", "audit.log")) as handle:
        return handle.read().splitlines()


def test():
    primary, backup, second, export = make_dirs("primary", "backup", "second", "export")
    prepare("behind", primary, backup, second)
    check(len(audit_lines(second)) == 0, "the second backup is not behind")
    args = ["--primary", primary, "--backup", backup, "--backup", second, "--export", export]
    with Keystone(*args) as keystone:
        keystone.wait_heading("Choose the CA drives")
        keystone.activate("Check drives")
        keystone.wait_heading("Start-up checks")
        keystone.wait_label("Drives behind")
        heading = keystone.labels_matching(r"^backup drive .* is behind .*: 0 operations and 1 line to copy\.$")
        check(len(heading) == 1 and second in heading[0], f"behind drive not named: {keystone.labels()}")
        check(
            keystone.labels_matching(r"^Note: #1 .* export CN=KEYSTONE TEST missed \(success\)$"),
            f"missing entry not listed: {keystone.labels()}",
        )
        check(
            not keystone.find_all(lambda n: n.roleName == "push button" and n.name == "Continue"),
            "Continue offered while a drive is behind",
        )
        copy = keystone.button("Copy the missing operations")
        check(not copy.sensitive, "copy enabled before the operator confirmed the list")
        keystone.activate("I have checked the missing operations listed above", role="check box")
        check(keystone.button("Copy the missing operations").sensitive, "copy not enabled after the tick")
        keystone.activate("Copy the missing operations")
        # The checks run again: every drive now holds the same history.
        keystone.wait_label("OK: All 3 drives hold the same history.", timeout=60)
        keystone.button("Continue")
    for drive in (primary, backup, second):
        lines = audit_lines(drive)
        check(len(lines) == 2, f"{drive}: {len(lines)} audit entries")
        check('"action":"drive_repair"' in lines[1], f"{drive}: no repair entry: {lines[1]}")
    check(audit_lines(primary) == audit_lines(second), "the drives still differ")


if __name__ == "__main__":
    run(test)
