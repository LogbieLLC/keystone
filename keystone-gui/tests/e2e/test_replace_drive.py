"""Replace a lost drive (ADR 0003), keyboard only.

A CA on a primary and a backup drive; the primary is lost, so only the backup and a
new, empty drive are connected. The start-up checks disable every signing action
and offer "Replace a lost drive". Its review shows what will be copied and that the
backup becomes the primary; the result lists the drives, each read back and
verified. Afterwards the CA opens normally on the two drives, with the old backup as
its primary.

# Covers: SEC-11 (ADR 0003), FR-12 AC1, FR-12 AC2, FR-14 AC1, FR-17 AC1, FR-19 AC1, NFR-04, NFR-10
"""

import json
import os
import re

from keystone_e2e import (
    Keystone,
    assert_no_plaintext_keys,
    check,
    make_dirs,
    prepare,
    run,
)


def audit_entries(drive):
    with open(os.path.join(drive, "keystone", "audit.log")) as handle:
        return [json.loads(line) for line in handle if line.strip()]


def test():
    primary, backup, new, export = make_dirs("primary", "backup", "new", "export")
    prepare("lost-primary", primary, backup)
    args = ["--backup", backup, "--export", export, "--new-drive", new]
    with Keystone(*args) as keystone:
        keystone.wait_heading("Choose the CA drives")
        keystone.activate("Check drives")
        keystone.wait_heading("Start-up checks")
        keystone.wait_label(
            "Blocked: Connected: 0 primary and 1 backup drive. Every signing action needs the primary drive and at least one backup.",
            exact=False,
        )
        check(
            not keystone.find_all(lambda n: n.roleName == "push button" and n.name == "Continue"),
            "signing flows are offered with a single drive",
        )
        keystone.activate("Replace a lost drive…")
        keystone.wait_heading("Replace a lost drive")
        keystone.wait_label(f"Note: Backup drive {backup}.")
        keystone.wait_for(
            lambda n: n.roleName == "push button" and n.name == "Review the replacement" and n.sensitive,
            "the time check",
        )
        keystone.activate("Review the replacement")
        keystone.wait_heading("Replace a lost drive: review")
        for expected in (
            f"Note: New drive: {new}.",
            "Note: New drive now: empty.",
            "Note: Role of the new drive: backup.",
            "Note: What is not done: nothing is signed; nothing on the connected drives is overwritten or deleted.",
        ):
            check(keystone.has_label(expected), f"{expected!r} not reviewed: {keystone.labels()}")
        check(
            keystone.labels_matching(
                rf"^Warning: The primary drive is not connected: backup drive [0-9a-f]{{8}} \({re.escape(backup)}\) becomes the primary drive\.$"
            ),
            f"promotion not reviewed: {keystone.labels()}",
        )
        check(os.listdir(new) == [], "the review wrote to the new drive")
        keystone.activate("Replace the lost drive")
        keystone.wait_heading("The lost drive was replaced", timeout=120)
        for folder in (backup, new):
            check(
                keystone.labels_matching(
                    rf"^OK: (primary|backup) drive [0-9a-f]{{8}} \({re.escape(folder)}\): every file was read back and matches its SHA-256\.$"
                ),
                f"{folder} not verified: {keystone.labels()}",
            )
        check(
            keystone.labels_matching(
                rf"^Note: Copied to backup drive [0-9a-f]{{8}} \({re.escape(new)}\): 0 operations, 0 files and 1 audit entry, each verified by SHA-256; its identity was written last\.$"
            ),
            f"copy not described: {keystone.labels()}",
        )
        check(
            keystone.labels_matching(
                rf"^Note: primary drive [0-9a-f]{{8}} \({re.escape(backup)}\) is now the primary drive\."
            ),
            f"promotion not described: {keystone.labels()}",
        )
        # The CA opens normally on the two drives.
        keystone.activate("Done")
        keystone.wait_heading("Start-up checks")
        keystone.wait_label("OK: All 2 drives hold the same history.", timeout=60)
        keystone.continue_to_home()
    entries = audit_entries(backup)
    check(entries == audit_entries(new), "the drives hold different audit logs")
    replacement = [e for e in entries if e["action"] == "drive_repair"]
    check(
        any("drive_added" in e.get("details", {}) for e in replacement)
        and any("primary_promoted" in e.get("details", {}) for e in replacement),
        f"replacement not audited: {replacement}",
    )
    check(os.listdir(primary) == ["keystone"], "the lost drive was touched")
    assert_no_plaintext_keys()


if __name__ == "__main__":
    run(test)
