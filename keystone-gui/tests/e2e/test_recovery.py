"""Recovery screen for a prepared interrupted operation (keyboard only).

The drives hold an interrupted "create master" operation: signed and staged on both
drives, nothing moved into place. The start-up checks send the operator to the
recovery screen, which shows one column per drive and one for the YubiKey with
exactly what each holds, and at most two actions, each with one plain sentence. The
screen's content and sentences come from the operations layer
(`ops::Ca::recovery_items`, read with the simulated YubiKey connected). No action
formats, deletes or overwrites anything. "Finish from the primary drive" really runs:
the staged files are moved into place on both drives, read back, and the start-up
checks then find no interrupted operation.

# Covers: FR-22 AC4, FR-22 AC8, FR-22 AC3, FR-12 AC2, SEC-22, NFR-04, NFR-08
"""

import os
import re

from keystone_e2e import (
    Keystone,
    assert_no_plaintext_keys,
    check,
    drive_args,
    make_dirs,
    prepare,
    run,
)

SERIAL = "3e" + "00" * 18 + "01"


def journal_files(drive):
    folder = os.path.join(drive, "keystone", "journal", "op-000001")
    return sorted(os.listdir(folder))


def tree_snapshot(drive):
    snapshot = []
    for folder, _, files in os.walk(drive):
        for name in files:
            path = os.path.join(folder, name)
            with open(path, "rb") as handle:
                snapshot.append((path, handle.read()))
    return sorted(snapshot)


def test():
    primary, backup, export = make_dirs("primary", "backup", "export")
    prepare("pending", primary, backup)
    before = (tree_snapshot(primary), tree_snapshot(backup))
    check(
        journal_files(primary) == ["001-pending.json", "002-signed.json", "003-staged.json"],
        f"unexpected prepared journal: {journal_files(primary)}",
    )
    with Keystone(*drive_args(primary, backup, export)) as keystone:
        keystone.wait_heading("Choose the CA drives")
        keystone.activate("Check drives")
        keystone.wait_heading("Start-up checks")
        keystone.wait_label(
            "Blocked: operation 1 (CN=KEYSTONE TEST E2E Root) was interrupted. Open the recovery screen to see what each drive holds."
        )
        check(
            not keystone.find_all(lambda n: n.roleName == "push button" and n.name == "Continue"),
            "Continue is offered while an operation is interrupted",
        )
        keystone.activate("Open recovery screen")
        keystone.wait_heading("Recover an interrupted operation")
        keystone.wait_label(
            "Interrupted: operation 1 to create the master (CN=KEYSTONE TEST E2E Root).",
            exact=False,
        )

        # One column per drive and one for the YubiKey (FR-22 AC8).
        labels = keystone.labels()
        primary_title = [l for l in labels if l.startswith("primary drive ") and primary in l]
        backup_title = [l for l in labels if l.startswith("backup drive ") and backup in l]
        check(len(primary_title) == 1, f"no primary column: {labels}")
        check(len(backup_title) == 1, f"no backup column: {labels}")
        check("YubiKey" in labels, f"no YubiKey column: {labels}")
        keystone.wait_label("Note: YubiKey serial number 31415926, firmware 5.7.4.")
        check(
            keystone.has_label("Note: Signing slot: empty (no key, no certificate)."),
            f"YubiKey slot not described: {labels}",
        )
        check(
            keystone.has_label("Note: No YubiKey step is recorded for this operation."),
            f"YubiKey steps not described: {labels}",
        )
        # Exactly what each drive holds.
        for expected in (
            "Note: State: interrupted (pending).",
            "Note: Journal entries: 001-pending.json, 002-signed.json, 003-staged.json.",
            f"Note: Signed certificate, serial {SERIAL}.",
            f"OK: certs/{SERIAL}.crt: staged copy present and verified, final copy missing.",
            f"OK: keys/{SERIAL}.key: staged copy present and verified, final copy missing.",
            "Note: Audit entries for this operation: 0.",
            "OK: Holds the complete, verified output.",
        ):
            count = labels.count(expected)
            check(count == 2, f"{expected!r} shown {count} times, expected once per drive")

        # At most two actions, each with one sentence; nothing destructive. The
        # actions are the buttons inside the "Recovery actions" group.
        heading = keystone.wait_label("Recovery actions")
        group = heading.parent
        actions = [
            node.name
            for node in group.findChildren(
                lambda n: n.roleName == "push button" and n.showing
            )
        ]
        check(1 <= len(actions) <= 2, f"actions offered: {actions}")
        for action in actions:
            check(
                not re.search(r"format|delete|overwrite|wipe|erase", action, re.I),
                f"destructive action offered: {action}",
            )
        finish = actions[0]
        check(finish.startswith("Finish from primary drive "), f"unexpected action {finish}")
        sentence = keystone.labels_matching(r"^Copy the finished files of operation 1 from primary drive ")
        check(len(sentence) == 1, f"no sentence for the action: {keystone.labels()}")
        check(
            sentence[0].endswith(
                "to every other drive and mark it completed; nothing is deleted or overwritten."
            ),
            f"sentence: {sentence}",
        )

        # Choosing the action: the time to record is checked, then the backend runs it.
        keystone.activate(finish)
        keystone.wait_heading(finish)
        keystone.wait_label("This action is recorded in the audit log with this time.")
        check(
            keystone.labels_matching(r"^OK: The time passes the checks"),
            f"no clock check: {keystone.labels()}",
        )
        keystone.tab_to(finish, "push button")
        keystone.press("space")
        keystone.wait_heading("Operation 1 was finished", timeout=60)
        for role, folder in (("primary", primary), ("backup", backup)):
            lines = keystone.labels_matching(
                rf"^OK: {role} drive [0-9a-f]{{8}} \({re.escape(folder)}\): every file was read back and matches its SHA-256\.$"
            )
            check(len(lines) == 1, f"{role} drive not verified: {keystone.labels()}")
        # The start-up checks run again: nothing is interrupted any more.
        keystone.activate("Done")
        keystone.wait_heading("Start-up checks")
        keystone.wait_label("OK: No operation was interrupted.", timeout=60)
    after = (tree_snapshot(primary), tree_snapshot(backup))
    check(before != after, "the drives did not change")
    for drive in (primary, backup):
        for placed in (f"certs/{SERIAL}.crt", f"keys/{SERIAL}.key"):
            check(
                os.path.isfile(os.path.join(drive, "keystone", placed)),
                f"{placed} not in place on {drive}",
            )
        check(
            journal_files(drive)[-1].endswith("-completed.json"),
            f"not completed on {drive}: {journal_files(drive)}",
        )
    # Nothing that existed before was overwritten or deleted (FR-22 AC8): the audit log
    # only grew, staged files were moved into place unchanged, the rest is identical.
    for snapshot_before, snapshot_after in zip(before, after):
        now = dict(snapshot_after)
        contents = set(now.values())
        for path, data in snapshot_before:
            if path.endswith(os.path.join("keystone", "audit.log")):
                check(now.get(path, b"").startswith(data), f"{path} was rewritten")
            elif f"{os.sep}staging{os.sep}" in path:
                check(data in contents, f"staged {path} was not moved into place unchanged")
            else:
                check(now.get(path) == data, f"{path} was changed or deleted")
    assert_no_plaintext_keys()


if __name__ == "__main__":
    run(test)
