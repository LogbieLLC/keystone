"""Blocking start-up warnings (keyboard only).

1. A backup drive whose first audit entry was edited: the start-up checks name the
   first bad entry and disable every signing action.
2. A backup drive whose last audit entry was edited: both chains verify, but the
   histories differ after entry 1. Both histories are shown side by side and every
   signing action is disabled; Keystone never chooses one.

# Covers: FR-14 AC3, FR-12 AC3, SEC-09, SEC-22, NFR-04
"""

from keystone_e2e import Keystone, check, drive_args, make_dirs, prepare, run


def open_checks(primary, backup, export):
    keystone = Keystone(*drive_args(primary, backup, export))
    keystone.wait_heading("Choose the CA drives")
    keystone.activate("Check drives")
    keystone.wait_heading("Start-up checks")
    return keystone


def no_continue(keystone):
    check(
        not keystone.find_all(
            lambda n: n.roleName == "push button" and n.name in ("Continue", "Open recovery screen")
        ),
        "the operator can continue past a blocking warning",
    )


def broken_chain():
    primary, backup, export = make_dirs("primary", "backup", "export")
    prepare("broken-audit", primary, backup)
    with open_checks(primary, backup, export) as keystone:
        broken = keystone.wait_label("the audit log is broken: entry 1 is the first bad entry", exact=False)
        check(broken.name.startswith("Blocked: backup drive "), f"wrong drive: {broken.name}")
        check(backup in broken.name, f"the drive path is not named: {broken.name}")
        check(
            keystone.labels_matching(r"^OK: primary drive .*: the audit log verifies \(2 entries\)\.$"),
            f"primary drive result missing: {keystone.labels()}",
        )
        keystone.wait_label("Blocked: Every signing action is disabled.", exact=False)
        no_continue(keystone)
        # The operator can still check again or choose other drives by keyboard.
        keystone.tab_to("Check again", "push button")
        keystone.tab_to("Choose other drives", "push button")


def diverged():
    primary, backup, export = make_dirs("primary", "backup", "export")
    prepare("diverged", primary, backup)
    with open_checks(primary, backup, export) as keystone:
        keystone.wait_label(
            "Blocked: The drives hold different histories after entry 1. Both are shown side by side. Keystone never chooses one; every signing action is disabled."
        )
        keystone.wait_label("Divergent histories, side by side")
        labels = keystone.labels()
        primary_column = [l for l in labels if l.startswith("primary drive ") and primary in l]
        backup_column = [l for l in labels if l.startswith("backup drive ") and backup in l]
        check(primary_column and backup_column, f"history columns missing: {labels}")
        check(
            keystone.labels_matching(r"^#2 .* export CN=KEYSTONE TEST second \(success\)$"),
            f"primary history missing: {labels}",
        )
        check(
            keystone.labels_matching(r"^#2 .* export CN=KEYSTONE TEST edited \(success\)$"),
            f"backup history missing: {labels}",
        )
        no_continue(keystone)
        check(
            not keystone.find_all(lambda n: n.roleName == "push button" and "Copy" in n.name),
            "a repair is offered for divergent histories",
        )


def test():
    broken_chain()
    diverged()


if __name__ == "__main__":
    run(test)
