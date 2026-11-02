"""Keyboard only: drive selection -> start-up checks -> clock confirmation -> home.

Every step is reached with Tab, Shift+Tab and Space only; no mouse and no
accessibility actions. Every interactive widget on the drive screen is in the
focus order, and every status is given in words.

# Covers: NFR-04, NFR-10, PRD section 6 preamble, FR-12 AC1, FR-17 AC1, FR-19 AC1, SEC-16, SEC-20
"""

from keystone_e2e import Keystone, check, drive_args, make_dirs, run


def test():
    primary, backup, export = make_dirs("primary", "backup", "export")
    with Keystone(*drive_args(primary, backup, export)) as keystone:
        keystone.wait_heading("Choose the CA drives")
        # Every interactive widget is reachable with Tab (one full cycle).
        expected = {
            ("text", "Primary drive folder"),
            ("text", "Backup drive folder"),
            ("text", "Second backup drive folder (optional)"),
            ("text", "Export drive folder"),
            ("push button", "Choose primary drive folder…"),
            ("push button", "Choose backup drive folder…"),
            ("push button", "Choose second backup drive folder…"),
            ("push button", "Choose export drive folder…"),
            ("push button", "Check drives"),
        }
        order = keystone.focus_order(20)
        missing = expected - set(order)
        check(not missing, f"not reachable by keyboard: {missing}; order: {order}")
        # Fields come before the main button (sensible order).
        check(
            order.index(("text", "Export drive folder"))
            < order.index(("push button", "Check drives")),
            f"focus order: {order}",
        )

        # Drive selection -> start-up checks.
        keystone.activate("Check drives")
        keystone.wait_heading("Start-up checks")
        keystone.wait_label(
            "Note: The drives are empty: there is no audit log or history to check yet. You can create a new CA."
        )
        check(
            keystone.has_label(
                "Note: Development build: the network check is compiled only into production builds (FR-01 AC2)."
            ),
            f"network line missing: {keystone.labels()}",
        )
        keystone.button("Continue")

        # Start-up checks -> clock confirmation.
        keystone.activate("Continue")
        keystone.wait_heading("Confirm the date and time")
        keystone.wait_label("The system clock says", exact=False)
        check(
            keystone.labels_matching(r"^OK: The time passes the checks"),
            f"clock check result missing: {keystone.labels()}",
        )
        check(
            keystone.labels_matching(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$"),
            f"time in UTC not shown: {keystone.labels()}",
        )
        for name in ("Date in UTC (YYYY-MM-DD)", "Time in UTC (HH:MM or HH:MM:SS)"):
            keystone.widget(name, "text")
        # Back with Shift+Tab works too.
        keystone.tab_to("Back", "push button")
        keystone.tab_to("Use the time I entered", "push button", backwards=True)

        # Clock confirmation -> home.
        keystone.activate("Confirm date and time")
        keystone.wait_heading("What do you want to do?")
        create = keystone.button("Create new CA")
        check(create.sensitive, "Create new CA is not offered on empty drives")
        for name in (
            "Set up YubiKey and main intermediate",
            "New sub-intermediate",
            "Revoke a certificate",
            "Refresh a CRL",
            "Replace lost YubiKey",
        ):
            check(not keystone.button(name).sensitive, f"{name} is offered on empty drives")
        check(
            keystone.has_label(
                "Note: Not available: the drives are empty. Create the CA first."
            ),
            f"reason not given in words: {keystone.labels()}",
        )
        check(
            keystone.labels_matching(r"^OK: Time confirmed for the next action: "),
            f"confirmed time not shown: {keystone.labels()}",
        )

        # Flow A starts with the keyboard and its first field has the focus.
        keystone.activate("Create new CA")
        keystone.wait_heading("Create the master: name and validity")
        focused = keystone.focused()
        check(
            focused is not None and focused.name == "Common Name (required)",
            f"focus is on {keystone.describe(focused)}",
        )
        keystone.wait_label("Blocked: The Common Name is required")
        check(not keystone.button("Continue").sensitive, "Continue enabled without a name")
        keystone.type("KEYSTONE TEST E2E Root")
        keystone.wait_label("OK: The name is valid: CN=KEYSTONE TEST E2E Root")
        check(keystone.button("Continue").sensitive, "Continue disabled with a valid name")
        keystone.wait_label("OK: Valid from", exact=False)


if __name__ == "__main__":
    run(test)
