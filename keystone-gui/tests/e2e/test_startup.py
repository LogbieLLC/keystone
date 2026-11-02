"""The application starts on the drive selection screen.

# Covers: NFR-10, NFR-05, NFR-04, FR-12 AC1, SEC-03 (starts with the hardening step first; development build)
"""

from keystone_e2e import Keystone, check, run


def test():
    with Keystone() as keystone:
        keystone.wait_heading("Choose the CA drives")
        for name in (
            "Primary drive folder",
            "Backup drive folder",
            "Second backup drive folder (optional)",
            "Export drive folder",
        ):
            keystone.widget(name, "text")
        for name in (
            "Choose primary drive folder…",
            "Choose backup drive folder…",
            "Choose second backup drive folder…",
            "Choose export drive folder…",
            "Check drives",
        ):
            keystone.button(name)
        # The first field has the keyboard focus.
        focused = keystone.focused()
        check(
            focused is not None
            and focused.roleName == "text"
            and focused.name == "Primary drive folder",
            f"initial focus is on {keystone.describe(focused)}",
        )
        # Checking empty fields explains every missing drive in words (FR-12 AC1).
        keystone.activate("Check drives")
        keystone.wait_label("Blocked: Choose the primary drive.")
        check(
            keystone.has_label(
                "Blocked: Choose at least one backup drive: every change is written to the primary and at least one backup."
            ),
            f"no backup-drive reason: {keystone.labels()}",
        )
        check(
            keystone.has_label("Blocked: Choose the export drive."),
            f"no export-drive reason: {keystone.labels()}",
        )


if __name__ == "__main__":
    run(test)
