"""Flow A wizard end to end, keyboard only, up to the backend adapter.

Drive selection, start-up checks and clock confirmation, then: master name and
validity with live validation, passphrase length, show-once and confirmation, the
review step, and "Create the master". The operations layer is not connected in this
build, so the adapter answers "not connected yet" and nothing is written: the drives
stay empty. The confirmed time is used by one execute step only.

# Covers: PRD section 6 Flow A, FR-02 AC4, FR-03 AC2, FR-03 AC3, FR-03 AC4, FR-10 AC3, FR-16 AC1, SEC-16, SEC-17, NFR-04, NFR-10
"""

import os
import re

from keystone_e2e import Keystone, check, drive_args, make_dirs, run


def shown_words(keystone):
    words = {}
    for label in keystone.labels():
        match = re.fullmatch(r"(\d+)\. ([a-z-]+)", label)
        if match:
            words[int(match.group(1))] = match.group(2)
    return words


def test():
    primary, backup, export = make_dirs("primary", "backup", "export")
    with Keystone(*drive_args(primary, backup, export)) as keystone:
        keystone.wait_heading("Choose the CA drives")
        keystone.activate("Check drives")
        keystone.wait_heading("Start-up checks")
        keystone.activate("Continue")
        keystone.wait_heading("Confirm the date and time")
        keystone.activate("Confirm date and time")
        keystone.wait_heading("What do you want to do?")
        keystone.activate("Create new CA")

        # Name and validity (FR-02 AC4, FR-10 AC3).
        keystone.wait_heading("Create the master: name and validity")
        keystone.type("KEYSTONE TEST E2E Root")
        keystone.tab_to("Country (optional, 2 letters)", "text")
        keystone.type("u")
        keystone.wait_label("Blocked: The Country must be exactly 2 letters", exact=False)
        check(not keystone.button("Continue").sensitive, "Continue enabled with a bad country")
        keystone.type("s")
        keystone.wait_label("OK: The name is valid: CN=KEYSTONE TEST E2E Root, C=US")
        check(
            keystone.has_label("A master (root) certificate can be valid for 1 to 25 years."),
            f"validity bounds not explained: {keystone.labels()}",
        )
        keystone.widget("Validity in years", "spin button")
        keystone.activate("Continue")

        # Passphrase length (FR-03 AC2).
        keystone.wait_heading("Create the master: passphrase length")
        keystone.wait_label("Note: 10 words give about 129 bits of strength.")
        keystone.activate("Generate the passphrase")

        # Show once and confirm (FR-03 AC3, AC4, SEC-17).
        keystone.wait_heading("Write down your passphrase")
        words = shown_words(keystone)
        check(sorted(words) == list(range(1, 11)), f"words shown: {words}")
        keystone.activate("I have written down all 10 words", role="check box")
        keystone.activate("Retype the words")
        keystone.wait_heading("Type the words again")
        for group, numbers in ((1, [1, 2, 3, 4]), (2, [5, 6, 7, 8]), (3, [9, 10])):
            keystone.tab_to(f"Word {numbers[0]}", "text")
            for number in numbers:
                keystone.type(words[number])
                keystone.press("Return")
            keystone.activate(f"Check group {group}")
            keystone.wait_label(f"OK: Group {group} matches and is kept.")
        keystone.activate("Confirm passphrase")

        # Review (the words are never shown again).
        keystone.wait_heading("Create the master: review")
        keystone.wait_label(
            "OK: Passphrase: 10 words, confirmed. It will not be shown again."
        )
        check(not shown_words(keystone), "words shown again after confirmation")
        check(
            keystone.has_label("Note: Name: CN=KEYSTONE TEST E2E Root, C=US."),
            f"name not reviewed: {keystone.labels()}",
        )
        check(
            keystone.has_label("Note: Validity: 20 years."),
            f"validity not reviewed: {keystone.labels()}",
        )
        check(
            keystone.labels_matching(r"^OK: Time confirmed: .* It is used for this action only\.$"),
            f"confirmed time not reviewed: {keystone.labels()}",
        )
        check(
            keystone.has_label(
                "Note: Key: RSA 8,192-bit, stored only in an encrypted file."
            ),
            f"fixed profile not shown: {keystone.labels()}",
        )

        # Execute through the backend adapter: not connected yet, nothing written.
        keystone.activate("Create the master")
        keystone.wait_heading("Not connected yet")
        keystone.wait_label(
            "Blocked: Creating the master is not connected yet: this build's operations layer is not wired to the GUI. Nothing was written to any drive or YubiKey."
        )
        # The confirmed time was used: the next flow asks for it again (SEC-16).
        keystone.activate("Back to the start-up checks")
        keystone.wait_heading("Start-up checks")
        keystone.activate("Continue")
        keystone.wait_heading("Confirm the date and time")
    for drive in (primary, backup, export):
        check(os.listdir(drive) == [], f"{drive} is not empty: {os.listdir(drive)}")


if __name__ == "__main__":
    run(test)
