"""Flow A end to end, keyboard only: the master is really created.

Drive selection, start-up checks and clock confirmation, then: master name and
validity with live validation, passphrase length, show-once and confirmation, the
review step, and "Create the master". The operations layer generates the RSA 8,192
key, self-signs the master, signs its first CRL and writes everything to both drives
and the CRL to the export drive. The result screen shows every drive read back and
the SHA-256 fingerprint, which must equal the fingerprint of the certificate file
on the drive. The confirmed time is used by one execute step only, and no plaintext
private key exists anywhere afterwards.

# Covers: PRD section 6 Flow A, FR-02 AC1, FR-02 AC4, FR-03 AC2, FR-03 AC3, FR-03 AC4, FR-04 AC1, FR-10 AC3, FR-12 AC1, FR-12 AC2, FR-13 AC6, FR-16 AC1, FR-20 AC1, SEC-04, SEC-08, SEC-16, SEC-17, NFR-04, NFR-10
"""

import os
import re

from keystone_e2e import (
    Keystone,
    assert_no_plaintext_keys,
    certificate_fingerprint,
    check,
    drive_args,
    files_under,
    make_dirs,
    run,
)


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

        # Execute: RSA 8,192 generation can take minutes (NFR-03).
        keystone.activate("Create the master")
        keystone.wait_heading("The master (root) certificate was created", timeout=600)
        for role, folder in (("primary", primary), ("backup", backup)):
            lines = keystone.labels_matching(
                rf"^OK: {role} drive [0-9a-f]{{8}} \({re.escape(folder)}\): every file was read back and matches its SHA-256\.$"
            )
            check(len(lines) == 1, f"{role} drive not verified: {keystone.labels()}")
        for name in ("keys/master.key", "certs/master.crt"):
            check(keystone.labels().count(name) == 2, f"{name} not listed per drive")
        fingerprints = keystone.result_fingerprints()
        check(len(fingerprints) == 1, f"fingerprints shown: {fingerprints}")
        on_drive = certificate_fingerprint(os.path.join(primary, "keystone", "certs", "master.crt"))
        check(fingerprints[0] == on_drive, f"shown {fingerprints[0]}, file {on_drive}")
        check(
            keystone.has_label("CN=KEYSTONE TEST E2E Root, C=US (master (root))"),
            f"certificate title missing: {keystone.labels()}",
        )
        check(
            keystone.labels_matching(r"^CRL number 1 of CN=KEYSTONE TEST E2E Root, C=US, next update "),
            f"first CRL not shown: {keystone.labels()}",
        )
        check(
            keystone.labels_matching(r"^Note: Upload the master's first CRL from the export drive"),
            f"upload note missing: {keystone.labels()}",
        )
        # The confirmed time was used: the next flow asks for it again (SEC-16).
        keystone.activate("Done")
        keystone.wait_heading("Start-up checks")
        keystone.wait_label("OK: All 2 drives hold the same history.", timeout=60)
        keystone.activate("Continue")
        keystone.wait_heading("Confirm the date and time")
    for drive in (primary, backup):
        names = [os.path.relpath(f, drive) for f in files_under(drive)]
        for expected in ("keystone/keys/master.key", "keystone/certs/master.crt"):
            check(expected in names, f"{expected} missing on {drive}: {names}")
        with open(os.path.join(drive, "keystone", "keys", "master.key")) as handle:
            check(
                handle.read().startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
                "the master key is not encrypted PKCS#8",
            )
    exported = [os.path.basename(f) for f in files_under(export)]
    check(
        len(exported) == 1 and exported[0].endswith("-crl-000001.crl"),
        f"export drive: {exported}",
    )
    assert_no_plaintext_keys()


if __name__ == "__main__":
    run(test)
