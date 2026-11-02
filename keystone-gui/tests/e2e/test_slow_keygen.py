"""NFR-03: during master key generation the window stays responsive, shows progress
and Cancel works, leaving no output on the drives (keyboard only).

The development test hook `--test-hook slow-keygen` holds software key generation
until Cancel is pressed (the hook is not compiled into production builds), so the
test does not depend on how fast this machine generates an RSA 8,192 key. While the
key is being generated the window answers accessibility requests quickly (its main
loop is never blocked: the work runs on a worker thread). After Cancel: no
certificate, key, CRL, record or staged file exists on any drive, the journal marks
the operation cancelled, nothing reached the export drive, no plaintext private key
exists anywhere, and "Create new CA" is offered again.

# Covers: NFR-03, FR-16 AC1, FR-16 AC2, SEC-04, NFR-04
"""

import os
import statistics
import time

from keystone_e2e import (
    Keystone,
    assert_no_plaintext_keys,
    check,
    drive_args,
    files_under,
    make_dirs,
    run,
)


def test():
    primary, backup, export = make_dirs("primary", "backup", "export")
    args = [*drive_args(primary, backup, export), "--test-hook", "slow-keygen"]
    with Keystone(*args) as keystone:
        keystone.open_home()
        keystone.activate("Create new CA")
        keystone.wait_heading("Create the master: name and validity")
        keystone.type("KEYSTONE TEST E2E Slow Root")
        keystone.wait_label("OK: The name is valid: CN=KEYSTONE TEST E2E Slow Root")
        keystone.activate("Continue")
        keystone.wait_heading("Create the master: passphrase length")
        keystone.activate("Generate the passphrase")
        keystone.confirm_passphrase(10)
        keystone.wait_heading("Create the master: review")
        keystone.activate("Create the master")

        # Progress (FR-16 AC1): the key generation reports what it does.
        keystone.wait_heading("Creating the master")
        keystone.wait_label("candidate numbers tested so far.", exact=False, timeout=120)
        keystone.wait_label("Note: You can still cancel: nothing permanent has been done yet.")
        cancel = keystone.button("Cancel")
        check(cancel.sensitive, "Cancel is not offered during key generation")

        # Responsive (NFR-03): every request is answered by the GUI's main loop while
        # the key is generated on the worker thread.
        latencies = []
        for _ in range(20):
            start = time.monotonic()
            check(cancel.position is not None, "the Cancel button has no position")
            latencies.append(time.monotonic() - start)
            time.sleep(0.05)
        print(f"accessibility round trips: max {max(latencies):.3f} s, median {statistics.median(latencies):.3f} s")
        check(max(latencies) < 1.0, f"the window stalled during key generation: {latencies}")
        check(statistics.median(latencies) < 0.2, f"slow answers: {latencies}")

        # Cancel (FR-16 AC2).
        keystone.activate("Cancel")
        keystone.wait_heading("Cancelled", timeout=120)
        keystone.wait_label(
            "Note: Cancelled before anything permanent was done. Staged files were removed; the reserved serial number stays reserved."
        )
        # The drives hold no CA yet: Create new CA is offered again.
        keystone.activate("Back to the start-up checks")
        keystone.continue_to_home()
        check(keystone.button("Create new CA").sensitive, "Create new CA is not offered again")
    for drive in (primary, backup):
        keystone_dir = os.path.join(drive, "keystone")
        for folder in ("certs", "keys", "crls", "record", "staging"):
            left = files_under(os.path.join(keystone_dir, folder))
            check(left == [], f"{folder} on {drive} is not empty: {left}")
        journal = files_under(os.path.join(keystone_dir, "journal"))
        check(
            any(name.endswith("-cancelled.json") for name in journal),
            f"no cancelled journal entry on {drive}: {journal}",
        )
    check(files_under(export) == [], f"the export drive is not empty: {files_under(export)}")
    assert_no_plaintext_keys()


if __name__ == "__main__":
    run(test)
