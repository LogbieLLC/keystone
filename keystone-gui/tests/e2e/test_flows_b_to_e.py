"""Flows B to E, Refresh CRL and a recovery, keyboard only, against the simulated
YubiKey, on one prepared master (Flow A itself is test_flow_a_wizard).

1. Flow B: a factory-fresh YubiKey gets a new PIN and PUK, the master's CRL address
   is asked once, the key is generated on the YubiKey, the master signs the main
   intermediate and the YubiKey its first CRL.
2. Flow C twice: with name constraints (the main intermediate's CRL address is asked
   once), then explicitly without them (warning). Each gets its own 10-word
   passphrase and is signed with the YubiKey PIN.
3. Flow D: the YubiKey revokes the constrained sub-intermediate (CRL number 2).
4. Refresh CRL: the main intermediate's CRL is re-signed (CRL number 3).
5. Flow E: the master revokes the main intermediate; the other sub-intermediate is
   cut off and listed for re-issue.
6. A master CRL refresh is interrupted right after its files were moved into place
   (ops test seam, in e2e_prepare); the start-up checks open the recovery screen and
   "Finish from primary drive" completes it and exports the CRL.
7. Flow B on a new YubiKey (another simulated device): the master's CRL address is
   not asked again.

Every result is read from labels: each drive read back and verified, the SHA-256
fingerprint of each new certificate, the CRL numbers. After every flow no plaintext
private key exists anywhere in the temporary folder.

# Covers: PRD section 6 Flow B, Flow C, Flow D, Flow E, FR-05 AC3, FR-06 AC2, FR-07 AC3, FR-08 AC2, FR-09 AC1, FR-12 AC2, FR-13 AC1, FR-13 AC4, FR-13 AC6, FR-15 AC1, FR-18 AC1, FR-20 AC1, FR-21 AC1, FR-21 AC6, FR-22 AC4, FR-22 AC8, SEC-04, SEC-08, SEC-16, NFR-04, NFR-08, NFR-10
"""

import os
import re
import time

from keystone_e2e import (
    Keystone,
    assert_no_plaintext_keys,
    certificate_fingerprint,
    check,
    drive_args,
    files_under,
    make_dirs,
    prepare,
    run,
)

PIN = "246810"
PUK = "13572468"
MASTER_CRL = "http://pki.keystone-test.invalid/master.crl"
MAIN_CRL = "http://pki.keystone-test.invalid/main.crl"


def step(text):
    print(f"--- {time.strftime('%H:%M:%S')} {text}", flush=True)


def wait_sensitive(keystone, name, timeout=30):
    return keystone.wait_for(
        lambda n: n.roleName == "push button" and n.name == name and n.sensitive,
        f"enabled button {name!r}",
        timeout,
    )


def verified_drives(keystone, primary, backup):
    for role, folder in (("primary", primary), ("backup", backup)):
        lines = keystone.labels_matching(
            rf"^OK: {role} drive [0-9a-f]{{8}} \({re.escape(folder)}\): every file was read back and matches its SHA-256\.$"
        )
        check(len(lines) == 1, f"{role} drive not verified: {keystone.labels()}")


def new_certificate_file(primary, before):
    after = set(files_under(os.path.join(primary, "keystone", "certs")))
    new = [f for f in after - before if f.endswith(".crt")]
    check(len(new) == 1, f"new certificate files: {new}")
    return new[0]


def check_fingerprint(keystone, cert_file):
    shown = keystone.result_fingerprints()
    expected = certificate_fingerprint(cert_file)
    check(shown == [expected], f"fingerprint shown {shown}, file {expected}")


def certs(primary):
    return set(files_under(os.path.join(primary, "keystone", "certs")))


def type_master(keystone, words):
    keystone.wait_heading("Unlock the master")
    keystone.fill("Master passphrase", " ".join(words))
    keystone.activate("Continue")


def flow_b(keystone, primary, backup, serial, name, ask_crl, words):
    step(f"Flow B on YubiKey {serial}")
    before = certs(primary)
    keystone.activate("Set up YubiKey and main intermediate")
    keystone.wait_label(f"Note: YubiKey serial number {serial}, firmware 5.7.4.", exact=False)
    keystone.activate("Continue")
    keystone.wait_heading("Set up the YubiKey: PIN and PUK")
    keystone.fill("New PIN", PIN)
    keystone.fill("New PIN again", PIN)
    keystone.fill("New PUK", PUK)
    keystone.fill("New PUK again", PUK)
    keystone.activate("Continue")
    if ask_crl:
        keystone.wait_heading("Set up the YubiKey: the master's CRL address")
        keystone.fill("CRL address (http:// or https://)", MASTER_CRL)
        wait_sensitive(keystone, "Continue")
        keystone.activate("Continue")
    keystone.wait_heading("Set up the YubiKey: main intermediate")
    check(
        not keystone.has_label("Set up the YubiKey: the master's CRL address"),
        "the master's CRL address was asked again",
    )
    keystone.fill("Common Name (required)", name)
    keystone.wait_label(f"OK: The name is valid: CN={name}")
    keystone.activate("Continue")
    type_master(keystone, words)
    keystone.wait_heading("Set up the YubiKey: review")
    keystone.activate("Set up the YubiKey")
    keystone.wait_heading(
        f"The YubiKey {serial} is set up and the main intermediate was created", timeout=180
    )
    verified_drives(keystone, primary, backup)
    check_fingerprint(keystone, new_certificate_file(primary, before))
    check(
        keystone.labels_matching(rf"^CRL number 1 of CN={re.escape(name)}, next update "),
        f"first CRL of the main intermediate not shown: {keystone.labels()}",
    )
    check(
        keystone.labels_matching(r"^Note: Upload this CRL to StarnetAuth"),
        f"upload note missing: {keystone.labels()}",
    )
    assert_no_plaintext_keys()


def flow_c(keystone, primary, backup, name, constrained, ask_crl):
    step(f"Flow C {name}")
    before = certs(primary)
    keystone.activate("New sub-intermediate")
    keystone.wait_heading("New sub-intermediate: name, validity and permitted names")
    keystone.fill("Common Name (required)", name)
    if constrained:
        keystone.fill("Permitted DNS names (separate with commas or spaces)", "starnet")
        keystone.wait_label("OK: permitted DNS: starnet")
    else:
        keystone.choose_radio("No name constraints (not recommended)")
        keystone.wait_label("Warning: ", exact=False)
    wait_sensitive(keystone, "Continue")
    keystone.activate("Continue")
    if ask_crl:
        keystone.wait_heading("New sub-intermediate: the main intermediate's CRL address")
        keystone.fill("CRL address (http:// or https://)", MAIN_CRL)
        wait_sensitive(keystone, "Continue")
        keystone.activate("Continue")
    keystone.wait_heading("New sub-intermediate: passphrase")
    keystone.activate("Generate the passphrase")
    keystone.confirm_passphrase(10)
    keystone.wait_heading("New sub-intermediate: review")
    if constrained:
        for line in (
            "Note: permitted DNS: starnet",
            "Note: email addresses: none allowed (only the reserved .keystone.invalid domain is permitted)",
            "Note: URIs: none allowed (only the reserved .keystone.invalid domain is permitted)",
        ):
            check(keystone.has_label(line), f"{line!r} not reviewed: {keystone.labels()}")
    else:
        check(
            keystone.labels_matching(r"^Warning: Name constraints: off"),
            f"no warning for unconstrained: {keystone.labels()}",
        )
    keystone.fill("YubiKey PIN", PIN)
    wait_sensitive(keystone, "Create the sub-intermediate")
    keystone.activate("Create the sub-intermediate")
    keystone.wait_heading("The sub-intermediate was created", timeout=180)
    verified_drives(keystone, primary, backup)
    cert = new_certificate_file(primary, before)
    stem = os.path.basename(cert)[: -len(".crt")]
    check_fingerprint(keystone, cert)
    exported = keystone.labels_matching(r"keystone-export/")
    for suffix in (".crt", ".key", "-chain.pem"):
        check(
            any(label.endswith(f"/{stem}{suffix}") for label in exported),
            f"{stem}{suffix} not on the export drive: {exported}",
        )
    assert_no_plaintext_keys()
    return stem


def flow_d(keystone, primary, backup, sub_name, main_name):
    step(f"Flow D revoke {sub_name}")
    keystone.activate("Revoke a certificate")
    keystone.wait_heading("Revoke a certificate")
    keystone.choose_radio(f"CN={sub_name} (sub-intermediate)")
    keystone.activate("Continue")
    keystone.wait_heading("Revoke a certificate: review and sign")
    check(
        keystone.labels_matching(rf"^Warning: Revoke: CN={re.escape(sub_name)} "),
        f"revoked certificate not reviewed: {keystone.labels()}",
    )
    keystone.fill("YubiKey PIN", PIN)
    wait_sensitive(keystone, "Revoke")
    keystone.activate("Revoke")
    keystone.wait_heading("The certificate was revoked and a new CRL signed", timeout=120)
    verified_drives(keystone, primary, backup)
    check(
        keystone.labels_matching(rf"^CRL number 2 of CN={re.escape(main_name)}, next update "),
        f"new CRL not shown: {keystone.labels()}",
    )
    check(
        keystone.labels_matching(rf"^Note: Revoked: CN={re.escape(sub_name)}, serial "),
        f"revocation not shown: {keystone.labels()}",
    )
    assert_no_plaintext_keys()


def refresh_main_crl(keystone, primary, backup, main_name):
    step("Refresh CRL of the main intermediate")
    keystone.activate("Refresh a CRL")
    keystone.wait_heading("Refresh a CRL")
    keystone.choose_radio(f"CN={main_name} (main intermediate)")
    keystone.activate("Continue")
    keystone.wait_heading("Refresh a CRL: review and sign")
    keystone.fill("YubiKey PIN", PIN)
    wait_sensitive(keystone, "Refresh the CRL")
    keystone.activate("Refresh the CRL")
    keystone.wait_heading("The CRL was refreshed", timeout=120)
    verified_drives(keystone, primary, backup)
    check(
        keystone.labels_matching(rf"^CRL number 3 of CN={re.escape(main_name)}, next update "),
        f"refreshed CRL not shown: {keystone.labels()}",
    )
    assert_no_plaintext_keys()


def flow_e(keystone, primary, backup, main_name, cut_off_name, words):
    step("Flow E")
    keystone.activate("Replace lost YubiKey")
    keystone.wait_heading("Replace lost YubiKey")
    check(
        keystone.labels_matching(rf"^Warning: Revoke: CN={re.escape(main_name)} "),
        f"old main intermediate not listed: {keystone.labels()}",
    )
    check(
        keystone.labels_matching(
            rf"^Warning: Mark revoked by ancestor, then re-issue: CN={re.escape(cut_off_name)} "
        ),
        f"cut-off sub-intermediate not listed: {keystone.labels()}",
    )
    keystone.activate("Continue")
    type_master(keystone, words)
    keystone.wait_heading("The old main intermediate was revoked by the master", timeout=120)
    verified_drives(keystone, primary, backup)
    check(
        keystone.labels_matching(r"^CRL number 2 of CN=KEYSTONE TEST E2E Root, next update "),
        f"new master CRL not shown: {keystone.labels()}",
    )
    check(
        keystone.labels_matching(r"^Warning: Re-issue these sub-intermediates under the new main intermediate"),
        f"re-issue advice missing: {keystone.labels()}",
    )
    keystone.button("Set up the new YubiKey now")
    assert_no_plaintext_keys()


def recover_interrupted_refresh(keystone, primary, backup, export):
    step("Recovery of the interrupted refresh")
    keystone.wait_heading("Choose the CA drives")
    keystone.activate("Check drives")
    keystone.wait_heading("Start-up checks")
    interrupted = keystone.wait_label(
        "(CN=KEYSTONE TEST E2E Root) was interrupted. Open the recovery screen", exact=False
    )
    operation = re.search(r"operation (\d+)", interrupted.name).group(1)
    keystone.activate("Open recovery screen")
    keystone.wait_heading("Recover an interrupted operation")
    keystone.wait_label(
        f"Interrupted: operation {operation} to refresh a CRL (CN=KEYSTONE TEST E2E Root).",
        exact=False,
    )
    group = keystone.wait_label("Recovery actions").parent
    actions = [
        n.name for n in group.findChildren(lambda n: n.roleName == "push button" and n.showing)
    ]
    check(1 <= len(actions) <= 2, f"actions: {actions}")
    finish = actions[0]
    check(finish.startswith("Finish from primary drive "), f"first action: {finish}")
    keystone.activate(finish)
    keystone.wait_heading(finish)
    keystone.tab_to(finish, "push button")
    keystone.press("space")
    keystone.wait_heading(f"Operation {operation} was finished", timeout=60)
    verified_drives(keystone, primary, backup)
    check(
        any(f.endswith("master-crl-000003.crl") for f in files_under(export)),
        f"the finished CRL was not exported: {files_under(export)}",
    )
    keystone.activate("Done")
    keystone.wait_heading("Start-up checks")
    keystone.wait_label("OK: No operation was interrupted.", timeout=60)
    keystone.continue_to_home()
    assert_no_plaintext_keys()


def test():
    primary, backup, export = make_dirs("primary", "backup", "export")
    step("preparing the master")
    words = prepare("master", primary, backup, export).split()
    check(len(words) == 10, "the prepared master passphrase has 10 words")
    main_name = "KEYSTONE TEST E2E Main"
    with Keystone(*drive_args(primary, backup, export)) as keystone:
        keystone.open_home()
        flow_b(keystone, primary, backup, 31415926, main_name, True, words)
        keystone.done_to_home()
        flow_c(keystone, primary, backup, "KEYSTONE TEST E2E Sub One", True, True)
        keystone.done_to_home()
        flow_c(keystone, primary, backup, "KEYSTONE TEST E2E Sub Two", False, False)
        keystone.done_to_home()
        flow_d(keystone, primary, backup, "KEYSTONE TEST E2E Sub One", main_name)
        keystone.done_to_home()
        refresh_main_crl(keystone, primary, backup, main_name)
        keystone.done_to_home()
        flow_e(keystone, primary, backup, main_name, "KEYSTONE TEST E2E Sub Two", words)
    step("interrupting a master CRL refresh")
    prepare("interrupt-refresh", primary, backup, export, stdin=" ".join(words) + "\n")
    with Keystone(*drive_args(primary, backup, export), "--sim-serial", "27182818") as keystone:
        recover_interrupted_refresh(keystone, primary, backup, export)
        flow_b(keystone, primary, backup, 27182818, "KEYSTONE TEST E2E Main Two", False, words)
    assert_no_plaintext_keys()


if __name__ == "__main__":
    run(test)
