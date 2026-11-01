# Keystone — Product Requirements Document

Offline X.509 CA key and certificate generator · Nov 1, 2026 · @Brad Byrd

## 1. Summary

Keystone is a Rust desktop application for Ubuntu 26.04.1 that builds a three-level offline certificate authority (CA) hierarchy on an air-gapped laptop. It creates an RSA 8,192-bit master (root) certificate stored in an encrypted file, a RSA 4,096-bit main intermediate whose key is generated on and never leaves a YubiKey, and RSA 4,096-bit sub-intermediates exported as encrypted PEM files for issuing systems such as StarnetAuth.

The production build never touches a network. All CA state lives on two or more USB drives, every action is recorded in a tamper-evident audit log, and revocation is handled with offline CRL files.

The code will be AI-generated. Every requirement therefore has an ID and testable acceptance criteria, and every feature is built test-first (TDD) and proven by end-to-end (E2E) tests.

## 2. Problem statement

Running a private CA safely needs a root key that is never exposed to a networked computer, but the usual tools (the `openssl` command line, `step` and similar) are long, error-prone command sequences with no guard rails. One wrong flag can produce a certificate that other systems reject, a key written to disk unencrypted, or a child certificate that outlives its parent.

The operator (a single person) needs one guided application that makes the safe path the easy path: generate the keys offline, protect them properly, produce standards-correct certificates that StarnetAuth and other systems accept, and keep a reliable record of everything signed.

If this is not built, the CA is either run by hand with a high chance of mistakes, or the root key ends up on a networked machine, where a single compromise lets an attacker impersonate every service that trusts the root.

## 3. Goals, non-goals and hard rules

**Goals**

1. **G1 Secure offline key generation.** No private key ever exists unencrypted on any disk. Using the master only on the air-gapped laptop is an operating rule: the tool supports it (encrypted key file, network refusal) but cannot enforce it, because the encrypted file plus its passphrase would work on any machine.
2. **G2 Standards-correct certificates.** Every certificate and CRL conforms to RFC 5280 and validates with `openssl verify`. StarnetAuth can use the sub-intermediates, and so can other issuing systems.
3. **G3 Easy GUI.** A guided interface where the secure path is also the easiest path. Very low risk tolerance, with every safety step engineered to be as easy as possible.
4. **G4 Proven by tests.** Every feature is written test-first (TDD) and covered by E2E tests before release.

**Hard rules** (apply to every version)

- **HR-1** The production build never opens, uses or depends on a network connection. It contains no networking code paths.
- **HR-2** Development and test builds may run anywhere, including networked CI. Production builds run only on a computer with no network connection.
- **HR-3** The tool stays general-purpose. StarnetAuth compatibility is required, but nothing is hard-coded to StarnetAuth.

**Non-goals for version 1**

- Issuing leaf (end-entity) certificates such as TLS server certificates. Planned for a later version.
- Online revocation (OCSP), ACME, or any CA server function. Network functions are permanently out of scope (HR-1).
- Hardware tokens other than YubiKey 5 (firmware 5.7+), or a hardware-held master key.
- Multiple operators, roles or user accounts.

## 4. Users and roles

Keystone has exactly one user: the operator, who owns the CA. There are no accounts and no roles. Possession of the secrets is what grants access.

| Actor | Trusted? | What they hold or can reach |
| --- | --- | --- |
| Operator (you) | Yes, the only trusted person | Master passphrase, YubiKey PIN and PUK, sub-intermediate passphrases, laptop, USB drives, YubiKey |
| Anyone else with physical access (visitor, thief, household member) | No | Possibly the laptop, a USB drive or the YubiKey, but none of the secrets |
| Build machines and CI | Partly: trusted only to produce identical builds | Source code and dependencies, never any CA secret |
| Issuing systems (StarnetAuth and others) | Trusted to use a sub-intermediate, nothing more | One sub-intermediate key, its passphrase and the chain file |

## 5. Scope

Version 1 builds a three-level CA hierarchy and nothing below it. Each level is stored differently, matched to how valuable its key is.

&#91;embedded content: CA hierarchy · 3 levels inside Keystone, issuing systems outside\]

The master signs the main intermediate; the YubiKey signs each sub-intermediate. Revocation runs the same way: the master's CRL covers main intermediates, the YubiKey's CRL covers sub-intermediates.

**In version 1**

- Master, main intermediate and sub-intermediate creation (FR-02 to FR-09).
- Revocation with offline CRL files (FR-13).
- YubiKey 5 (firmware 5.7+) via native PIV, including hardening and replacement (FR-05, FR-06, FR-15).
- Multi-USB storage, issuance record, tamper-evident audit log (FR-11, FR-12, FR-14).
- GTK4 desktop GUI on Ubuntu 26.04.1.

**Later versions**

- Leaf (end-entity) certificate issuance.
- Possibly RSA-PSS signatures and other token types (would trigger a threat model review).

**Certificate profile defaults** (structure fixed in version 1; only names, validity, permitted names and CRL addresses are editable, FR-10 AC3)

| Setting | Master (root) | Main intermediate | Sub-intermediate |
| --- | --- | --- | --- |
| Key | RSA 8,192, file | RSA 4,096, on YubiKey | RSA 4,096, file |
| Validity | 20 years | 10 years | 5 years |
| basicConstraints (critical) | CA, no path length | CA, path length 1 | CA, path length 0 |
| keyUsage (critical) | keyCertSign, cRLSign | keyCertSign, cRLSign | keyCertSign, cRLSign |
| Signature | SHA-384 with RSA (PKCS#1 v1.5) | same | same |
| Name | Common Name required; Organization and Country optional | same | same |
| Name constraints (critical) | None | None | On by default: permitted DNS names entered by the operator; IP, email and URI excluded (FR-21) |

## 6. User flows

Every flow starts the same way: the tool checks there is no active network interface (FR-01), verifies the audit log (FR-14), and asks the operator to confirm the date and time (FR-17). Each flow ends with the write-and-verify step to 2+ USB drives (FR-12).

**Flow A: Create the master (first run)**

1. Operator plugs in the primary and backup USB drives and chooses "Create new CA".
2. Operator enters the master's name fields (Common Name required) and reviews the defaults (RSA 8,192, 20 years).
3. Operator picks a passphrase length from 10 to 20 words. The tool generates it and shows it once.
4. Operator writes the words down, then re-types all of them. The tool continues only on an exact match.
5. The tool generates the key (with progress and cancel), self-signs the master certificate, signs the master's first empty CRL (FR-13 AC6), encrypts the key, and writes everything to all USB drives.
6. The tool shows the master certificate's SHA-256 fingerprint for the operator to record.

**Flow B: Set up the YubiKey and create the main intermediate**

1. Operator inserts a YubiKey 5. The tool checks firmware 5.7 or newer and refuses older keys.
2. If the YubiKey still has default codes, the tool requires a new PIN and PUK, and sets a random PIN-protected management key.
3. The tool generates a 4,096-bit key on the YubiKey, with PIN-and-touch policy on every signature.
4. Operator unlocks the master with the passphrase. The master signs the main intermediate certificate (10 years, path length 1).
5. The certificate is written to the YubiKey and to all USB drives. The master key is wiped from memory. The YubiKey then signs the main intermediate's first empty CRL (PIN + touch), which goes to the export USB for StarnetAuth (FR-13 AC6).

**Flow C: Create a sub-intermediate (e.g. for StarnetAuth)**

1. Operator chooses "New sub-intermediate", enters name fields, reviews defaults (RSA 4,096, 5 years, path length 0), and enters the DNS names this sub-intermediate may issue for (name constraints, FR-21).
2. The tool generates the key in software and generates a 10-word passphrase for it, which the operator confirms.
3. Operator enters the YubiKey PIN and touches the YubiKey. The main intermediate signs the certificate.
4. The tool writes `.crt`, encrypted `.key` and chain `.pem` to all USB drives, plus an export folder for carrying to the issuing system.

**Flow D: Revoke and publish a CRL**

1. Operator picks a certificate from the issuance record and a revocation reason.
2. For a sub-intermediate, the YubiKey signs the new CRL (PIN + touch). For a main intermediate, the master signs it (passphrase).
3. The tool writes the CRL to all USB drives and the export folder.

**Flow E: Replace a lost or broken YubiKey**

1. Operator chooses "Replace lost YubiKey" and unlocks the master.
2. The master revokes the old main intermediate and issues a new master CRL.
3. The tool runs Flow B on a new YubiKey.
4. The tool lists every sub-intermediate signed by the old main intermediate and marks each one "revoked by ancestor". Revoking the old main intermediate already cuts them off for clients that check CRLs, so no signature from the lost YubiKey is needed. The tool then guides re-issuing each one under the new main intermediate (Flow C). The old main intermediate's last CRL stays hosted until it expires, because it can no longer be refreshed.

## 7. Functional requirements

Each requirement lists acceptance criteria (AC) written as testable statements. Every AC must have a test written before the code (TDD), at the level that best demonstrates it. E2E tests cover every user flow (A to E), every boundary (USB drives, YubiKey, StarnetAuth), interrupted writes, token loss and invalid certificates.

**FR-01 Network refusal at startup**

- AC1: In a production build, if any network interface other than loopback is up (Ethernet, Wi-Fi, Bluetooth PAN, USB tethering, WWAN), the tool shows an error naming the interface and exits with no other action.
- AC2: The check is compiled in only with the `production` Cargo feature; test builds omit it.
- AC3: The check reads local interface state only (for example `/sys/class/net`) and opens no network socket.

**FR-02 Create master certificate**

- AC1: Generates an RSA 8,192-bit key with public exponent 65537 using OpenSSL 3.
- AC2: Self-signs an X.509 v3 certificate with SHA-384 with RSA (PKCS#1 v1.5), default validity 20 years.
- AC3: Extensions: basicConstraints critical CA=true with no path length; keyUsage critical keyCertSign and cRLSign; subjectKeyIdentifier present.
- AC4: Common Name is required; Organization and Country are optional; Country must be 2 letters.

**FR-03 Passphrase generation**

- AC1: Words are drawn from the embedded EFF large wordlist (7,776 words) using the OS secure random source; no user-chosen passphrases are accepted.
- AC2: Operator chooses 10 to 20 words for the master; sub-intermediates default to 10.
- AC3: The passphrase is shown until the operator confirms it, then never again. It is never written to disk, logs or clipboard.
- AC4: Confirmation is designed for a tired person. Words are shown numbered, in groups of 4. Retyping is enabled only after the operator ticks "I have written down all N words". Each word box autocompletes from the wordlist and accepts only list words. Each group is checked on its own, and a mistake marks only that group for re-entry, keeping the correct groups. The operator can go back and view the words again at any time before confirming. The flow continues only when every word matches.

**FR-04 Encrypted key storage**

- AC1: The master key is stored as encrypted PKCS#8 PEM using PBES2 with scrypt and AES-256-CBC. Sub-intermediate keys use PBES2 with PBKDF2-HMAC-SHA256 (at least 600,000 iterations) and AES-256-CBC, the most widely readable variant, so OpenSSL and other issuing systems can decrypt it.
- AC2: `openssl pkey` can decrypt the file with the passphrase (interoperability test).
- AC3: A wrong passphrase gives a clear error and no partial output.

**FR-05 YubiKey detection**

- AC1: Talks to the YubiKey via native PIV over PC/SC, with no PKCS#11 or vendor library.
- AC2: Refuses YubiKeys with firmware older than 5.7 and states the reason.
- AC3: Shows serial number and firmware version before any action.

**FR-06 YubiKey hardening**

- AC1: Refuses to proceed while the PIN, PUK or management key are factory defaults.
- AC2: Requires a new PIN (6 to 8 characters) and PUK, entered twice.
- AC3: Sets a random AES-256 management key, stored on the YubiKey protected by the PIN.
- AC4: The signing slot uses PIN policy "always" and touch policy "always".

**FR-07 Main intermediate**

- AC1: Generates an RSA 4,096-bit key on the YubiKey; the private key never leaves it.
- AC2: Master signs the certificate: validity default 10 years, basicConstraints critical CA=true pathLen=1, keyUsage critical keyCertSign and cRLSign, SKI and AKI present.
- AC3: The certificate is stored in the YubiKey slot and on all USB drives.
- AC4: Before generating, the tool checks the signing slot. If it already holds a key or certificate, the tool refuses, shows what is there, and offers only an explicit wipe that needs the operator to type the YubiKey's serial number. It never overwrites a slot silently.
- AC5: After generating, the tool reads the slot's PIV attestation certificate and verifies the complete chain offline. Yubico's PIV attestation roots and the published Yubico intermediate certificates that firmware 5.7.4 and later require are embedded in the binary. The device-specific certificates come from the YubiKey itself during setup: the tool generates the slot's attestation certificate and reads the F9 attestation signing certificate from the device. The attested public key must equal the public key in the certificate the master signs. It must confirm the key was generated on this YubiKey, the serial matches FR-05, and the PIN and touch policies are "always". Any failure stops setup. The attestation certificate is stored with the issuance record.

**FR-08 Sub-intermediate**

- AC1: Generates an RSA 4,096-bit key in software.
- AC2: YubiKey signs the certificate (PIN + touch): validity default 5 years, pathLen=0, same keyUsage, SKI and AKI present.

**FR-09 PEM export**

- AC1: Writes `<name>.crt` (certificate), `<name>.key` (encrypted PKCS#8, own passphrase) and `<name>-chain.pem` (sub-intermediate, main intermediate, master in that order).
- AC2: `openssl verify -CAfile master.crt -untrusted main.crt sub.crt` returns OK.
- AC3: E2E test: a generated sub-intermediate key, still encrypted, is imported with its passphrase and chain into a StarnetAuth test instance through POST /api/v1/pki/ca/import. A wrong passphrase must be refused with nothing stored. The CA must report ready and issue one ACME certificate that openssl verify accepts against the 8,192-bit master. This also proves Go's crypto/x509 accepts the 8,192-bit root, which is at the top of the RSA size Go's TLS code allows.

**FR-10 Certificate rules**

- AC1: A child's notAfter can never be later than its issuer's notAfter; the GUI blocks it.
- AC2: Serial numbers are 159 random bits and positive. They are unique across every history the tool has seen: the issuance records and journals on all connected drives, including abandoned operations and divergent histories. Before signing, the tool checks the planned serial against all of them.
- AC3: Key size, signature algorithm, key usage, basicConstraints and path lengths are fixed in version 1 and cannot be changed in the GUI. The operator can edit only: name fields; validity within bounds (master 1 to 25 years, main intermediate 1 to 15, sub-intermediate 1 to 10, never past the issuer, AC1); permitted names (FR-21); and CRL addresses (FR-18).
- AC4: Every generated certificate passes an RFC 5280 linting test (for example `zlint` or `pkilint`) in CI.

**FR-11 Issuance record**

- AC1: Every signed certificate is recorded: serial, subject, issuer, validity, SHA-256 fingerprint, status, revocation date and reason.
- AC2: The GUI lists the record and can filter by issuer and status.

**FR-12 Write and verify to multiple USB drives**

- AC1: Every change is written to the primary and at least one backup USB drive.
- AC2: After writing, each copy is read back and compared by SHA-256; any mismatch is an error and the action is not reported as successful.
- AC3: On start, the tool compares the drives. If one drive's audit log is an exact prefix of another's (the same entries and hashes, only fewer), the tool shows the missing operations and, after the operator confirms them, copies each one whole to the behind drive: its audit entries and every output file its completed entry lists, each verified against that entry's SHA-256 values. The completed entry is written to the behind drive last, only after all of that operation's files verify, so copying a log entry can never make an incomplete drive look repaired. If the logs diverge (different entries after a common point), the tool blocks every signing action and shows both histories side by side. It never chooses a history by length or automatically.
- AC4: Writes are atomic (write to a temporary file, flush, rename).

**FR-13 Revocation and CRLs**

- AC1: The master signs a CRL covering main intermediates; the YubiKey signs a CRL covering sub-intermediates.
- AC2: CRLs are X.509 v2 with CRL number and AKI extensions; default nextUpdate 1 year (master) and 90 days (main intermediate).
- AC3: The GUI warns 30 days before a CRL's nextUpdate, and the warning opens the guided Refresh CRL action (AC4).
- AC4: Refresh CRL re-signs an issuer's current CRL with a new thisUpdate, a new nextUpdate and a higher CRL number, without any new revocation, and writes it to the export USB for StarnetAuth to host.
- AC5: Revocation must be shown to work, not only to exist. Tests use openssl verify -crl\_check\_all with the CRLs downloaded from a StarnetAuth test instance (-crl\_download), in two independent scenarios, each on its own fresh hierarchy. Scenario A revokes only the sub-intermediate; scenario B revokes only the main intermediate. In each, the leaf verifies before revocation, and afterwards the failure must be "certificate revoked" at the depth of the certificate that scenario revoked (depth 1 for the sub-intermediate, depth 2 for the main intermediate). Any other failure fails the test. A plain openssl verify (no CRL check) or Go's Certificate.Verify does not count, because neither checks revocation.
- AC6: Every issuer gets its first, empty CRL as part of the operation that creates it: the master in Flow A, the main intermediate in Flow B (YubiKey PIN + touch). The CRL is written to the export USB, and the GUI says to upload it to StarnetAuth before that issuer's first child is deployed. An issuer cannot sign its first child until its empty CRL exists, so a fresh hierarchy never fails a CRL check for lack of a CRL.

**FR-14 Tamper-evident audit log**

- AC1: Every operation appends an entry: timestamp, action, subject, serial, fingerprint, result.
- AC2: Each entry contains the SHA-256 of the previous entry.
- AC3: The chain is verified on every start; a broken chain shows a blocking warning naming the first bad entry.

**FR-15 Replace lost YubiKey**

- AC1: The guided flow (Flow E) works with the old YubiKey physically absent. The master revokes the old main intermediate; a new main intermediate is created on the new YubiKey; every sub-intermediate under the old one is marked "revoked by ancestor" in the issuance record, so no CRL from the lost YubiKey is needed; each one is then re-issued under the new main intermediate. An E2E test runs the whole flow with the simulator token removed.

**FR-16 Progress and cancel**

- AC1: Key generation and signing run off the GUI thread; the window stays responsive.
- AC2: A cancel button stops the operation only before its first persistent change and leaves no output behind. A persistent change is any signature, any YubiKey credential change (PIN, PUK, management key), any key generated on the YubiKey, or any output file moved from staging into place. Writing the pending journal entry and staged files does not count, because both are reversible, so Cancel stays available during long software key generation. Cancelling deletes the staged files, marks the journal entry cancelled, and keeps its reserved serial. After the first persistent change, the operation can no longer be cancelled; it finishes or resumes through FR-22.

**FR-17 Clock confirmation**

- AC1: Before any signing, the tool shows the system date and time and requires the operator to confirm or correct it.
- AC2: Sanity checks run before the operator confirms. If the time is earlier than the newest audit log entry (or the latest clock-correction baseline, AC3), or earlier than the binary's build date, signing is blocked until the clock is corrected. If it is more than 5 years after the build date, a warning needs an explicit confirmation.
- AC3: Clock correction. If an entry was recorded with a wrong future date, the operator can run Correct clock baseline: confirm the correct current time (still no earlier than the build date), and the tool appends an audited clock-correction entry that records the previous newest timestamp and the confirmed time. Existing entries are never changed. From then on, AC2 compares against the newest timestamp among the correction entry and every audit entry written after it; the erroneous timestamps before the correction are ignored. The baseline therefore keeps advancing with each later legitimate operation, so the clock can never be moved back past it. The tool lists any certificate signed with a future date so the operator can revoke and re-issue it. A test records a future-dated entry, runs the correction, and confirms signing resumes.

**FR-18 CRL location field**

- AC1: A CRL Distribution Point URL is set per issuer: the master's CRL address goes into main intermediates, and the main intermediate's CRL address goes into sub-intermediates. The GUI asks for each address once, before that issuer's first child is signed, and expects the address where StarnetAuth will host that CRL. Leaving it empty needs an explicit choice and shows a warning that revocation of those certificates could then not be checked.
- AC2: The tool only writes the text into certificates and never contacts the URL.

**FR-19 Open existing CA**

- AC1: The tool loads CA state from the USB drives, verifies drive consistency (FR-12 AC3) and the audit log (FR-14 AC3).

**FR-20 Fingerprints**

- AC1: After creating any certificate, the GUI shows its SHA-256 fingerprint in a copy-friendly format for the operator to record.

**FR-21 Name constraints on sub-intermediates**

- AC1: When creating a sub-intermediate, name constraints are on by default. The operator enters one or more permitted DNS names (for example `starnet`, which covers `starnet` and every name under it). Turning them off needs an explicit choice and shows a warning that the sub-intermediate could then issue for any name.
- AC2: The extension is written as critical, with the permitted DNS subtrees entered.
- AC3: IP addresses are excluded entirely (0.0.0.0/0 and ::/0 in excludedSubtrees) unless the operator enters permitted IP ranges. Email and URI names are excluded the same way.
- AC4: Entries are validated before signing: each DNS name must be a valid name without wildcards or a trailing dot, and each IP range a valid CIDR. Invalid entries block the action with a clear reason.
- AC5: Test: a leaf certificate for a permitted name verifies with `openssl verify` and Go's crypto/x509; a leaf for any other DNS name, or for an IP address not permitted, fails both.
- AC6: The permitted names are shown in the review step, the issuance record and the audit log entry.

**FR-22 Operation journal and recovery**

- AC1: Every operation that changes CA state (key generation, signing, revocation, CRL refresh, YubiKey setup) gets an operation number and a "pending" journal entry on every CA drive before its first irreversible step. The entry records the planned serial number, so a serial is never reused.
- AC2: Outputs are written to a staging folder on each drive, verified (FR-12 AC2), then moved into place. A "completed" entry is written last and lists the SHA-256 of every output file of that operation (certificates, encrypted keys, CRLs, record updates). Export requires the completed entry and the complete, hash-verified output set on at least two drives.
- AC3: Any certificate that was signed is recorded in the issuance record, even when a later step fails. A signed certificate is never silently dropped.
- AC4: On start, a pending operation with no completed entry opens a recovery screen. It lists exactly what exists on each drive and on the YubiKey, and offers only safe actions: finish the writes from a drive that holds the verified output, or mark the operation abandoned when no signed output exists anywhere. An abandoned serial stays reserved.
- AC5: A YubiKey slot holding a key with no matching certificate (key generation succeeded, signing did not) is detected. Recovery offers only to complete setup with the existing key: verify its attestation (FR-07 AC5), then have the master sign it. If the attestation fails, recovery says setup cannot be completed with this key. Replacing the key is never a recovery action; it requires the separate, explicitly confirmed wipe flow (FR-07 AC4).
- AC6: Fault-injection tests interrupt each operation at every step (before signing, after signing, between drive writes, after the token step) and check that recovery after restart reaches a consistent state with no lost record.
- AC7: YubiKey setup is journaled step by step: PIN changed, PUK changed, management key set, key generated, certificate written. After an interruption, the tool reads the YubiKey's actual state and resumes from the first incomplete step. It asks the operator for a new PIN or PUK that was already set, and never stores them. Fault-injection tests interrupt between every pair of these steps and check that setup resumes to a correctly hardened YubiKey.
- AC8: The recovery screen is designed as carefully as the main flows. It shows one column per drive and one for the YubiKey, with exactly what each holds for the interrupted operation. It offers at most two actions, each with one plain sentence saying what it will do and what it will not do. It never offers to format, delete or overwrite anything. It is covered by E2E tests and by the usability walkthrough (NFR-10).

## 8. Non-functional requirements

| ID | Requirement | How it is verified |
| --- | --- | --- |
| NFR-01 | Runs on Ubuntu 26.04.1 desktop (x86-64) using the distribution's GTK4, libadwaita and OpenSSL 3 packages | E2E suite runs on a clean Ubuntu 26.04.1 image |
| NFR-02 | Availability: not applicable; the tool only runs when the operator opens it | n/a |
| NFR-03 | RSA 8,192-bit generation may take minutes; GUI shows progress, stays responsive (no frame longer than 100 ms blocked) and can cancel | E2E test with simulated slow keygen |
| NFR-04 | Every screen is fully usable by keyboard; no information is conveyed by colour alone | Accessibility tree checks in E2E tests |
| NFR-05 | English only | n/a |
| NFR-06 | TDD: each acceptance criterion has a test, at the level that best demonstrates it, committed before or with its code | CI requires the test to exist and pass |
| NFR-07 | Line coverage at least 90% on the core (non-GUI) crate; E2E tests cover every user flow, every boundary, and the failure cases in FR-10, FR-15 and FR-22 | Coverage report in CI |
| NFR-08 | E2E in CI uses a software YubiKey simulator behind the same trait as the real driver | CI pipeline |
| NFR-09 | A hardware E2E suite runs against a real YubiKey 5 (firmware 5.7+) before every release, with the operator touching the key when prompted | Release checklist records the run |
| NFR-10 | Every safe step is guided in order by the GUI; the operator never needs the command line or outside documentation for Flows A to E, passphrase confirmation, or the recovery screen | Usability walkthrough before release |

## 9. Security requirements

Each requirement mitigates one or more threats in Appendix A (column "Mitigates"). Each one also needs an automated test or a release-checklist item.

| ID | Requirement | Mitigates |
| --- | --- | --- |
| SEC-01 | Dependencies are minimal, pinned in `Cargo.lock`, vendored for production builds, and checked in CI with `cargo audit`, `cargo deny` (licences, advisories, banned crates) and `cargo vet` | T-01 |
| SEC-02 | Production builds are reproducible: two independent builds (CI and a separate machine) must produce the same SHA-256 before the binary is copied to the laptop by USB. This proves the binary matches the reviewed source; it does not prove the source is free of flaws (SEC-01 and SEC-18 cover that) | T-01, T-02 |
| SEC-03 | No networking: `cargo deny` bans networking crates (for example `reqwest`, `hyper`, `tokio` net features); FR-01 refuses to run with an active interface; the production build installs a seccomp filter at startup that refuses socket() for every address family except AF\_UNIX, which PC/SC (pcscd), Wayland and D-Bus need for local communication; an E2E run under strace confirms no AF\_INET, AF\_INET6 or AF\_PACKET socket is opened and the GUI and YubiKey still work with the filter on. The filter is installed as the first action in main, before GTK, OpenSSL or PC/SC initialisation; a test confirms it is active before the first GTK call, and the hardware E2E suite confirms PC/SC works under it | T-03 |
| SEC-04 | Private keys at rest are only stored as encrypted PKCS#8 (PBES2 with AES-256; scrypt for the master, PBKDF2-HMAC-SHA256 for sub-intermediates); a CI test scans all output for unencrypted private key markers and fails if any is found | T-04, T-15 |
| SEC-05 | Passphrases are only tool-generated: 10 to 20 words (master) and 10 words (sub-intermediates) from the 7,776-word list, giving about 129 to 258 bits | T-04, T-05 |
| SEC-06 | YubiKey hardening per FR-06: no default codes, PIN and touch for every signature, PIN retry limit left at the device default | T-06 |
| SEC-07 | Secrets are held in zeroizing, memory-locked buffers and wiped after use; the process disables core dumps; passphrases never touch the clipboard, logs or disk | T-07, T-17 |
| SEC-08 | All file input (PEM, record, log) is parsed with strict size limits and no execution; named fuzz targets run in CI: the PEM and encrypted PKCS#8 parser (including decryption), the certificate and CRL parser, the audit-log and journal parser, and the issuance-record parser | T-08 |
| SEC-09 | Audit log is hash-chained and verified at every start (FR-14); USB copies are compared at every start (FR-12 AC3) | T-09, T-10 |
| SEC-10 | Every certificate's SHA-256 fingerprint is shown to the operator and recorded in the issuance record | T-10 |
| SEC-11 | All CA state is written to 2+ USB drives and verified by read-back hash (FR-12) | T-11 |
| SEC-12 | Guided YubiKey replacement and master-signed CRL (FR-15, FR-13) | T-12 |
| SEC-13 | Every generated certificate and CRL is linted for RFC 5280 and validated with `openssl verify` in CI; property tests cover the certificate rules in FR-10 | T-13, T-18 |
| SEC-14 | Sub-intermediates carry pathLen=0 and default 5-year validity and can be revoked by CRL | T-14 |
| SEC-15 | Sub-intermediate keys are exported only encrypted, each with its own generated passphrase | T-15 |
| SEC-16 | Operator confirms the system date and time before every signing (FR-17) | T-16 |
| SEC-17 | A passphrase is shown once, on a dedicated screen with a hide control, and is never shown again after confirmation | T-17 |
| SEC-18 | AI-generated code gates: `#![forbid(unsafe_code)]` outside one small, reviewed FFI module; `clippy -D warnings`; all crypto calls go through one audited module; the operator reviews that module before each release | T-18 |
| SEC-19 | Release authenticity is checked outside the binary: before install, the operator checks the binary with the operating system's sha256sum against the value written on paper from the two matching builds (SEC-02). On start, the binary also compares its own SHA-256 with the value recorded at install; this only detects corruption or an accidental change, because a deliberately modified binary could skip its own check | T-02, T-19 |
| SEC-20 | The tool refuses to create a new CA on a drive that already holds one, and never overwrites an existing key file | T-20 |
| SEC-21 | Sub-intermediates carry critical name constraints by default (FR-21), so a stolen sub-intermediate key can only issue certificates for the permitted names; tests prove certificates outside them fail verification | T-14 |
| SEC-22 | Operation journal with pending and completed states, recovery on start, and signing blocked while drive histories diverge (FR-12 AC3, FR-22); fault-injection tests at every step of every operation | T-21 |
| SEC-23 | The main intermediate key's origin is proven by a PIV attestation verified offline against Yubico's roots, and a slot that already holds a key is never overwritten without an explicit, typed wipe (FR-07 AC4, AC5) | T-22 |

## 10. Architecture overview

Keystone is a Rust Cargo workspace with a thin GTK4 GUI over a core library that holds every rule, so all CA logic can be tested without a screen.

&#91;embedded content: Keystone architecture · GUI, core crate, 3 adapters, 3 external parts\]

The core crate talks to the outside only through three adapters. The `TokenSigner` trait has two implementations (the real PIV driver and the CI simulator), which is what lets the full E2E suite run without a YubiKey.

| Part | Choice |
| --- | --- |
| Language | Rust (stable), Cargo workspace: `keystone-core`, `keystone-gui`, `keystone-testkit` |
| GUI | GTK4 + libadwaita via `gtk4-rs` and `libadwaita-rs` |
| Cryptography | OpenSSL 3 from Ubuntu via the `openssl` crate, wrapped in one crypto module |
| YubiKey | Native PIV over PC/SC (for example the `yubikey` crate on `pcsc`), no PKCS#11 |
| Build features | `production` (network guard, binary self-check) and default test build |
| Hosting | None. Production runs only on the air-gapped laptop; development and CI run anywhere |
| Tests | Unit tests per acceptance criterion (TDD); E2E via GTK accessibility automation on a clean Ubuntu 26.04.1 image; hardware E2E on a real YubiKey before release |

## 11. Data

All CA data lives on the USB drives, copied to every drive. The laptop keeps nothing between sessions. CA records are kept for the life of the CA and are never deleted by the tool.

| Data | Where | Sensitivity | Protection | Retention |
| --- | --- | --- | --- | --- |
| Master private key | USB drives | Critical | Encrypted PKCS#8, 10–20 word passphrase | Life of the CA |
| Main intermediate private key | YubiKey only | Critical | Non-exportable, PIN + touch | Until the YubiKey is replaced |
| Sub-intermediate private keys | USB drives and export folder | High | Encrypted PKCS#8, own 10-word passphrase; inside StarnetAuth, sealed in its database | Until the certificate expires; the operator deletes export copies after installing |
| Certificates (all levels) and chain files | USB drives, export folder, YubiKey slot | Low (public) | Integrity via fingerprints and the audit log | Life of the CA |
| CRLs | USB drives, export folder | Low (public) | Signed by issuer | Latest plus history |
| Issuance record | USB drives | Medium (reveals what was issued) | Hash checks across drives | Life of the CA |
| Audit log | USB drives | Medium | Hash chain (FR-14) | Life of the CA, append only |
| Binary hash record | USB drives | Low | Compared at start (SEC-19) | Updated at each install |
| Passphrases, PIN, PUK | Operator's memory or paper only | Critical | Never stored by the tool | n/a |

## 12. Integrations

Keystone has no network integrations. Its only outside connections are physical.

| System | Connection | Data crossing | Direction |
| --- | --- | --- | --- |
| YubiKey 5 (firmware 5.7+) | USB, PIV over PC/SC (`pcscd`) | PIN, management key, data to sign, signatures, certificate | Both ways |
| CA USB drives (2+) | USB mass storage | All CA state | Both ways |
| Export USB drive | USB mass storage, carried by hand | Sub-intermediate `.crt`, encrypted `.key`, chain `.pem`, CRLs | Out of the laptop |
| StarnetAuth and other issuing systems | Not connected; the operator installs exported files by hand | Sub-intermediate files and passphrase; signed CRLs for StarnetAuth to host | Out (manual) |
| Build machines and CI | Not connected; the release binary arrives by USB | The Keystone binary | In (manual) |

StarnetAuth compatibility is verified by importing a generated sub-intermediate into a StarnetAuth test instance on a networked machine, never on the laptop (see Open question 1). Dependency: StarnetAuth must first gain encrypted-key import (an encrypted PKCS#8 key plus passphrase in POST /api/v1/pki/ca/import and the GUI form). Until it ships, FR-09 AC3 cannot pass. Second dependency: StarnetAuth must host the CRLs Keystone signs (OQ-2). Until that ships, revocation by CRL reaches no relying party.

## 13. Success metrics

Version 1 is done when all five are true:

1. Every certificate passes `openssl verify` against the full chain, and a sub-intermediate is accepted by StarnetAuth.
2. Every FR acceptance criterion has a passing test written first (TDD), and the E2E suite covers every user flow, every boundary and every failure case.
3. Two independent production builds produce identical SHA-256 checksums.
4. The production build contains no networking code paths and refuses to start with an active network interface (tested).
5. A first-time run of Flows A, B and C is completed using only the GUI's guided steps, with no outside documentation.

## 14. Build plan and milestones

There is no deadline. The code will be AI-generated, so the plan is ordered by dependency, not by date. A milestone starts only when every test in the previous milestone passes in CI. Within each milestone the order is always: write the failing test, write the code, make the test pass, refactor.

1. **M0 Integration spike (disposable).** Before any production code, prove the assumptions most likely to force design changes, using throwaway code and a real YubiKey: an 8,192-bit master; a 4,096-bit main intermediate generated on and signing from the YubiKey; a name-constrained sub-intermediate; import into a StarnetAuth test instance; a leaf issued by StarnetAuth that verifies inside its permitted names and fails outside them; and that leaf rejected by openssl verify -crl\_check\_all after revocation. It also verifies the full PIV attestation chain (slot certificate, F9 signing certificate, Yubico intermediates for firmware 5.7.4+, root), checks that the attested key matches the certified key, and measures RSA 8,192 key generation and signing time on the actual laptop. Findings update this PRD, and the spike code is deleted. Encrypted-key import is recorded as unproven until the real encrypted-key path passes against StarnetAuth; it is added to the spike once StarnetAuth ships it. Scope is fixed from here: M0 resolves compatibility questions, it does not add features.
2. **M1 Project skeleton and guard rails.** Cargo workspace (core library crate, GUI crate, test-support crate), `production` feature flag, CI with `clippy`, `cargo audit`, `cargo deny`, `cargo vet`, coverage, and the plaintext-key scanner. Covers SEC-01, SEC-03 (ban list), SEC-04 (scanner), SEC-18.
3. **M2 Core crypto, no GUI.** Passphrase generator, RSA keygen, certificate builder with the profile rules, encrypted PKCS#8, chain verification with OpenSSL. Covers FR-02, FR-03, FR-04, FR-10, FR-21, SEC-05, SEC-07, SEC-13.
4. **M3 Storage.** Multi-drive write and verify, issuance record, hash-chained audit log, drive comparison, overwrite protection. Operation journal and recovery. Covers FR-11, FR-12, FR-14, FR-19, FR-22, SEC-08, SEC-09, SEC-11, SEC-20, SEC-22.
5. **M4 YubiKey.** A `TokenSigner` trait with two implementations: the native PIV driver and the software simulator used in CI. Detection, firmware check, hardening, on-device keygen, signing. Covers FR-05, FR-06, FR-07, FR-08, SEC-06.
6. **M5 Revocation.** CRL building for both issuers, Refresh CRL, expiry warnings, replace-lost-YubiKey logic with the old token absent, and the CRL-rejection test. Covers FR-13, FR-15, SEC-12, SEC-14.
7. **M6 GUI.** GTK4 + libadwaita screens for Flows A to E, progress and cancel, clock confirmation, fingerprints, passphrase screens, keyboard navigation. Covers FR-09, FR-16, FR-21 (GUI entry), FR-17, FR-18, FR-20, NFR-03, NFR-04, NFR-10, SEC-16, SEC-17.
8. **M7 Production hardening.** Network refusal, seccomp socket filter, install-time hash check and binary self-check, reproducible build pipeline. Covers FR-01, SEC-02, SEC-03, SEC-19.
9. **M8 Release.** Full E2E suite on clean Ubuntu 26.04.1, hardware E2E on a real YubiKey, StarnetAuth import test, operator review of the crypto module, usability walkthrough. Covers NFR-09 and success metrics 1 to 5. M8 cannot be declared done until both StarnetAuth dependencies (encrypted-key import, CRL hosting) have shipped and their tests pass. Until then those tests are reported as blocked, never as skipped or passing.

## 15. Assumptions

Change any of these by number.

1. Project name is Keystone. *(user said)*
2. No deadline; the code is AI-generated. *(user said)*
3. No known concerns beyond those in the threat model. *(default)*
4. Availability is not applicable. *(default)*
5. Progress indicator and cancel for long operations. *(default)*
6. Full keyboard navigation; nothing shown by colour alone. *(default)*
7. English only. *(default)*
8. The YubiKey management key is random and stored on the YubiKey, protected by the PIN. *(default)*
9. Key files are encrypted PKCS#8 PEM with AES-256: scrypt for the master, PBKDF2-HMAC-SHA256 for sub-intermediates (most widely readable). *(default)*
10. Passphrase words come from the embedded EFF large wordlist, chosen with the OS secure random source. *(default)*
11. Sub-intermediate passphrases are 10 words. *(default)*
12. Serial numbers are 159 random bits. *(default)*
13. CRL lifetime is 1 year (master) and 90 days (main intermediate), with a 30-day warning. *(default)*
14. CRL Distribution Point URLs point to the addresses where StarnetAuth hosts Keystone's CRLs; the exact paths are decided in the StarnetAuth hosting project. *(default)*
15. Secrets are wiped from memory after use and never written unencrypted. *(default)*
16. The operator confirms date and time before every signing. *(default)*
17. The tool does not encrypt whole USB drives; drive encryption is optional and outside the tool. *(default)*
18. No compliance or legal requirements. *(default)*
19. Path length limits: none (master), 1 (main intermediate), 0 (sub-intermediate). *(user accepted)*
20. The air-gapped laptop runs a minimal Ubuntu 26.04.1 install with full-disk encryption, Secure Boot, swap disabled or encrypted, and USB auto-mount set to `noexec`. *(default, threat model)*
21. Sub-intermediate keys use RSA 4,096 bits. *(default, from "intermediate certs of 4096 bits")*
22. Name constraints apply to sub-intermediates only, are on by default, are critical, and exclude IP, email and URI names unless ranges are entered. The master and main intermediate carry none, so new sub-intermediates can cover new domains later. *(user confirmed, 2026-11-01)*
23. Certificate structure is fixed in version 1; editable validity is bounded to master 1 to 25 years, main intermediate 1 to 15, sub-intermediate 1 to 10. *(user chose fixed structure 2026-11-01; bounds default)*
24. Testing rule: every acceptance criterion is test-first at the level that best demonstrates it; E2E covers every flow, boundary and failure case, not every criterion separately. *(user chose 2026-11-01)*
25. RSA 8,192 for the master is an owner requirement, not a compatibility need: StarnetAuth also accepts ECDSA and Ed25519 CA keys (its own generated CA uses ECDSA P-384). RSA 8,192 is slower and makes larger signatures, and it sits at the top of the RSA size Go's TLS code accepts; M0 measures the cost. *(user said 2026-11-01)*

## 16. Open questions

- [x] **OQ-1** Resolved 2026-11-01 from the StarnetAuth code. Its import (POST /api/v1/pki/ca/import, x509ca.parseKey) refuses encrypted keys and accepts an unencrypted PKCS#8 or PKCS#1 key, RSA at least 2,048 bits. The chain may be in any order but must include the self-signed root, and every certificate must be currently valid. After import, StarnetAuth stores the key sealed in its database (AES-256-GCM envelope, D-060). Decision (owner, 2026-11-01): StarnetAuth will be updated to accept an encrypted PKCS#8 key plus its passphrase in the import form and API, so the key is never decrypted outside StarnetAuth. Keystone exports sub-intermediate keys with PBES2, PBKDF2-HMAC-SHA256 and AES-256-CBC, which StarnetAuth can decrypt with Go's standard library alone (crypto/pbkdf2, crypto/aes, encoding/asn1), with no new dependency. This StarnetAuth change is a dependency of FR-09 AC3 and is tracked in StarnetAuth's own PRD and repository.
- [x] **OQ-2** Resolved 2026-11-01 (owner decision). Keystone signs each CRL offline (FR-13) and writes it to the export USB. StarnetAuth will host those CRLs at fixed addresses, so relying parties can fetch them. Hosting is a separate StarnetAuth project, because today StarnetAuth serves only its own leaf CRL (/pki/crl, D-052). The CRL addresses are written into the certificates Keystone signs (FR-18), so they must be fixed before the main intermediate and the first sub-intermediate are created.

## Appendix A: Threat model (STRIDE)

**A.1 Scope.** Keystone version 1: the production binary on the air-gapped laptop, the CA USB drives, the YubiKey, the export USB drive, and the build pipeline that produces the binary. StarnetAuth and other issuing systems are out of scope except where they hold a sub-intermediate.

**A.2 Data-flow diagram**

&#91;embedded content: Data-flow diagram · 4 trust boundaries, 6 crossings\]

The laptop is the only zone that ever holds the master key unlocked. Every crossing into or out of it is a physical one, and each is tied to the threats in A.6.

**A.3 Assets**

| Asset | Why it matters | Sensitivity |
| --- | --- | --- |
| Master private key | Can sign anything every relying party trusts | Critical |
| Main intermediate key (YubiKey) | Can sign new sub-intermediates | Critical |
| Master passphrase | Unlocks the master key file | Critical |
| Sub-intermediate keys | Can issue certificates for its issuing system | High |
| Production binary | Handles every secret; a tampered binary leaks them | High |
| Audit log and issuance record | Detect unintended signing; needed for correct CRLs | Medium |
| CRLs | Stop trust in revoked CAs | Medium |

**A.4 Threat actors**

| Actor | Motivation | Capability |
| --- | --- | --- |
| Malicious dependency (supply chain) | Steal keys or plant a backdoor | High |
| Physical-access attacker (thief, visitor, household member) | Steal or use the laptop, a USB drive or the YubiKey | Medium |
| Infected USB media from networked machines | Get malware onto the laptop or exfiltrate data | Medium |
| Operator mistakes (not malicious) | n/a: loss, mix-ups, wrong exports | High likelihood, varied impact |
| AI code generator (not malicious) | n/a: subtle bugs in crypto or file handling | Medium |

**A.5 Trust boundaries and entry points**

1. **Build to laptop:** the release binary carried in by USB (T-01, T-02).
2. **USB drives to process:** CA files read at start and on every action (T-08, T-09).
3. **YubiKey to process:** PIV responses over PC/SC (T-06).
4. **Process to export USB:** sub-intermediate files leaving the laptop (T-15).
5. **Operator to GUI:** passphrases, PIN, date confirmation (T-05, T-16, T-17).
6. **Network:** must not exist (T-03).

**A.6 Threats** (Likelihood and Impact 1 to 3; Risk = L × I)

| ID | STRIDE | Component / boundary | Threat | L | I | Risk | Mitigation | Requirement |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-01 | Elevation of privilege | Build pipeline | A compromised crate or C library adds code that leaks or weakens keys | 2 | 3 | 6 | Minimal, pinned, vendored, audited dependencies; reproducible build | SEC-01, SEC-02 |
| T-02 | Tampering | Build to laptop | Binary altered on the build machine or the USB drive | 1 | 3 | 3 | Two-build checksum match, checked on the laptop with the OS's sha256sum before install | SEC-02, SEC-19 |
| T-03 | Information disclosure | Process to network | Key material sent over a network connection | 1 | 3 | 3 | No networking code; refuse to run with an interface up; seccomp filter allowing only local (AF\_UNIX) sockets | SEC-03 |
| T-04 | Information disclosure | CA USB drives | Stolen drive; master key file brute-forced offline | 2 | 3 | 6 | Encrypted PKCS#8 with scrypt; 129–258-bit generated passphrase | SEC-04, SEC-05 |
| T-05 | Spoofing | Operator to GUI | Weak or guessable passphrase lets someone unlock the master | 2 | 3 | 6 | Only tool-generated passphrases | SEC-05 |
| T-06 | Spoofing | YubiKey | Stolen YubiKey used to sign rogue sub-intermediates | 1 | 3 | 3 | Non-default PIN, PIN retry limit, touch required | SEC-06 |
| T-07 | Information disclosure | Process memory | Keys or passphrases left in RAM, swap or a core dump | 1 | 3 | 3 | Zeroizing locked buffers, no core dumps, swap off (Assumption 20) | SEC-07 |
| T-08 | Tampering | USB drives to process | Malformed or malicious file exploits a parser bug | 2 | 2 | 4 | Strict parsing with size limits; fuzz tests; `noexec` mounts | SEC-08 |
| T-09 | Tampering | Audit log, issuance record | Records edited to hide a signing | 1 | 2 | 2 | Hash chain verified at start; cross-drive comparison | SEC-09 |
| T-10 | Repudiation | Signing actions | A certificate is signed and nobody can say when or why | 1 | 2 | 2 | Audit log entry and fingerprint for every signing | SEC-09, SEC-10 |
| T-11 | Denial of service | CA USB drives | Drive failure or loss destroys the master key and records | 2 | 3 | 6 | Write to 2+ drives, read-back verify | SEC-11 |
| T-12 | Denial of service | YubiKey | YubiKey lost or broken; no more sub-intermediates | 2 | 2 | 4 | Guided replacement; master-signed CRL | SEC-12 |
| T-13 | Tampering | Certificate builder | Wrong extensions or constraints, e.g. a sub-intermediate able to create more CAs | 2 | 2 | 4 | RFC 5280 lint, `openssl verify`, property tests | SEC-13 |
| T-14 | Elevation of privilege | Issuing system (StarnetAuth) | Sub-intermediate key stolen from the issuing system | 2 | 3 | 6 | pathLen=0, 5-year validity, revocation by CRL, name constraints limit what a stolen key can issue | SEC-14, SEC-21 |
| T-15 | Information disclosure | Process to export USB | Sub-intermediate key exported or carried unencrypted | 2 | 3 | 6 | Encrypted export with own passphrase; plaintext-key scanner; StarnetAuth imports the encrypted key with its passphrase, so no plain copy exists outside it | SEC-04, SEC-15 |
| T-16 | Tampering | Laptop clock | Wrong date gives certificates wrong validity periods | 2 | 1 | 2 | Operator confirms date and time before signing; automatic check against the newest audit entry and the build date | SEC-16 |
| T-17 | Information disclosure | GUI display | Passphrase seen by someone nearby or left on screen | 1 | 3 | 3 | Shown once with hide control; never on clipboard | SEC-07, SEC-17 |
| T-18 | Tampering | Source code | AI-generated code misuses crypto (bad RNG, plaintext temp file) | 2 | 3 | 6 | Single audited crypto module, no unsafe, lint and property tests, operator review | SEC-13, SEC-18 |
| T-19 | Elevation of privilege | Laptop OS | Physical attacker installs malware on the laptop (evil maid) | 1 | 3 | 3 | Install-time hash check with the OS's sha256sum; full-disk encryption and Secure Boot (Assumption 20). The binary's self-check only catches corruption | SEC-19 |
| T-20 | Denial of service | CA USB drives | Operator accidentally creates a new CA over an existing one | 1 | 3 | 3 | Refuse to overwrite an existing CA or key | SEC-20 |
| T-21 | Repudiation | CA USB drives, YubiKey | A crash, pulled drive or removed YubiKey mid-operation leaves a signed certificate unrecorded, or leaves the drives disagreeing about what happened | 2 | 2 | 4 | Operation journal, recovery screen, block on divergent histories | SEC-22 |
| T-22 | Spoofing | YubiKey | A counterfeit or previously used YubiKey, or a slot with a key already loaded, holds the main intermediate key | 1 | 3 | 3 | PIV attestation verified against Yubico roots; refuse an occupied slot | SEC-23 |

**A.7 Risk summary** (highest first)

- **Risk 6:** T-01 malicious dependency, T-04 stolen USB drive, T-05 weak passphrase, T-11 drive loss, T-14 stolen sub-intermediate, T-15 unencrypted export, T-18 AI code errors.
- **Risk 4:** T-08 malicious file, T-12 lost YubiKey, T-13 wrong certificate constraints, T-21 interrupted operation.
- **Risk 3:** T-02, T-03, T-06, T-07, T-17, T-19, T-20, T-22.
- **Risk 2:** T-09, T-10, T-16.

**A.8 Residual risks**

- **T-01, T-18:** A well-hidden backdoor or bug in OpenSSL, GTK or generated code may pass every test. Reduced by audits and review, not removed. Fits a very-low tolerance only with the operator review in M8.
- **T-09:** Someone holding every USB drive can rewrite the whole log consistently, because entries are hashed, not signed. Accepted: such an attacker already holds the encrypted master key.
- **T-14:** Revocation only helps if relying parties fetch and check the CRL; Go's crypto/x509 and many TLS clients do not check CRLs by default. StarnetAuth will host Keystone's CRLs (OQ-2); until that ships, and for verifiers that do not check CRLs, a stolen sub-intermediate stays trusted up to its expiry, but name constraints (SEC-21) limit it to the permitted names. A relying party that ignores name constraints would not get that limit; current OpenSSL, Go, Windows and browser verifiers enforce them.
- **T-19:** An attacker with long, repeated physical access could patch the OS and the self-check together. Depends on laptop storage and Secure Boot (Assumption 20).

**A.9 Threat model assumptions**

1. The laptop has never been connected to a network after its Ubuntu install, and its network hardware is disabled or removed where possible.
2. Ubuntu 26.04.1, OpenSSL 3, GTK4 and `pcscd` from the distribution are trusted as installed.
3. The operator keeps passphrases, PIN and PUK on paper stored separately from the USB drives and YubiKey.
4. Backup USB drives are stored in a different physical place from the primary.

**A.10 Review triggers** — revisit this threat model when any of these happen:

- Leaf certificate issuance is added.
- A new token type, key algorithm or key size is supported.
- Any dependency is added, or a major version of OpenSSL or GTK changes.
- The way binaries reach the laptop, or the way CRLs are distributed, changes.
- StarnetAuth changes how it stores or uses intermediate keys.
