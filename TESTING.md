# Testing Policy — Keystone

This document says which tests Keystone needs, when they run, and what blocks a merge or a release.
It builds on the PRD (`Keystone PRD6 - final.md`), which already requires test-first development (NFR-06), at least 90% coverage on the core (NFR-07), and the tests listed in its security requirements. Where this file and the PRD say the same thing, the PRD ID is given.

The words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as defined in RFC 2119.
Each rule says what enforces it **today**. "Setup checklist #N" refers to the numbered list at the end of [GOVERNANCE.md](GOVERNANCE.md#setup-checklist). **No CI exists yet**, so every CI-based rule is a promise until setup checklist #8 is done.

## 1. Test types

The workspace does not exist yet. The folders below are the planned layout from the PRD (crates `keystone-core`, `keystone-gui`, `keystone-testkit`); update them when the crates are created.

| Test type | What it covers | Planned location | Required? |
| --- | --- | --- | --- |
| Unit | Each acceptance criterion that is best shown at unit level | `#[cfg(test)]` modules in each crate | Yes |
| Integration | `keystone-core` working with its adapters: storage, the YubiKey simulator, OpenSSL | `keystone-core/tests/` | Yes |
| Property | The certificate rules in FR-10 (validity, serials, fixed profile), using `proptest` | `keystone-core/tests/` | Yes |
| End-to-end (E2E) | Flows A to E, every boundary (USB drives, YubiKey, StarnetAuth), and the failure cases in FR-10, FR-15 and FR-22; driven through GTK accessibility with Dogtail, using the YubiKey simulator (NFR-08); keyboard and accessibility checks (NFR-04) | `keystone-gui/tests/e2e/` | Yes |
| Interoperability | `openssl verify` and `openssl pkey` on every output; RFC 5280 lint of every generated certificate and CRL (FR-10 AC4, SEC-13); CRL rejection tests (FR-13 AC5); StarnetAuth import (FR-09 AC3) | `keystone-core/tests/interop/` | Yes (StarnetAuth tests may be BLOCKED, see TEST-10) |
| Fuzz | The four named targets from PRD SEC-08: PEM and encrypted PKCS#8 parser (including decryption); certificate and CRL parser; audit-log and journal parser; issuance-record parser | `fuzz/` | Yes |
| Fault injection | Interrupting every operation at every step, and YubiKey setup between every pair of steps (FR-22 AC6, AC7) | `keystone-core/tests/` | Yes |
| Network policy | E2E run under `strace` plus negative socket tests (PRD SEC-03) | `keystone-gui/tests/e2e/` | Yes (from milestone M7) |
| Plaintext-key scanner | Scans all test output for unencrypted private-key markers (PRD SEC-04) | CI job | Yes |
| Hardware E2E | Real YubiKey 5 (firmware 5.7+), with the operator touching the key (NFR-09) | Run by the maintainer | Before every full release |
| Usability walkthrough | First-time run of Flows A, B and C with only the GUI (NFR-10) | Run by the maintainer | Before every full release |

**TEST-01** — Every PRD acceptance criterion MUST have a test written first, at the level that best demonstrates it, and committed before or together with its code (PRD NFR-06). Every PR MUST list the PRD IDs it covers (for example `FR-04 AC2`, `SEC-08`).  
*Why:* the code is AI-generated, so the tests are the main proof that it does what the PRD says.  
*Enforced by:* PR template (exists) + maintainer review; requirement-traceability CI check — not set up yet (setup checklist #8).

**TEST-02** — Each test type in the table above MUST exist for the area it covers by the end of the PRD milestone that builds that area.  
*Why:* a milestone is only done when its proof exists.  
*Enforced by:* maintainer review at each milestone; CI jobs — not set up yet (setup checklist #8).

## 2. Tests that come with a change

**TEST-03** — Every bug fix MUST include a regression test that fails without the fix and passes with it.  
*Why:* stops the same bug from coming back.  
*Enforced by:* PR template (exists) + maintainer review.

New behaviour is covered by TEST-01. A refactor that changes no behaviour needs no new tests, but all existing tests still have to pass unchanged.

## 3. Coverage

**TEST-04** — Line coverage of the `keystone-core` crate MUST be at least 90%, measured with `cargo llvm-cov` (PRD NFR-07). A PR that brings it below 90% MUST NOT be merged.  
*Why:* the core holds every CA rule; untested lines there are untested security decisions.  
*Enforced by:* CI coverage job — not set up yet (setup checklist #8).

## 4. When tests run

Keystone supports one platform: **Ubuntu 26.04.1 desktop, x86-64** (PRD NFR-01). CI uses a clean Ubuntu 26.04.1 image.

**TEST-05** — CI MUST run on every PR into `dev` or `main` and on every push to `dev` or `main`. The long fuzz runs MUST run nightly.  
*Why:* agents merge into `dev` on CI results alone, so CI has to run on everything.  
*Enforced by:* CI workflow triggers — not set up yet (setup checklist #8).

## 5. What blocks a merge

**TEST-06** — A PR MUST NOT be merged into `dev` or `main` unless all of these checks pass:
- formatting (`cargo fmt --check`)
- linting (`cargo clippy -- -D warnings`, PRD SEC-18)
- all tests, including E2E with the YubiKey simulator
- coverage (TEST-04)
- `cargo audit`, `cargo deny`, `cargo vet` (PRD SEC-01)
- the plaintext-key scanner (PRD SEC-04)
- the RFC 5280 lint (PRD SEC-13)
- a short fuzz run per fuzz target
- CodeQL (SECP-06)
- the requirement-traceability check (TEST-01)

*Why:* these checks are the automatic part of every review.  
*Enforced by:* required status checks in the `dev` and `main` rulesets — not set up yet (setup checklist #4, #5, #8).

**TEST-07** — A test MUST NOT be deleted, skipped, weakened or marked `#[ignore]`, and a threshold (such as coverage) MUST NOT be lowered, in order to make a check pass. Agents MUST NOT do any of these at all. The maintainer MAY do so only through a policy exception (GOV-23).  
*Why:* a weakened test hides exactly the problem it was written to find.  
*Enforced by:* maintainer review; AGENTS.md; CI configuration is ask-first for agents (AGENT-02).

## 6. What blocks a release

A `-dev` release needs every CI check green on the tagged commit (GOV-15). A full release needs much more:

**TEST-08** — A full release MUST NOT be published until all of these are true on the tagged commit:
- every check in TEST-06 passes;
- the full E2E suite passes on a clean Ubuntu 26.04.1 image;
- the hardware E2E suite passes on a real YubiKey 5 (firmware 5.7+), and the run is recorded in the release checklist (PRD NFR-09);
- the usability walkthrough is done (PRD NFR-10);
- the maintainer has reviewed the crypto module (PRD SEC-18);
- no test is BLOCKED (TEST-10).

*Why:* the release binary will handle real CA secrets on the air-gapped laptop.  
*Enforced by:* maintainer full-release checklist.

## 7. Flaky tests

**TEST-09** — A flaky test (one that passes or fails at random without a code change) MUST be treated as a bug: it gets an issue, and it MUST be fixed before the next `dev` → `main` merge.  
*Why:* in a tool with fault-injection and recovery logic, "random" failures are often real timing bugs.  
*Enforced by:* maintainer review at the `dev` → `main` PR.

## 8. Test data

**TEST-10** — A test that cannot run because an outside dependency is missing (today: StarnetAuth encrypted-key import and CRL hosting, PRD section 12) MUST be reported as **BLOCKED**. It MUST NOT be skipped quietly or counted as passing. BLOCKED tests run in a separate report job that is not required for merging; a full release is not possible while any test is BLOCKED (PRD milestone M8).  
*Why:* a missing proof has to stay visible until it exists.  
*Enforced by:* "blocked tests" report job — not set up yet (setup checklist #8); TEST-08.

**TEST-11** — Test data MUST be synthetic. Test certificates MUST carry `KEYSTONE TEST` in their Common Name, and test keys MUST come only from `keystone-testkit`. Real CA material (keys, certificates, passphrases, PINs) MUST NOT be committed.  
*Why:* a test key that looks real could end up trusted somewhere.  
*Enforced by:* maintainer review; plaintext-key scanner — not set up yet (setup checklist #8); secret scanning — not set up yet (setup checklist #7).

**TEST-12** — Tests that write files MUST use temporary directories (the `tempfile` crate), never real mounted USB drives or other real folders.  
*Why:* Keystone writes CA state to drives; a test must never be able to touch a real CA drive.  
*Enforced by:* maintainer review.

## 9. Security tests

The fuzz targets, the network-policy tests, the plaintext-key scanner and the interoperability tests are listed in section 1.

**TEST-13** — Every crash or hang found by fuzzing MUST become a regression test, and its input MUST be added to the fuzz corpus.  
*Why:* the same malformed file should never crash Keystone twice.  
*Enforced by:* maintainer review.

## How to run the tests

These commands are **planned**; they will work once the workspace exists (PRD milestone M1). Update this section with the real commands then.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo llvm-cov --package keystone-core --fail-under-lines 90
cargo audit
cargo deny check
cargo vet
cargo +<pinned-fuzz-toolchain> fuzz run <target> -- -max_total_time=<seconds>
```

---
Last reviewed: 2026-11-01
