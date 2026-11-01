# Contributing to Keystone

Thank you for helping. This page explains **how** to contribute. The rules themselves are in
[GOVERNANCE.md](GOVERNANCE.md) and [TESTING.md](TESTING.md); this page only shows how to follow them.

Keystone is an offline Rust desktop app that builds a three-level X.509 certificate authority on an air-gapped laptop. Read `Keystone PRD6 - final.md` (the PRD) first: every feature, rule and test in Keystone comes from it.

Keystone has one maintainer. Replies to issues and pull requests are **best effort**: there is no promised response time.

## Before you start

- **Small fixes, tests and documentation:** open a pull request directly.
- **New features:** open an issue first, and wait until the maintainer agrees before you start work (GOV-17).
- **Changes to sensitive code, or a new dependency:** open an issue first and wait for agreement. These changes get a line-by-line review (GOV-18). Sensitive code is listed in GOVERNANCE.md section 3; it includes the crypto module, the FFI module, the YubiKey driver patch, the network guard and seccomp filter, the certificate profile, and the audit log.
- **Not accepted:** any network feature (Keystone will never have networking code), token types other than YubiKey 5, and leaf-certificate issuance in version 1 (GOV-21).
- **Security problems:** do not open a public issue. See [SECURITY.md](SECURITY.md).

## Set up and run the tests

Keystone targets **Ubuntu 26.04.1 desktop, x86-64**. The Rust toolchain version is pinned in `rust-toolchain.toml`.

The Ubuntu packages you need are listed in `Keystone Dependencies.md` (section "Ubuntu dependencies"). The test commands are in [TESTING.md](TESTING.md#how-to-run-the-tests).

The workspace does not exist yet (the project is between planning and its first milestone). This section will get exact commands when it does.

## Make your change

1. Fork the repository and create a branch from `dev`.
2. Write the failing test first, then the code (TESTING.md, TEST-01). Fixing a bug? Add a test that fails without your fix (TEST-03).
3. Use synthetic test data only. Never use or commit a real key, passphrase or PIN (TEST-11).
4. Write commit messages in [Conventional Commits](https://www.conventionalcommits.org/) style, for example `fix: reject CRL with missing AKI` (GOV-12).
5. Sign off every commit with `git commit -s`. This adds a `Signed-off-by:` line, which means you certify the [Developer Certificate of Origin](https://developercertificate.org/): that you have the right to submit this code under the Apache-2.0 license (GOV-19).
   Forgot? Run `git rebase --signoff dev` and force-push your branch.
6. If an AI tool wrote any part of your change, say so in the pull request description. You are responsible for every line (GOV-20).

## Open a pull request

- Open the pull request **into `dev`**, not `main`.
- Fill in the pull request template: what changes, which PRD IDs it covers, and the checklist.
- Every required check has to pass before a merge (TESTING.md section 5).
- The maintainer reviews and merges pull requests from forks; automated agents never merge them (GOV-08).

## Code of conduct

This project follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) (Contributor Covenant 3.0).
