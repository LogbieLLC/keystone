# Governance — Keystone

Keystone is an offline Rust desktop application (GTK4 + libadwaita) that builds a three-level X.509 certificate-authority hierarchy on an air-gapped laptop. Status: **planning complete, no code yet** (next step: milestone M0 in the PRD).

This document explains who makes decisions and how changes reach `dev`, `main` and releases.
Testing rules are in [TESTING.md](TESTING.md). Security rules and how to report a vulnerability are in [SECURITY.md](SECURITY.md).
AI agents follow the rule summary in [AGENTS.md](AGENTS.md). The product requirements are in `Keystone PRD6 - final.md` ("the PRD").

The words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as defined in RFC 2119.
Each rule says what enforces it **today**. Where the enforcement does not exist yet, the rule points to an item in the [Setup checklist](#setup-checklist) at the end of this file. Until that item is done, the rule is a promise, not a guarantee.

## 1. Roles

| Role | Who | What they may do |
| --- | --- | --- |
| Maintainer | Brad Byrd | Final say on every decision; merges into `main`; creates tags and releases; approves policy exceptions |
| Copyright holder | Logbie LLC | Owns the copyright of the maintainer's and agents' work (Apache-2.0) |
| AI coding agents | See section 5 | Write code and tests on branches, open PRs, merge their own PRs into `dev` under section 5 |
| Code review bots | Any | Comment and request changes on PRs |
| Outside contributors | Anyone | Open issues and PRs under section 6 |

**GOV-01** — The maintainer (Brad Byrd) MUST make the final decision on any disputed question about Keystone.  
*Why:* one person decides, so a decision is never stuck.  
*Enforced by:* GitHub repository Admin role held only by the maintainer — not set up yet (setup checklist #1).

**GOV-02** — Write access MUST be given only by the maintainer, and only to accounts with two-factor authentication (2FA) turned on. Outside contributors MAY receive the GitHub "Triage" role after repeated good contributions.  
*Why:* write access to a CA tool's source is a path to every certificate it will ever sign.  
*Enforced by:* maintainer review of the collaborator list; 2FA requirement — not set up yet (setup checklist #2).

## 2. How decisions are made

**GOV-03** — A decision that is hard to reverse SHOULD be recorded as a short ADR (Architecture Decision Record: a one-page file that states the decision and why) in `docs/adr/`, linked from the related issue.  
*Why:* later readers, human or AI, can see why the code is the way it is.  
*Enforced by:* maintainer review.

**GOV-04** — A change to a PRD hard rule (HR-1 to HR-3), the fixed certificate profile, or the threat model (PRD Appendix A) MUST come with an ADR. When a threat-model review trigger (PRD Appendix A.10) happens, the threat model MUST be updated in the same PR.  
*Why:* these are the foundations of Keystone's security; changing them silently would make the threat model wrong.  
*Enforced by:* PR template checkbox (exists) + maintainer review.

**GOV-05** — If the maintainer is unavailable for a long time, the project pauses. README.md and SECURITY.md MUST say so, and the recovery steps for the GitHub account and the release signing key MUST be kept offline, outside this repository.  
*Why:* users of a security tool need to know that nobody may answer, and access must be recoverable.  
*Enforced by:* README.md and SECURITY.md text (exists); offline recovery steps — not set up yet (setup checklist #12).

## 3. Making changes

### Branches

```
work branch ──PR (squash)──▶ dev ──PR (merge commit)──▶ main ──signed tag──▶ full release
                              │
                              └──signed tag──▶ -dev release
```

### Sensitive code

The following is **sensitive code**. Rules GOV-10, GOV-15, GOV-18 and SECP-06 refer to this list.

- the crypto module (every OpenSSL call) and the single FFI / `unsafe` module
- the local patch of the `yubikey` driver
- the network guard, the seccomp filter and all code behind the `production` Cargo feature
- the fixed certificate profile, the passphrase generator, the embedded EFF wordlist and the embedded Yubico attestation roots
- the audit-log hash chain and the operation-journal code
- CI configuration: `.github/workflows/`, `.github/dependabot.yml`, `deny.toml`, `supply-chain/` (cargo vet), `rust-toolchain.toml`
- the policy files: `GOVERNANCE.md`, `TESTING.md`, `SECURITY.md`, `AGENTS.md`, `CLAUDE.md`, and `CODEOWNERS` if it exists

The exact folder paths are added when the crates exist (open item #2).

### Rules

**GOV-06** — Work branches MUST reach `dev` only through a PR, and `dev` MUST reach `main` only through a PR. Direct pushes, force pushes and deletion of `dev` and `main` MUST NOT happen.  
*Why:* every change passes CI and leaves a reviewable record.  
*Enforced by:* GitHub rulesets on `dev` and `main` — not set up yet (setup checklist #4, #5).

**GOV-07** — A PR MUST NOT be merged into `dev` unless every required CI check passed (no check failed, was skipped or was cancelled).  
*Why:* agents may merge into `dev` without a human, so CI is the only gate at that point.  
*Enforced by:* required status checks in the `dev` ruleset — not set up yet (setup checklist #4, #8).

**GOV-08** — A PR from a fork (an outside contributor) MUST be merged into `dev` only by the maintainer.  
*Why:* code from outside is untrusted until a human has read it.  
*Enforced by:* maintainer review; AGENTS.md.

**GOV-09** — A PR into `main` MUST be merged by the maintainer after reviewing it. The only exception is AGENT-05: an agent with the maintainer's written permission for that specific PR.  
*Why:* `main` is what full releases are built from.  
*Enforced by:* `main` ruleset requiring one approving review — not set up yet (setup checklist #5; needs #3 so the maintainer is not the PR author).

**GOV-10** — The description of every `dev` → `main` PR MUST list every change to sensitive code since the last merge into `main`, and the maintainer MUST review those changes line by line before merging.  
*Why:* sensitive code may reach `dev` without human review, so this PR is where that review happens.  
*Enforced by:* PR template section (exists) + maintainer review.

**GOV-11** — Work-branch PRs MUST be squash-merged into `dev`. `dev` → `main` PRs MUST use a merge commit. Commits on `dev` and `main` MUST be signed.  
*Why:* one signed commit per change on `dev`, and the full reviewed history on `main`.  
*Enforced by:* allowed merge methods and "require signed commits" in the rulesets — not set up yet (setup checklist #4, #5).

**GOV-12** — Commit messages and PR titles SHOULD follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:` …).  
*Why:* the squash commit uses the PR title, so the history stays readable.  
*Enforced by:* PR review checklist.

## 4. Releases

**GOV-13** — Versions MUST use the format `YYYY.M.BUILD`: four-digit year, month **without** a leading zero, and BUILD starting at 1 in each new month (for example `2026.11.1`, `2026.11.2`, then `2026.12.1`). Development releases add `-dev` (for example `2026.11.2-dev`). The git tag is `v` followed by the version (`v2026.11.2-dev`).  
*Why:* Cargo requires SemVer-shaped numbers, and SemVer does not allow leading zeros, so `2026.01.3` would be rejected.  
*Enforced by:* Cargo rejects leading zeros (automatic once `Cargo.toml` exists); the rest by maintainer review.

**GOV-14** — Release tags and GitHub releases MUST be created only by the maintainer. Every release tag MUST be signed with the maintainer's own signing key, which MUST NOT be the CA's YubiKey.  
*Why:* a signed tag proves which source a release was built from.  
*Enforced by:* tag ruleset protecting `v*` — not set up yet (setup checklist #6); signing key — not set up yet (setup checklist #11).

**GOV-15** — A `-dev` release MUST be built from `dev`, published as a GitHub pre-release marked "not for use with a real CA", and have every CI check green on the tagged commit. Before tagging it, the maintainer MUST review the sensitive-code changes since the last such review. Until the PRD's version 1 acceptance (milestone M8) is complete, every release MUST be a `-dev` release.  
*Why:* `-dev` releases are public, but contain code that has not been through the full release checks.  
*Enforced by:* maintainer release checklist.

**GOV-16** — A full release MUST be built only from a signed tag on `main`, from a clean working tree, with vendored sources and `cargo build --frozen`, and the two independent builds MUST produce the same SHA-256 (PRD SEC-02). Every release blocker in TESTING.md section 6 MUST be met. A binary built any other way MUST NOT be called a release.  
*Why:* the operator must be able to prove that the binary on the air-gapped laptop matches the reviewed source.  
*Enforced by:* maintainer release checklist; reproducible-build pipeline — not set up yet (setup checklist #11; PRD milestone M7).

## 5. AI coding agents

These agents may work on Keystone: Claude Code on the maintainer's PC, Claude cloud sessions, Grok, ChatGPT, and possibly Devin. Code review bots may review PRs.
All agents follow [AGENTS.md](AGENTS.md), which is the single rule file for agents. `CLAUDE.md` only points to it.

**AGENT-01** — Agents MAY create branches, commit to them, open PRs, add tests, and upgrade existing crates, except the crates listed in AGENT-02.  
*Why:* routine work should not wait for the maintainer.  
*Enforced by:* AGENTS.md.

**AGENT-02** — Agents MUST ask the maintainer and wait for a yes before they:
- change CI configuration (see the sensitive-code list);
- add or remove a crate;
- upgrade the `yubikey` driver or its local patch, `openssl`, `openssl-sys`, or the Rust toolchain pin;
- change a policy file (see the sensitive-code list).

*Why:* these changes alter the checks, the approved dependency baseline, or the agents' own rules. An agent could otherwise loosen its own rules on `dev`.  
*Enforced by:* AGENTS.md; maintainer review at the `dev` → `main` PR (GOV-10).

**AGENT-03** — Agents MUST stop and ask the maintainer when a PRD requirement is unclear or two requirements conflict; when a change would touch a PRD hard rule, the certificate profile or the threat model; or when the work goes outside the task they were given.  
*Why:* guessing at requirements in a CA tool produces certificates that are wrong in subtle ways.  
*Enforced by:* AGENTS.md.

**AGENT-04** — An agent MAY merge its own PR into `dev` only when GOV-07 is met, and only after the required checks exist in the `dev` ruleset. Until then, the maintainer merges every PR.  
*Why:* with no required checks, "every check passed" would be true for any change.  
*Enforced by:* `dev` ruleset — not set up yet (setup checklist #4, #8).

**AGENT-05** — Agents MUST NOT: push directly to `dev` or `main`; merge into `main` unless the maintainer gave written permission for that specific PR (the agent quotes that permission in a PR comment before merging); merge a PR from a fork; create tags or publish releases; or approve a policy exception, including for themselves.  
*Why:* these are the points where a human decision protects the release.  
*Enforced by:* rulesets — not set up yet (setup checklist #4, #5, #6); AGENTS.md.

**AGENT-06** — Agents MUST NOT make a certification that only a human can make: no `Signed-off-by:` line, no `cargo vet certify` and no edits to `cargo vet` audit records, and no signed tags.  
*Why:* each of these is a personal statement by the maintainer (that the code may be submitted, or that a dependency was reviewed).  
*Enforced by:* AGENTS.md; maintainer review.

**AGENT-07** — Agent work MUST be marked: a `Co-Authored-By:` trailer naming the agent in each commit, the label `ai-generated` on the PR, and the agent named in the PR description.  
*Why:* reviewers need to know which changes were machine-written.  
*Enforced by:* PR template; `ai-generated` label — not set up yet (setup checklist #10).

**AGENT-08** — Code review bots MAY comment and request changes. A bot's approval MUST NOT be counted as the maintainer's approval.  
*Why:* the human review is the control; a bot review is extra information.  
*Enforced by:* maintainer review.

## 6. Outside contributions

Outside contributions are welcome. How to contribute is explained in [CONTRIBUTING.md](CONTRIBUTING.md). Keystone has one maintainer, so replies to issues and PRs are **best effort**: there is no promised response time.

**GOV-17** — Small fixes, tests and documentation MAY be opened directly as a PR. A new feature MUST start as an issue, and the maintainer MUST agree to it before work begins.  
*Why:* contributors do not lose work on features that will not be accepted.  
*Enforced by:* maintainer review.

**GOV-18** — An outside PR that touches sensitive code or adds a dependency MUST have an agreed issue first, and MUST receive a line-by-line review by the maintainer.  
*Why:* this code decides whether keys stay secret and certificates are correct.  
*Enforced by:* maintainer review.

**GOV-19** — Every commit in a PR from an outside contributor MUST carry a `Signed-off-by:` line ([Developer Certificate of Origin 1.1](https://developercertificate.org/)), added with `git commit -s`. PRs by the maintainer and by agents are exempt, because Logbie LLC owns that work.  
*Why:* the contributor certifies that they have the right to submit the code under Apache-2.0.  
*Enforced by:* DCO GitHub App, set to skip repository members — not set up yet (setup checklist #9).

**GOV-20** — A contribution written partly or fully by an AI tool MUST say so in the PR description. The human contributor is responsible for every line.  
*Why:* reviewers check machine-written code differently.  
*Enforced by:* PR template checkbox (exists).

**GOV-21** — Contributions that fall under the PRD's non-goals MUST be declined: any network feature (permanently, HR-1), token types other than YubiKey 5, and leaf-certificate issuance in version 1.  
*Why:* these are deliberate scope decisions, and network code would break Keystone's main security promise.  
*Enforced by:* maintainer review.

**GOV-22** — Everyone taking part in the project MUST follow the code of conduct ([CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), Contributor Covenant 3.0).  
*Why:* a respectful space keeps contributors.  
*Enforced by:* maintainer moderation; reporting contact — open item #1.

## 7. Exceptions

**GOV-23** — A rule in GOVERNANCE.md, TESTING.md or SECURITY.md MAY be broken only when the PR description gives a written reason, the PR carries the label `policy-exception`, and the maintainer approves it.  
*Why:* sometimes a rule does not fit a situation; the reason is then recorded instead of the rule being ignored.  
*Enforced by:* maintainer review; `policy-exception` label — not set up yet (setup checklist #10).

## 8. Changing this policy

**GOV-24** — A change to a policy file MUST be made in a PR that gives a short reason, and the PR MUST stay open at least 7 days before it is merged. Typo and broken-link fixes are excepted.  
*Why:* contributors get time to comment on rules that affect them.  
*Enforced by:* maintainer review.

**GOV-25** — The policy files MUST be reviewed before each full release, and whenever the maintainers, the hosting or the security exposure change. Wherever a rule can be enforced automatically (a CI check or a GitHub ruleset), the review SHOULD move it to automatic enforcement.  
*Why:* rules that nobody checks drift away from reality.  
*Enforced by:* maintainer full-release checklist.

## Open items

1. **Code-of-conduct reporting contact.** No private contact exists yet; `CODE_OF_CONDUCT.md` contains a `TODO`. Affects GOV-22.
2. **Exact paths of the sensitive code.** Add the real folder paths to the sensitive-code list in section 3 when the crates exist (PRD milestone M1). Affects GOV-10, GOV-15, GOV-18, SECP-06.

## Setup checklist

These settings and CI jobs do not exist yet. Each rule marked "not set up yet" points to one of these numbers. Remove an item when it is done, and update the rule's *Enforced by* line.

1. **Create the public GitHub repository**, push `main`, create `dev`, and turn on **private vulnerability reporting** (Settings → Security). The maintainer keeps the only Admin role. — enables GOV-01 and the reporting section of SECURITY.md.
2. **2FA for everyone with write access.** If the repository is in a GitHub organization, turn on "Require two-factor authentication"; otherwise check each collaborator's 2FA before giving write access. — enables GOV-02, SECP-08.
3. **Give agents their own GitHub identity** (a machine user or a GitHub App) with the Write role, never Admin, so agents' PRs are not authored by the maintainer and their tokens cannot change settings or rulesets. — enables GOV-09, SECP-02.
4. **Ruleset for `dev`:** require a PR; block direct pushes, force pushes and deletion; require the status checks from item #8; require signed commits; allow squash merge only. — enables GOV-06, GOV-07, GOV-11, AGENT-04, AGENT-05, TEST-06.
5. **Ruleset for `main`:** require a PR with one approving review; require the status checks from item #8; require signed commits; allow merge commits only; block force pushes and deletion. — enables GOV-06, GOV-09, GOV-11, AGENT-05, TEST-06.
6. **Tag ruleset for `v*`:** only the maintainer may create, update or delete these tags. — enables GOV-14, AGENT-05.
7. **Turn on secret scanning, push protection and Dependabot alerts**, and add `.github/dependabot.yml` with weekly updates for `cargo` and `github-actions`. — enables SECP-01, SECP-05, TEST-11.
8. **Write the CI workflow (PRD milestone M1)** with these required jobs: format, clippy, tests (including E2E with the YubiKey simulator), coverage, `cargo audit`, `cargo deny` (including the networking-crate ban), `cargo vet`, the plaintext-key scanner, the RFC 5280 lint, a short fuzz run per target, CodeQL, and the requirement-traceability check. Add a nightly long fuzz run and the non-required "blocked tests" report job. Set default `permissions: contents: read` and pin every third-party action to a full commit SHA. — enables GOV-07, AGENT-04, TEST-01, TEST-02, TEST-04, TEST-05, TEST-06, TEST-10, TEST-11, SECP-03, SECP-04, SECP-06, SECP-07, SECP-09.
9. **Install the DCO GitHub App**, configured to require sign-off only from people who are not repository members. — enables GOV-19.
10. **Create the labels `ai-generated` and `policy-exception`.** — enables AGENT-07, GOV-23.
11. **Release tooling:** a hardware-backed signing key for tags and `SHA256SUMS` (not the CA's YubiKey), SBOM generation (for example `cargo-cyclonedx`), GitHub build-provenance attestations, and the reproducible two-build pipeline (PRD milestone M7). — enables GOV-14, GOV-16, SECP-10.
12. **Store recovery material offline:** GitHub recovery codes and the signing key's recovery steps, kept outside the repository and separate from CA material. — enables GOV-05.

---
Last reviewed: 2026-11-01
