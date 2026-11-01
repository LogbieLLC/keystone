# Security Policy — Keystone

Keystone creates and protects the keys of a certificate authority. A vulnerability in it can affect every certificate its users sign, so security reports are very welcome.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.** A public report tells attackers about the problem before a fix exists.

Report privately through **GitHub private vulnerability reporting**: open the **Security** tab of the Keystone repository on GitHub and choose **Report a vulnerability**.

Please include:
- which version is affected (for example `2026.11.2` or `2026.11.3-dev`) and which part (for example key storage, certificate building, YubiKey handling, the recovery screen);
- the steps to reproduce the problem, using test keys only;
- what an attacker could do with it (for example read a private key, make Keystone sign something unintended, or produce a certificate other systems wrongly trust).

### What happens next

- You receive an acknowledgement **within 14 days**.
- You receive a first assessment (whether it is a real vulnerability, and how serious) **within 30 days**.
- Details are published in coordination with you, **within 90 days of your report**, or sooner once a fix is released, unless you and the maintainer agree on a different date.
- A confirmed vulnerability gets a GitHub Security Advisory, and a CVE (a public ID number for a vulnerability) is requested through GitHub.
- Every advisory says plainly whether operators have to revoke or re-issue any certificate or key made with an affected version, and which ones.
- Reporters are credited in the advisory, unless they ask not to be.
- There is no bug bounty (no payment for reports).

Keystone has one maintainer. If the maintainer is unavailable for a long time, the project pauses, and reports may not be answered within these times.

### Supported versions

| Version | Receives security fixes |
| --- | --- |
| Latest full release (`YYYY.M.BUILD`) | Yes |
| Older full releases | No — upgrade to the latest full release |
| Any `-dev` release (`YYYY.M.BUILD-dev`) | No — `-dev` releases are not for use with a real CA |

No full release exists yet. Until the PRD's version 1 acceptance (milestone M8) is complete, every release is a `-dev` release.

### Out of scope

- Vulnerabilities in StarnetAuth, Ubuntu, OpenSSL, GTK, libadwaita, `pcscd` or the YubiKey firmware themselves. Please report those to their own projects. If Keystone's use of them makes a problem worse, that part is in scope.
- Attacks that need the operator to break the operating assumptions in the PRD (section 15, assumption 20, and Appendix A.9), for example running the production build on a laptop that is connected to a network.

### Good-faith research

If you research Keystone's security in good faith — on your own copy, using your own test keys, without touching anyone else's systems, keys or data — and you report what you find privately and give reasonable time for a fix, the maintainer and Logbie LLC will not take legal action against you for that research.

---

## Security practices (for maintainers and contributors)

The words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as defined in RFC 2119.
Rule IDs here use the prefix `SECP-` so they do not clash with the PRD's own security requirements `SEC-01` to `SEC-23`.
Each rule says what enforces it **today**. "Setup checklist #N" refers to the numbered list at the end of [GOVERNANCE.md](GOVERNANCE.md#setup-checklist).

### 1. Secrets

**SECP-01** — Secrets (tokens, passwords, private keys, passphrases) MUST NOT be committed to this repository. GitHub secret scanning and push protection MUST be turned on.  
*Why:* anything committed to a public repository is public forever.  
*Enforced by:* GitHub secret scanning and push protection — not set up yet (setup checklist #7).

**SECP-02** — Real CA material (private keys, passphrases, YubiKey PIN, PUK or management key, production USB drives, or a real CA YubiKey) MUST NOT exist on any development machine, CI runner or agent environment, and agents MUST NOT access it. The hardware YubiKey tests are run only by the maintainer. Agents' GitHub tokens MUST NOT be able to change repository settings or rulesets.  
*Why:* the PRD trusts build machines and CI only to produce identical builds, never with a CA secret (PRD section 4).  
*Enforced by:* AGENTS.md; separate agent GitHub identity without Admin — not set up yet (setup checklist #3).

### 2. Dependencies

**SECP-03** — Dependencies MUST be minimal and pinned to exact versions, `Cargo.lock` MUST be committed, production builds MUST use vendored sources, and CI MUST run `cargo audit`, `cargo deny` (licences, advisories, banned crates) and `cargo vet` (PRD SEC-01).  
*Why:* a malicious or vulnerable dependency is the highest-rated threat in the threat model (T-01).  
*Enforced by:* `.gitignore` no longer ignores `Cargo.lock` (exists); CI jobs — not set up yet (setup checklist #8).

**SECP-04** — Each new crate, and each new version of a crate, MUST be reviewed by the maintainer, who records the review with `cargo vet`. Agents MUST ask before adding or removing a crate (AGENT-02), and an outside contributor MUST have an agreed issue before adding one (GOV-18).  
*Why:* the `cargo vet` record is the maintainer's statement that the code was checked; nobody else can make it.  
*Enforced by:* `cargo vet` CI job — not set up yet (setup checklist #8); maintainer review.

**SECP-05** — Dependabot alerts MUST be on, and Dependabot SHOULD open update PRs weekly for `cargo` and `github-actions`. These PRs follow the same rules as agent dependency upgrades (AGENT-01, AGENT-02).  
*Why:* security fixes in dependencies are found quickly, but still pass every check.  
*Enforced by:* Dependabot settings and `.github/dependabot.yml` — not set up yet (setup checklist #7).

### 3. Static analysis and code safety

**SECP-06** — Code MUST pass `cargo clippy -- -D warnings`; `#![forbid(unsafe_code)]` MUST apply everywhere except the single reviewed FFI module; every OpenSSL call MUST go through the one crypto module (PRD SEC-18). CodeQL code scanning for Rust MUST run on every PR, and a high-severity finding MUST block the merge.  
*Why:* AI-generated code that misuses cryptography is a top threat (T-18); keeping the dangerous code in two small places makes it reviewable.  
*Enforced by:* CI jobs `clippy` and CodeQL — not set up yet (setup checklist #8); maintainer review of the crypto and FFI modules.

**SECP-07** — Networking code and networking crates MUST NOT be added to Keystone (PRD HR-1, SEC-03).  
*Why:* Keystone's central promise is that the production build has no networking code paths.  
*Enforced by:* `cargo deny` ban list — not set up yet (setup checklist #8); network-policy tests (TESTING.md section 1); GOV-21.

### 4. Code-host accounts and branch protection

**SECP-08** — Everyone with write access MUST use two-factor authentication. The maintainer MUST use a hardware security key for GitHub. The CA's YubiKey MUST NOT be used for GitHub or any development work.  
*Why:* a stolen GitHub account could change the source of every future release; the CA's YubiKey has to stay single-purpose.  
*Enforced by:* 2FA requirement — not set up yet (setup checklist #2); honour system for the hardware key.

**SECP-09** — GitHub Actions workflows MUST use default `permissions: contents: read`, MUST pin every third-party action to a full commit SHA, and MUST NOT give secrets to PRs from forks. `pull_request_target` MUST NOT be used to run code from a PR.  
*Why:* CI runs code from strangers' PRs; it must not be able to write to the repository or read secrets.  
*Enforced by:* maintainer review of workflow changes (CI configuration is sensitive code); CI workflow — not set up yet (setup checklist #8).

Branch and tag protection are described in GOVERNANCE.md (GOV-06, GOV-11, GOV-14).

### 5. Sensitive data

What Keystone handles, and how it is protected, is listed in the PRD: section 11 (data) and Appendix A (threat model). The most important points for development:
- Passphrases, PINs and PUKs are never stored by the tool.
- Private keys are only ever written encrypted (PRD SEC-04); the plaintext-key scanner checks this in CI.
- Development and CI never see real CA secrets (SECP-02).
- Test data is synthetic (TEST-11).

### 6. Release integrity

**SECP-10** — Every release (including `-dev` releases) MUST publish a `SHA256SUMS` file signed with the maintainer's signing key. A full release MUST also publish an SBOM (Software Bill of Materials: a list of every component in the release) and a GitHub build-provenance attestation, and MUST come from two independent builds with the same SHA-256 (PRD SEC-02); that value is what the operator checks on the laptop before install (PRD SEC-19).  
*Why:* users must be able to prove the binary they run is the one that was built from the reviewed source.  
*Enforced by:* maintainer release checklist; release tooling — not set up yet (setup checklist #11).

### 7. Threat model

The threat model is Appendix A of the PRD (`Keystone PRD6 - final.md`).

**SECP-11** — The threat model MUST be reviewed before every full release, and whenever one of its review triggers (PRD Appendix A.10) happens. The review MUST be noted in the release PR or in the PR that caused the trigger.  
*Why:* a threat model that does not match the code gives false confidence.  
*Enforced by:* maintainer full-release checklist; GOV-04.

### 8. Incident response

An incident is, for example: a release that is broken or malicious, a compromised GitHub account or signing key, or a malicious dependency.

**SECP-12** — In a security incident, the maintainer MUST:
1. **Contain** — pull the affected release, and revoke or rotate the affected key or token.
2. **Assess** — find out what was exposed and which versions are affected.
3. **Fix** — release a corrected version.
4. **Tell users** — publish a GitHub Security Advisory that says which certificates or keys operators have to revoke or re-issue.
5. **Learn** — write a short postmortem in `docs/incidents/`.

*Why:* a fixed order prevents skipping containment under stress.  
*Enforced by:* maintainer; this checklist.

---
Last reviewed: 2026-11-01
