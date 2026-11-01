# AGENTS.md — Keystone

Instructions for AI coding agents (Claude, ChatGPT/Codex, Grok, Devin and others) working on Keystone.
Keystone is an offline Rust desktop app that builds an X.509 CA hierarchy. The requirements are in `Keystone PRD6 - final.md` and the dependency baseline is in `Keystone Dependencies.md`. Read both before writing code.

<!-- BEGIN project-policy (generated; edit GOVERNANCE.md / TESTING.md / SECURITY.md instead) -->
## Project policy for AI agents

These rules come from GOVERNANCE.md, TESTING.md and SECURITY.md. The ID in brackets points to the full rule and its reason. If a rule here seems to conflict with your task, stop and ask the maintainer (Brad Byrd).

### Always
- Work on a branch and open a PR into `dev`. [GOV-06]
- Write the failing test first; commit it before or with the code. [TEST-01]
- List the PRD IDs your PR covers in its description (for example `FR-04 AC2`, `SEC-08`). [TEST-01]
- Add a regression test with every bug fix. [TEST-03]
- Use synthetic test data only; put `KEYSTONE TEST` in every test certificate's Common Name; get test keys only from `keystone-testkit`. [TEST-11]
- Write files in tests only to temporary directories (`tempfile`). [TEST-12]
- Turn every fuzz crash or hang into a regression test and add its input to the corpus. [TEST-13]
- Report a test that needs StarnetAuth as BLOCKED, never as skipped or passing. [TEST-10]
- Open an issue for a flaky test. [TEST-09]
- Mark your work: a `Co-Authored-By:` trailer naming you in each commit, the `ai-generated` label, and your name in the PR description. [AGENT-07]
- Use Conventional Commits for commit messages and PR titles. [GOV-12]
- Merge into `dev` only your own PR, only as a squash merge through GitHub, only when every required check passed (none failed, skipped or cancelled), and only once required checks exist in the `dev` ruleset. [AGENT-04, GOV-07, GOV-11, TEST-06]
- When you open a `dev` → `main` PR, list every sensitive-code change since the last merge into `main` (sensitive code is listed in GOVERNANCE.md section 3). [GOV-10]
- Leave a PR that changes a policy file unmerged until it has been open 7 days. [GOV-24]
- Keep every OpenSSL call inside the crypto module, and `unsafe` only inside the FFI module. [SECP-06]
- Keep dependencies pinned to exact versions, and commit the `Cargo.lock` change together with any dependency change. [SECP-03]

### Ask first (and wait for a yes)
- Before changing CI configuration (`.github/workflows/`, `.github/dependabot.yml`, `deny.toml`, `supply-chain/`, `rust-toolchain.toml`). [AGENT-02]
- Before adding or removing a crate. [AGENT-02, SECP-04]
- Before upgrading `yubikey` or its local patch, `openssl`, `openssl-sys`, or the Rust toolchain pin. Other crate upgrades are allowed. [AGENT-01, AGENT-02]
- Before changing a policy file: GOVERNANCE.md, TESTING.md, SECURITY.md, AGENTS.md, CLAUDE.md, CODEOWNERS. [AGENT-02]
- When a PRD requirement is unclear or two requirements conflict. [AGENT-03]
- When a change would touch a PRD hard rule (HR-1 to HR-3), the certificate profile or the threat model. [AGENT-03, GOV-04]
- When the work goes outside the task you were given. [AGENT-03]

### Never
- Push directly to `dev` or `main`. [GOV-06, AGENT-05]
- Merge into `main`, unless the maintainer gave written permission for that specific PR; quote it in a PR comment first. [GOV-09, AGENT-05]
- Merge a PR from a fork. [GOV-08, AGENT-05]
- Delete, skip, weaken or `#[ignore]` a test, or lower a threshold such as coverage. [TEST-07]
- Create tags or publish releases. [GOV-14, AGENT-05]
- Add a `Signed-off-by:` line, run `cargo vet certify`, edit `cargo vet` audit records, or sign a tag. [AGENT-06]
- Approve a policy exception, including for yourself. [GOV-23, AGENT-05]
- Treat a review bot's approval as the maintainer's approval. [AGENT-08]
- Access real CA material: real keys, passphrases, YubiKey PIN/PUK/management key, production USB drives, or a real YubiKey. [SECP-02]
- Commit secrets. [SECP-01]
- Add networking code or a networking crate. [SECP-07]
- Use `pull_request_target` to run PR code, or a third-party action not pinned to a full commit SHA. [SECP-09]
- Add features from the PRD's non-goals (network functions, other token types, v1 leaf certificates). [GOV-21]
<!-- END project-policy -->
