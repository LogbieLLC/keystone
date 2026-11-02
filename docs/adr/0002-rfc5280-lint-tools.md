# ADR 0002: RFC 5280 linting: zlint for certificates, pkilint for CRLs

- Status: Accepted (maintainer decision, 2026-11-02)
- Affects: FR-10 AC4, SEC-13, CI (`rfc5280-lint` job)

## Context

FR-10 AC4 requires every generated certificate to pass an RFC 5280 linting test in CI,
"for example `zlint` or `pkilint`". Both were run on a generated KEYSTONE TEST hierarchy:

- **pkilint 0.13.3** reported false positives on valid RFC 5280 encodings:
  - it rejects single-label DNS name constraints such as the PRD's own example
    `starnet` (it uses a domain validator that demands a top-level domain, while RFC 5280
    refers to RFC 1034 preferred name syntax, which allows one label);
  - it validates rfc822Name and URI *constraints* as full mailboxes and full URLs,
    although RFC 5280 section 4.2.1.10 allows domain forms (`.example.com`) there.
  - It linted every CRL clean.
- **zlint v3**, restricted to its RFC 5280 / RFC 5480 / RFC 5891 rules, handled both
  correctly. Its default CA/Browser Forum rules do not apply to a private CA (certificate
  policies, AIA and so on are not in the PRD profile). zlint does not lint CRLs.

## Decision

- Certificates: **zlint v3.7.3** with `-includeSources RFC5280,RFC5480,RFC5891`. Any
  `error`, `warn` or `fatal` result fails CI.
- CRLs: **pkilint 0.13.3** `lint_crl -t CRL -p PKIX`. Any finding at WARNING or above
  fails CI.
- Both tools are pinned and installed in CI only (zlint built from source with Go, pkilint
  from PyPI in a virtual environment). Neither is part of the product.
- `scripts/lint-samples.sh` runs both on the output of
  `cargo run -p keystone-testkit --example generate_samples`.

## Consequences

- The lint gate passes for every certificate and CRL Keystone produces today, including
  single-label permitted DNS names.
- If a future zlint or pkilint version changes behaviour, the pin keeps CI stable; an
  upgrade is a CI-configuration change (ask-first for agents, AGENT-02).
