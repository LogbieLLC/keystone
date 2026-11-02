# ADR 0001: Block email and URI names in sub-intermediates with a reserved permitted subtree

- Status: Accepted (maintainer decision, 2026-11-02)
- Affects: the fixed certificate profile (PRD section 5, FR-21 AC3, SEC-21), threat T-14
- Requires: GOV-04 (profile change needs an ADR)

## Context

FR-21 AC3 says sub-intermediates exclude IP addresses entirely (0.0.0.0/0 and ::/0 in
excludedSubtrees) and that "email and URI names are excluded the same way".

RFC 5280 section 4.2.1.10 defines no value that matches *every* email address or *every*
URI. The first implementation wrote a zero-length rfc822Name and a zero-length
uniformResourceIdentifier into excludedSubtrees. Testing showed:

- Go's crypto/x509 and NSS treat a zero-length constraint as "match everything", so they
  rejected email/URI leaves.
- OpenSSL compares the empty value literally, so it **never matches**: a leaf carrying
  `email:attacker@evil.example` or `URI:spiffe://evil.example/x` under a stolen
  sub-intermediate **verified OK** with `openssl verify`.
- RFC 5280 linters reject the zero-length values (zlint `e_name_constraint_not_fqdn`,
  pkilint `invalid_email_address_syntax` / `invalid_uri_syntax`), which conflicts with
  FR-10 AC4.

## Decision

Sub-intermediates put rfc822Name `.keystone.invalid` and uniformResourceIdentifier
`.keystone.invalid` in **permittedSubtrees**, and no longer write zero-length entries.

`.invalid` is a reserved top-level domain (RFC 2606, RFC 6761) that can never be a real
host. Because a permitted subtree of a given name type exists, every email address and
every URI in a leaf must fall under `.keystone.invalid`, which no real one does.

IP handling is unchanged: excluded 0.0.0.0/0 and ::/0 unless the operator enters
permitted IP ranges. DNS handling is unchanged: the operator's permitted DNS names.

## Evidence (measured 2026-11-02, OpenSSL 3.0.13, Go 1.24.7, zlint v3)

| Leaf under the sub-intermediate | `openssl verify` | Go `Certificate.Verify` |
| --- | --- | --- |
| `DNS:www.starnet` (permitted) | OK | OK |
| `DNS:www.starnet` + `email:alice@example.com` | fails | fails ("not permitted by any constraint") |
| `DNS:www.starnet` + `URI:https://evil.example.com/x` | fails | fails |

zlint's RFC 5280 rule set reports no findings on the resulting certificate.

## Consequences

- Email and URI names are blocked by OpenSSL **and** Go, which closes a real gap in the
  T-14 mitigation (a stolen sub-intermediate key).
- The wording differs from FR-21 AC3's literal text ("excluded"); the effect matches its
  intent. The PRD should be updated to describe this encoding.
- The review step, issuance record and audit entry (FR-21 AC6) state exactly what is
  written.
- Tests in `keystone-core/tests/interop/name_constraints.rs` prove the table above with
  both verifiers.
