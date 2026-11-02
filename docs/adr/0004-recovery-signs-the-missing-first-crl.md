# ADR 0004: Recovery may sign the master's missing first CRL

- Status: Accepted (maintainer decision, 2026-11-02)
- Affects: FR-22 AC4 (recovery actions), FR-13 (CRLs), FR-02 (Flow A)

## Context

Flow A signs the master certificate and then the master's first, empty CRL (CRL number 1).
No child may be issued before an issuer's first CRL exists.

If Flow A is interrupted after the master certificate was signed but before the first CRL
was signed, the master certificate is a signed output (FR-22 AC3). So it cannot be
abandoned, and FR-22 AC4's other action, "finish the writes", would leave a master without
its first CRL.

FR-22 AC4 lists only "finish the writes" and "abandon". But FR-22 AC5 already lets the
master sign during recovery, when a YubiKey setup is completed with the key already in the
YubiKey.

## Decision

For this one state, recovery offers **"Unlock the master with its passphrase to sign its
missing first CRL, then write the files and mark the operation completed"**.

- It signs only the empty first CRL (CRL number 1) with the content Flow A would have
  signed. It never signs the master certificate again.
- The CRL is journaled and audited like any other signature (FR-14 AC1, FR-22 AC1).
- It deletes and overwrites nothing (FR-22 AC8).
- It needs the master passphrase and a confirmed time (FR-17, SEC-16).

The alternative was to let recovery only write the files, and make the operator run
"Refresh CRL" before anything else. It was rejected: it adds a step the operator must
remember, and it leaves the CA blocked until then.

## Consequences

- PRD FR-22 AC4 should read: "...offers only safe actions: finish the writes from a drive
  that holds the verified output (for an interrupted Flow A, also signing the master's
  missing first CRL), or mark the operation abandoned when no signed output exists
  anywhere."
- The recovery screen's sentence says that the master's passphrase is needed and that
  the master certificate is not signed again.
