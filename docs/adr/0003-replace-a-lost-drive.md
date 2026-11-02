# ADR 0003: Guided "Replace a lost drive" action

- Status: Accepted (maintainer decision, 2026-11-02)
- Affects: SEC-11, FR-12, threat T-11 (drive failure or loss); adds a guided action not
  listed in PRD section 6
- Requires: GOV-04 (threat-model mitigation change needs an ADR)

## Context

Every CA-changing operation needs the primary drive and at least one backup (FR-12 AC1).
The storage review found that no flow could add a replacement drive or promote a backup.
If the primary failed, or a CA's only backup failed, the CA could never write again —
not even an emergency key-compromise revocation (FR-13). T-11 was therefore only half
mitigated.

## Decision

Add a guided **Replace a lost drive** action (plan → review → execute, like the flows):

1. It copies the complete CA state from the healthy, in-sync drive(s) to a new **empty**
   drive: every audit entry, journal entry, record file and output file listed in a
   completed entry. Each copied file is verified by SHA-256 against the completed
   entries and the audit chain; the new drive's identity file is written last, so an
   interrupted copy never looks like a complete drive.
2. If the lost drive was the primary, it promotes one backup to primary.
3. It appends audited entries (drive added / replaced, primary promoted) on all drives.
4. It signs nothing, needs a confirmed time (FR-17), never overwrites or deletes
   anything, refuses a non-empty target, and refuses while drive histories diverge or an
   operation is pending.
5. It is allowed when only **one** healthy drive remains — the emergency case. A drive
   set with fewer than a primary plus one backup can run only this action; every signing
   action still requires a primary and at least one backup.

## Consequences

- A single drive failure no longer ends the CA's ability to revoke or issue.
- The PRD should list this action next to Flows A–E; the threat model's T-11 mitigation
  now reads "write to 2+ drives, read-back verify, guided drive replacement".
- Fault-injection tests interrupt the copy at every drive change (FR-22 AC6 style).
