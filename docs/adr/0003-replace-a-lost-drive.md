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

## Amendment 1 (maintainer decisions, 2026-11-02)

The final storage review showed three gaps in the decision above. The maintainer chose
the following changes. They replace rule 4's "refuses while an operation is pending" and
add rules 6 to 9.

**Rule 4, changed — a drive lost during an operation.** If a drive dies while an
operation is running, every recovery action needs a primary and a backup, so under the
original rule 4 the CA could never write again, not even for a key-compromise revocation.
Replacement is now **allowed while one operation is pending**:

- It also copies that operation's journal entries and its staged files. Staged keys are
  always encrypted (SEC-04).
- Before copying, it checks that those journal entries and staged files are byte-identical
  on every connected drive. If they differ, it refuses and names the difference.
- The pending operation is not finished, abandoned or changed by the replacement. After
  it, the normal recovery screen (FR-22 AC4) runs on the primary plus the new drive.
- The review page says that an interrupted operation exists and that recovery comes next.
- Replacement still refuses while the connected drives' histories diverge or a drive is
  damaged.

**Rule 6, new — the operator declares which drives are lost.** Promoting a backup could
fork or roll back the CA's history: a backup missing a recent operation could be promoted
and lose, for example, a revocation; and an old primary found again could still sign
together with an old backup that never saw the promotion. So:

- The audit log keeps a **drive roster**: every drive id recorded by Flow A's drive setup
  and by each later "drive added" entry, with its role, minus drives recorded as lost.
- Every replacement names the drive or drives it replaces. The operator picks them from
  the roster (shown by drive label, role and id) and confirms that each one is lost.
- Every roster drive must be either **connected** or **declared lost** in this action.
  Otherwise the action is refused and names the missing drive. Without a primary
  connected, this also applies to every other backup.
- The declared drives are recorded as lost in the audit log.

**Rule 7, new — the most complete drive is the source.** Without a primary, the source
is the connected drive with the longest verified history. A connected drive that is only
behind it is brought up to date in the same action before anything else is copied, and
that is audited. Drives that diverge still block the action.

**Rule 8, new — a lost drive is never used again.** At start, Keystone refuses any drive
whose id another connected drive's audit log records as lost. It tells the operator to
retire it. Such a drive is never repaired back into the set.

**Rule 9, new — one physical device per drive, and no unrecorded drives** (from the same
review, needs no decision):

- Two CA drives on one device are refused, and so is a target on a connected drive's
  device.
- A replacement drive carries a create-only marker file. A drive with an identity but no
  "drive added" entry is reported as damaged, and nothing is signed with it until the
  replacement is run again.

Residual risk: if every drive that saw a replacement is lost too, the remaining old drives
cannot know they were replaced. Keystone is offline and cannot detect that. The
replacement's result page therefore tells the operator to retire, and physically mark, the
drives declared lost.
