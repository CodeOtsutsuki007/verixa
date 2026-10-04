# Threat Model: Audit Log Tampering and Deletion

This document presents a **STRIDE-based threat model** for Phase 10 — Audit Logging (`packages/audit`), roadmap issues 181–200.

It analyzes threats across the record, storage, verification, anchoring, query, export, and retention paths, and maps each threat either to the issue that mitigates it or to an explicitly accepted risk with the rationale for accepting it.

Companion documents: `docs/security/audit-log-integrity.md` (how the mechanisms work), `docs/adr/0003-stellar-audit-anchoring.md` (why the external commitment is a ledger and not a service), `docs/guides/stellar-anchoring.md` (operating the anchor).

---

## The Core Security Thesis

An ordinary CRUD threat model is dominated by **unauthorized writes**: prevent the attacker from changing a row. An append-only audit log inverts that. The writes are the easy part — anyone may add a record, and the interesting adversaries are the ones who want to _remove or alter_ what is already there.

> **The primary threat is a stakeholder with legitimate write access to the audit store quietly rewriting or truncating history, and the log being unable to prove that they did not.**

That single sentence dictates the shape of everything in this package:

- The adversary is modelled as someone with **database write access**, not merely an external requester. Every control that assumes the storage is trustworthy is worthless here.
- The goal is **tamper evidence, not tamper proofing**. Nothing in this design stops a privileged actor from editing rows; the design makes edits _detectable by someone who holds an earlier copy of a hash_.
- Because "holds an earlier copy of a hash" is the whole basis of the guarantee, the hashes have to escape the database. That is what anchoring to Stellar is for (Issue 190A), and it is why the chain alone is not the answer.

| Mechanism                                            | What it detects                                                                                  | What it cannot detect                                            | Mitigating issue(s)   |
| :--------------------------------------------------- | :----------------------------------------------------------------------------------------------- | :--------------------------------------------------------------- | :-------------------- |
| **Append-only repository port**                      | Application-level edits, since no code path exists to make them                                  | Direct SQL, a compromised DB role, a restore from a stale backup | Issue 183             |
| **Hash chaining** (`AuditLogEntry`, `verifyChain`)   | Altered content, broken links, sequence gaps — _given a trusted earlier hash_                    | A chain rewritten from the point of tampering onward             | Issue 190, 191        |
| **Stellar anchoring** (chain head committed off-box) | A wholesale rewrite, because the new head will not match any committed digest                    | Truncation after the last anchored head; edits between anchors   | Issue 190A, 190B–190D |
| **Length-prefixed canonical form**                   | Equivocation, where two different records hash identically                                       | —                                                                | Issue 196             |
| **Metadata bounds + per-sink encoders**              | Log forgery, CSV row injection, spreadsheet formula execution, unbounded writes                  | —                                                                | Issue 196, 193        |
| **Retention seam (evaluation only)**                 | Nothing directly — it makes the erasure decision reviewable and auditable before deletion exists | —                                                                | Issue 192             |

---

## Trust Boundaries

```
   Domain events (in-process, trusted-ish)          External caller (untrusted)
  +-------------------------------------+        +---------------------------+
  | Subscribers 185/186 -> RecordAudit- |        | Query 187 / Export 189    |
  | Event 184                           |        | (authorization: Issue 199)|
  +------------------+------------------+        +-------------+-------------+
                     |                                          |
                     v  metadata bounded here (196)             v
        +-----------------------------+            +-------------------------+
        | AuditLogEntry  hash chain   |--append--> | Postgres  audit_*       |
        | (190) canonical form (196)  |            | (183: no update/delete) |
        +--------------+--------------+            +------------+------------+
                     |                                          |
                     | chain head digest                        | read (187/189)
                     v                                          v
        +-----------------------------+            +-------------------------+
        | Stellar anchor (190A)       |            | CSV / JSONL export      |
        | append-only outside our ACL |            | encoders (189, 196)     |
        +-----------------------------+            +-------------------------+
                     |                                          |
                     v                                          v
              Anyone with a receipt                      Auditor's laptop
              + operator funding monitor (190C)          (formula injection!)
```

Three things cross a boundary on every write: the values being recorded, the digest that commits to them, and the digest leaving the trust zone entirely.

### Failure stance

| Component                     | Failure mode               | Behaviour                                                                                   | Why                                                                                                             |
| :---------------------------- | :------------------------- | :------------------------------------------------------------------------------------------ | :-------------------------------------------------------------------------------------------------------------- |
| `RecordAuditEvent` (184)      | Repository append throws   | Entry is **not** written; the error goes to `onError`; the audited operation still succeeds | An audit write must not turn a successful login into a failed one. See Accepted Risk AR-1.                      |
| `AuditMetadata.create` (196)  | Bag exceeds a bound        | Entry **is** written with a `metadataRejected` marker                                       | Dropping the record is the outcome an attacker wants. See AR-2.                                                 |
| `AnchorAuditLog` (190A)       | Horizon submit fails       | Anchor is retried/reported; the chain keeps growing                                         | The commitment is asynchronous by design; a delayed anchor is a degraded guarantee, not a broken one.           |
| `AnchorBalanceMonitor` (190C) | Anchor account underfunded | `beforeAnchor()` refuses the submit and alerts                                              | Discovering an unfunded anchor from a ledger rejection means discovering it _after_ the commitment gap started. |
| `verifyChain` (190/191)       | Any break                  | Reports the **first** break only                                                            | Everything after a break is unreliable as a consequence of it; the cascade would bury the fact that matters.    |
| `ExportAuditEvents` (189/196) | Log larger than the cap    | Stops and reports `truncated: true`                                                         | A silently partial compliance file is worse than a refused request: the row count was the evidence.             |

---

## STRIDE

### Spoofing — "an entry attributes an action to someone who did not do it"

| #   | Threat                               | Attack sketch                                                                             | Mitigation                                                                                                                                                                                                    | Status                                                   |
| :-- | :----------------------------------- | :---------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :------------------------------------------------------- |
| S1  | Forged `actorId` on a written entry  | Call `RecordAuditEvent` directly with a victim's id                                       | Entries are written by **subscribers** reacting to domain events (185, 186), where the actor is whatever the authenticated use case already resolved — not a request field. No public route accepts an actor. | Mitigated by construction; the write path is not exposed |
| S2  | System-attributed entries            | Write an entry with `actorId: undefined` to make a human action look like a scheduled job | `undefined` means "no actor asserted", and is what the anchoring job itself produces; the distinction between _asserted system_ and _absent actor_ is visible in the sequence                                 | Partially mitigated — see AR-3                           |
| S3  | Spoofed identity upstream of the log | Compromise authentication, then record whatever you like                                  | Out of scope for this package: the audit log records claims. Its job is to make the claim durable and tamper-evident, not to verify it.                                                                       | Accepted: this is the boundary of what a log can know    |
| S4  | Replay of an old, valid chain        | Restore a backup and serve yesterday's honest log as today's                              | Anchored heads are timestamped by ledger close time; a restored chain whose head does not match the latest anchored digest is detected. Continuous anchoring narrows the window to the anchor interval.       | Mitigated (190A); cadence is an operator decision        |

### Tampering — "altering what was recorded"

| #   | Threat                                | Attack sketch                                                                        | Mitigation                                                                                                                                                                                                                                                                    | Status                             |
| :-- | :------------------------------------ | :----------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------- |
| T1  | Edit a stored entry                   | `UPDATE audit_log_entries SET ...`                                                   | `hasValidHash` recomputes the digest from content rather than trusting the stored column, so an edited row fails verification even if its hash column was edited to match — the recomputation is the check.                                                                   | Mitigated (190)                    |
| T2  | Delete a row                          | `DELETE FROM audit_log_entries WHERE sequence = 42`                                  | `verifyChain` reports `link_broken` (predecessor hash mismatch) and `sequence_gap` (numbering skips)                                                                                                                                                                          | Mitigated (190, 191)               |
| T3  | Delete the tail                       | Remove the last N entries, leaving a chain that links perfectly                      | Nothing in the chain detects this — it is the documented limit, and `packages/audit/domain/entities/audit-log-entry.spec.ts` asserts it. The anchor catches it: the anchored head will not be the head anyone presents.                                                       | Mitigated only by anchoring (190A) |
| T4  | Rewrite the chain forward             | Recompute every hash from the edited entry onward                                    | Internally consistent and undetectable locally. Requires an external, non-rewritable commitment to detect — which is the entire reason for ADR-0003.                                                                                                                          | Mitigated by anchoring (190A)      |
| T5  | Port-scoped privilege                 | A DB role that can `UPDATE` even though no code path can                             | The `REVOKE UPDATE/DELETE` statements in `packages/database/prisma/migrations/20260928000000_add_audit_constraints_and_indexes/migration.sql` are **commented out**: they are an operator step, and they are inert if the application role owns the table.                    | Accepted gap — see AR-4            |
| T6  | Equivocation: two records, one digest | Put a newline in `actorId` so the serialized pre-image of one entry equals another's | Framing was the vulnerability: the original canonical form joined fields with a separator that could appear inside a field. The form is now versioned (`verixa-audit-v2`) and every field carries its own UTF-8 byte length, so nothing inside a value can be read as framing | Mitigated (196)                    |
| T7  | Silent reordering of metadata         | Insert the same key/value pairs in a different order                                 | Keys are sorted before hashing, so insertion order cannot change the digest — and cannot _hide_ a change either                                                                                                                                                               | Mitigated (196)                    |
| T8  | Update in place "to fix a mistake"    | Edit an entry after the fact                                                         | There is no update method on the entity, the port, or the repository. Corrections are new appended entries that describe the correction                                                                                                                                       | Mitigated by API shape (183, 190)  |

### Repudiation — "the log is the alibi; the risk is that it was not written"

| #   | Threat                                  | Attack sketch                                | Mitigation                                                                                                                                                                                                                                                                                                                             | Status                                            |
| :-- | :-------------------------------------- | :------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------ |
| R1  | Event loss through a failing subscriber | Break audit writes, then act unrecorded      | `RecordAuditEvent` swallows failures by design, so loss is silent at the call site — but a gap in the sequence is _visible_ to `verifyChain`, and the anchored head will not match. An attacker who can break writes reliably is a privileged attacker, at which point the honest answer is that the log degrades to their discretion. | Accepted risk AR-1, with detection                |
| R2  | Loss under load                         | Overflow the write path during a burst       | Batching and backpressure (193) make loss a designed, observable event rather than a dropped promise                                                                                                                                                                                                                                   | Open: Issue 193                                   |
| R3  | Selective non-recording                 | Never emit an event for the sensitive action | The subscribers are registered at composition root (194) and cover the domain events of every prior context; an action that produces no domain event produces no audit record by definition                                                                                                                                            | Accepted: coverage is the wiring's job (194, 197) |
| R4  | Repudiation of an export                | "I never gave that file to the auditor"      | An export is itself an auditable act: `audit.log.exported` metadata schema exists and `ExportAuditEvents` emits a structured record naming format, count, and truncation                                                                                                                                                               | Mitigated (189, 196); who may export is Issue 199 |

### Information Disclosure — "the log is a treasure trove by design"

| #   | Threat                         | Attack sketch                                                                             | Mitigation                                                                                                                                                                                                                                                          | Status                                      |
| :-- | :----------------------------- | :---------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :------------------------------------------ |
| I1  | Read the whole log             | Query or export everything                                                                | Query and export authorization is Issue 199. Until then the port is authorization-blind by design: it has no notion of a requesting principal, so no call site can accidentally half-implement one.                                                                 | Open: Issue 199                             |
| I2  | Secrets in metadata            | Record a token or password "for debugging"                                                | The metadata schema registry is `.strict()` per action, and its guidance is explicit: no secrets, no PII beyond resource identity. Validation happens at construction.                                                                                              | Mitigated (181); reviewed at authoring time |
| I3  | Error messages echo input      | Overflow the bound with a value containing a probe, then read the rejection message back  | `AuditMetadata.create` names the _type_ and the _bound_ and never echoes a value; the key it names is truncated and escaped, so a rejection cannot be used to reflect unsanitized input into a log line                                                             | Mitigated (196)                             |
| I4  | Test doubles in production API | `InMemoryAuditLogRepository.tamper()` and `.remove()` are exported from the package index | They are the only way to write a test that proves tampering is detected, and the class is unambiguously a test double — nothing in the composition root resolves it. It is a deliberate sharp edge, and the reason `tamper` is named `tamper` rather than `update`. | Accepted AR-5                               |
| I5  | Retention and erasure          | Keep personal data forever                                                                | Issue 192 evaluates a policy and reports candidates; it deletes nothing. Actual erasure is Phase 24 and must keep the anchored digest while removing content, with an explicit erasure entry appended.                                                              | Open: Phase 24                              |

### Denial of Service — "an audit log is a write-amplifying machine"

| #   | Threat                             | Attack sketch                                             | Mitigation                                                                                                                                                | Status                                           |
| :-- | :--------------------------------- | :-------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------- |
| D1  | Unbounded metadata                 | One entry carrying a megabyte bag per request             | 32 fields, 64-character keys, 1024-character values, enforced on input — a bound cannot be imposed later                                                  | Mitigated (196)                                  |
| D2  | Export the whole table into memory | Request an export of a log with 100M rows                 | `DEFAULT_EXPORT_MAX_RECORDS` caps one export and `truncated` says when the cap bit                                                                        | Mitigated (189/196); paging cadence is Issue 188 |
| D3  | Write amplification                | Trigger enough audited events to saturate the append path | Issue 193 (batching, backpressure)                                                                                                                        | Open                                             |
| D4  | Anchor starvation                  | Drain the anchor account's XLM so commitments stop        | Issue 190C: a balance metric, a threshold alert before the failure, and a `beforeAnchor()` guard that refuses to submit rather than failing at the ledger | Mitigated (190C)                                 |
| D5  | Hash-cost amplification            | Make digests expensive with huge pre-images               | Bounded metadata (D1) bounds the pre-image; SHA-256 cost is linear in a length we cap                                                                     | Mitigated by D1                                  |

### Elevation of Privilege — "who is allowed to make the log say things"

| #   | Threat                         | Attack sketch                                                                                        | Mitigation                                                                                                                                                                                          | Status                                               |
| :-- | :----------------------------- | :--------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------- |
| E1  | Escape on the reader's machine | Put `=cmd\|'/c calc'!A1` in a field, wait for an admin to open the CSV in Excel                      | The attacker never touches the server; they touch whoever reads the export. CSV cells are escaped, quoted, and formula-neutralized; JSONL preserves values because a JSON document is not a formula | Mitigated (196)                                      |
| E2  | Forge a log line               | Newline + a plausible timestamped line inside a value                                                | Nothing is interpolated into a log _message_: pino receives fields, and metadata in a text projection is escaped, so an injected break is two characters rather than a break                        | Mitigated (196, following the 008 redaction pattern) |
| E3  | Fabricate a CSV row            | `...,\r\nfake,row` inside a quoted field                                                             | One entry, one line is the invariant the CSV writer exists to keep; the line count of a file is then its record count                                                                               | Mitigated (196)                                      |
| E4  | Trusted reconstitution         | Feed untrusted input to `AuditLogEntry.reconstitute()` / `AuditMetadata.of()`, which skip validation | These are the storage-reload paths. `reconstitute` is documented as trusted-input-only; untrusted input must go through `append`/`create`.                                                          | Accepted AR-6: naming and documentation, not types   |
| E5  | Anchor key misuse              | Sign an anchoring transaction with the anchor's key                                                  | Roadmap 190B (KMS-backed key management). The key signs nothing but the digest, and a memo-hash commitment cannot forge a chain — it can only commit a hash the holder already had.                 | Open: Issue 190B                                     |

---

## Accepted Risks

These are the risks this package knowingly carries. Each is here rather than in a backlog because the alternative was worse and the tradeoff is permanent.

**AR-1 — Audit writes never fail the audited operation.**
`RecordAuditEvent` swallows every error. Alternative rejected: propagate. It turns an audit-storage incident into an authentication outage, and every caller then has to decide what to do about a failure of something that already happened. Detection instead of prevention: gaps are visible to `verifyChain`, and the anchored head will not match what an operator expects.

**AR-2 — Rejected metadata still produces an entry.**
When a bag violates a bound, the entry is appended with `metadataRejected` naming the reason. Alternatives rejected: drop the record (that is the attacker's goal — an unrecorded action), and sanitize on input (that rewrites evidence: the digest would commit to something other than what was supplied). Bounds are an _input_ rule because no encoder can bound an unbounded value later; escaping is an _output_ rule because every sink has its own.

**AR-3 — The log records assertions, not proofs.**
`actorId` is whatever the writing code believed. Nothing in the audit layer can verify it. The guarantee is durability and tamper evidence, so an incorrect attribution stays incorrect forever and visibly — which is the right property for evidence and the wrong one for a security decision. Do not read the audit log as an authorization input.

**AR-4 — Database-level append-only enforcement is an operator step.**
The `REVOKE UPDATE/DELETE` statements ship commented out, and they do nothing when the application role owns the table (Heroku's default). Code-level immutability is real; SQL-level immutability is a deployment instruction. Threat T5 is therefore open for anyone who cannot tell the difference between those two.

**AR-5 — Tampering helpers are exported from a public package.**
`tamper()` and `remove()` exist so tests can prove the chain detects edits. A test that cannot delete a row cannot show `sequence_gap` firing. The exposure is an in-memory object with no persistence behind it; the alternative — a private build of the double — would hide the most important behaviour in the package.

**AR-6 — `reconstitute`/`of` are trust-by-convention.**
The skip-validation reload paths are essential (re-validating history would make old records unreadable after a rule change, and would report imagined tampering) and are guarded by naming and documentation rather than by types. Reviewers should treat any call site that reaches them with request data as a defect.

---

## What This Design Does Not Claim

Worth stating plainly, because "we hash-chain our audit log" is routinely offered as though it were the whole answer.

1. **It is not tamper-proof.** Anyone with write access to the table can rewrite the chain from any point forward, and the result verifies perfectly.
2. **Chaining is only evidence relative to a hash someone kept.** Without an external copy — an anchored digest — T4 and T3 are undetectable.
3. **Anchored digests do not prove the log is complete.** They prove that a particular digest existed at a ledger close time. Truncation after the last anchor is a gap in coverage, and the anchor interval is the exposure window.
4. **Timestamps are asserted.** `occurredAt` is the application's clock, and the ledger's close time only brackets when a digest was committed.
5. **Structured output is not a substitute for authorization.** Every encoder in this package is safe; none of them is access control (Issue 199).

---

## Review Checklist

For changes to `packages/audit`, or anything that writes audit data:

- [ ] Does the change add a new output path (log, CSV, JSON, terminal, spreadsheet, digest)? If so, how does it keep structure separate from content? Copy an existing encoder rather than inventing one.
- [ ] Does anything new reach a `reconstitute`-style path with data that came from outside the process?
- [ ] Are new metadata fields bounded, and are the bounds checked on input rather than at output?
- [ ] Does the change add a repository method that could alter or remove history? (The answer must be no; that is the guarantee.)
- [ ] If the canonical form changed, is it versioned, and has the digest-history consequence been written down? Changing serialization silently rewrites every stored hash comparison.
- [ ] Does a failure of the audit write change whether the audited action succeeded?

---

## References

- `packages/audit/domain/entities/audit-log-entry.ts` — chain construction and `verifyChain`
- `packages/audit/domain/value-objects/audit-metadata.ts` — bounds and per-sink encoders
- `packages/audit/application/use-cases/export-audit-events.ts` — CSV/JSONL writers
- `packages/audit/application/ports/retention-policy.ts` — Issue 192 seam
- `packages/stellar-anchor/infrastructure/balance-monitor.ts` — Issue 190C funding guard
- `docs/security/audit-log-integrity.md` — the mechanisms, in order
- `docs/adr/0003-stellar-audit-anchoring.md` — commitment choice
- `docs/security/threat-model-abac.md` — the format this document follows
- OWASP Logging Cheat Sheet; STIG/Audit-expo formula-injection guidance; RFC 4180
