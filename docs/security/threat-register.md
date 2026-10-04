# Threat Register

Every threat identified so far across Verixa's bounded contexts, in one place,
with its current status. The per-context threat models explain _why_; this
register answers "what is still open?" without reading all of them.

Format, ID scheme and status definitions: [Threat Model Template](threat-model-template.md).
In short:

- **mitigated** — a control exists on the default branch, is wired into the
  running application where relevant, and a named test exercises it;
- **accepted-risk** — deliberately not addressed further, with written reasoning;
- **open** — everything else, including mitigations that are designed, planned
  or in review. A plan goes in the Mitigation column, not in the status.

## Keeping it true

A pull request that adds, removes or weakens a mitigation updates the row here
in the same pull request. A new threat model adds its threats here when it is
merged. IDs are permanent and never reused. If a row and the code disagree,
the code is right and the row is a bug.

## Sources

| Prefix | Context                  | Source                                                                                                                                                                                                             |
| :----- | :----------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CRED` | Credentials (Phase 04)   | Issue 077's scope — enumeration, brute force, token theft, credential stuffing — plus [Authentication Flows](authentication-flows.md), [Password Storage](password-storage.md), [Token Storage](token-storage.md). |
| `AUD`  | Audit logging (Phase 10) | Issue 195's scope — tampering, silent deletion, subscriber failure / event loss, log injection — plus the audit package and [ADR-0003](../adr/0003-stellar-audit-anchoring.md).                                    |
| `ABAC` | Policy engine (Phase 08) | [Threat Model: Policy Engine & ABAC Evaluation](threat-model-abac.md), IDs mapped one-to-one from that document.                                                                                                   |

**Why the `CRED` and `AUD` rows exist before their threat models do.** The
dedicated documents for Issues 077 (`threat-model-credentials.md`) and 195
(`threat-model-audit.md`) have not been published yet. Rather than leave those
two contexts out — which would make the register report fewer open threats
than there are — their rows are derived here from the issues' defined scope
and from the controls actually present in the code, each checked against the
test that exercises it. When those documents land, they adopt these IDs (adding
new ones as needed) and become the long-form explanation for each row.

**Not yet indexed:** threat models proposed in unmerged pull requests
(sessions, identity verification). They join the register when they merge,
under their own prefixes.

## Summary

| Context   | Mitigated | Accepted risk |   Open |  Total |
| :-------- | --------: | ------------: | -----: | -----: |
| `CRED`    |        10 |             1 |      4 |     15 |
| `AUD`     |         6 |             1 |     10 |     17 |
| `ABAC`    |         0 |             0 |     15 |     15 |
| **Total** |    **16** |         **2** | **29** | **47** |

The number that stands out is `ABAC`: fifteen threats, every one open. That is
not a finding against the ABAC threat model, which is thorough; it is that
`packages/authorization` does not exist on the default branch yet, so every
mitigation it describes is a plan. The register's job is to make that visible
rather than let "Eliminated" in the design document be read as a statement
about the running system.

## Credentials (`CRED`)

Code: `packages/credentials`, routes in `apps/api/src/routes/auth.ts`, wiring
in `apps/api/src/composition-root.ts`. Test paths below are relative to
`packages/credentials/`.

| ID         | Threat                                                                           | STRIDE | Actor                                         | Entry point                              | Mitigation                                                                                                                                                                                                                     | Verification                                                                                                                                                      | Status        |
| :--------- | :------------------------------------------------------------------------------- | :----- | :-------------------------------------------- | :--------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------ |
| `CRED-I-1` | Account enumeration through login error responses                                | I      | Anonymous client                              | `POST /auth/login`                       | One `AuthenticationError` for all six failure reasons (Issue 066)                                                                                                                                                              | `authenticate-with-password.spec.ts` — "returns an identical error for an unknown email and a wrong password"                                                     | mitigated     |
| `CRED-I-2` | Account enumeration through login response timing                                | I      | Anonymous client                              | `POST /auth/login`                       | Decoy argon2 verification when no credential exists                                                                                                                                                                            | `authenticate-with-password.spec.ts` — "does a real hash verification when there is no user to check"                                                             | accepted-risk |
| `CRED-I-3` | Account enumeration through observable lockout                                   | I      | Anonymous client                              | `POST /auth/login`                       | `AccountLockedError` identical to `AuthenticationError` on the wire; hashing continues while locked (Issue 067)                                                                                                                | `authenticate-with-password-lockout.spec.ts` — "is distinct to the caller and identical to a client"                                                              | mitigated     |
| `CRED-I-4` | Account enumeration through reset / verification request endpoints               | I      | Anonymous client                              | Reset and verification request use cases | Both report success unconditionally (Issues 068, 069)                                                                                                                                                                          | `password-reset.spec.ts` — "responds identically whether or not the account exists"; `email-verification.spec.ts` — "succeeds identically for an unknown address" | mitigated     |
| `CRED-I-5` | Account confirmation through reset-token rejection reasons                       | I      | Holder of a stale reset link                  | Reset confirmation                       | Used, expired and unknown tokens rejected identically (Issue 070)                                                                                                                                                              | `password-reset.spec.ts` — "reports every rejection identically, unlike email verification"                                                                       | mitigated     |
| `CRED-I-6` | Offline cracking of password hashes after a database breach                      | I      | Attacker holding a DB dump                    | `credentials` table                      | argon2id with enforced minimum cost; transparent rehash on login (Issues 063, 075)                                                                                                                                             | `infrastructure/argon2-password-hasher.spec.ts` — "rejects parameters that would silently weaken every password"                                                  | mitigated     |
| `CRED-I-7` | Use of reset / verification tokens read from the database                        | I      | Attacker with DB read access                  | Verification and reset token tables      | Only SHA-256 digests stored ([Token Storage](token-storage.md))                                                                                                                                                                | `password-reset.spec.ts` — "stores only the digest"; `email-verification.spec.ts` — "stores only the digest, never the raw token"                                 | mitigated     |
| `CRED-S-1` | Online brute force against a single account                                      | S      | Anonymous client                              | `POST /auth/login`                       | Lockout after five failures, exponential backoff capped at an hour (Issue 067)                                                                                                                                                 | `authenticate-with-password-lockout.spec.ts` — "locks on the Nth consecutive failure", "refuses the correct password while locked"                                | mitigated     |
| `CRED-S-2` | Credential stuffing: few attempts each across many accounts                      | S      | Anonymous client with breached password lists | `POST /auth/login`                       | Per-account lockout does not engage below threshold. `RateLimiter` seam is wired, but `NoopRateLimiter` allows everything until Phase 15                                                                                       | none                                                                                                                                                              | open          |
| `CRED-S-3` | Reuse of a leaked reset or verification link                                     | S      | Anyone who later sees the link                | Reset and verification confirmation      | Single-use, expiring, 256-bit tokens; issuing a new token retires the old one                                                                                                                                                  | `password-reset.spec.ts` — "rejects a reused token", "rejects an expired token", "retires the previous token when a new one is issued"                            | mitigated     |
| `CRED-S-4` | Taking over an account from a hijacked session by changing its password          | S      | Holder of a stolen session                    | `ChangePassword`                         | Current password required (Issue 071)                                                                                                                                                                                          | `change-password.spec.ts` — "rejects wrong current password", "does not change password on wrong current"                                                         | mitigated     |
| `CRED-T-1` | Returning to a compromised password after a forced change                        | T      | Attacker holding an old password              | Reset and change-password                | Password history rejects the last N passwords (Issue 072)                                                                                                                                                                      | `change-password.spec.ts` — "rejects reuse of a password from history on second change"; `password-reset.spec.ts` — "rejects reuse of a password from history"    | mitigated     |
| `CRED-E-1` | Attacker's session survives the victim's password reset                          | E      | Holder of a stolen session                    | Reset confirmation                       | `ConfirmPasswordReset` calls `SessionRevoker`, but the composition root wires `NoSessionsRevoker` until Prisma/Redis session adapters exist ([Authentication Flows](authentication-flows.md#why-a-reset-must-revoke-sessions)) | Use case: `password-reset.spec.ts` — "revokes every existing session". Running app: none                                                                          | open          |
| `CRED-D-1` | Flooding a victim with reset / verification emails, invalidating their real link | D      | Anonymous client                              | Reset and verification request use cases | None until Phase 15 rate limiting (documented as a gap in [Authentication Flows](authentication-flows.md#deliberately-not-solved))                                                                                             | none                                                                                                                                                              | open          |
| `CRED-R-1` | Credential events that cannot be attributed afterwards                           | R      | Any authenticated user denying an action      | Reset, change-password, verification     | Login and registration outcomes are recorded from `apps/api/src/routes/auth.ts`; reset, change and verification are not until the credentials audit subscriber (Issue 185)                                                     | none                                                                                                                                                              | open          |

**`CRED-I-2`, accepted risk.** The decoy removes the order-of-magnitude timing
difference, not all of it; argon2 verification, database hits and JIT warm-up
still vary. A fixed response deadline would close the remainder, and was
rejected as heavier than the threat warrants, because the attacks that scale
against the residual are volume attacks that lockout and rate limiting address
(see [Authentication Flows — What this does not claim](authentication-flows.md#what-this-does-not-claim)).
Revisit if rate limiting slips, since `CRED-S-2` is currently open.

## Audit logging (`AUD`)

Code: `packages/audit`, schema in
`packages/database/prisma/migrations/20260915120000_add_audit_log_and_anchors`,
wiring in `apps/api/src/composition-root.ts`. Test paths below are relative to
`packages/audit/`.

| ID        | Threat                                                                                     | STRIDE | Actor                                             | Entry point                         | Mitigation                                                                                                                                                                       | Verification                                                                                                                 | Status        |
| :-------- | :----------------------------------------------------------------------------------------- | :----- | :------------------------------------------------ | :---------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------- | :------------ |
| `AUD-T-1` | Editing an audit entry in place                                                            | T      | Operator or attacker with DB write                | `audit_log_entries`                 | Hash chain; `verifyChain` recomputes each hash and reports `content_altered`                                                                                                     | `domain/entities/audit-log-entry.spec.ts` — "detects an altered entry"                                                       | mitigated     |
| `AUD-T-2` | Silently deleting an audit entry                                                           | T      | Operator or attacker with DB write                | `audit_log_entries`                 | Successor still commits to the deleted hash (`link_broken`); renumbering caught as `sequence_gap`                                                                                | `audit-log-entry.spec.ts` — "detects a deleted entry", "detects a truncated chain that was renumbered"                       | mitigated     |
| `AUD-T-3` | Application code updating or deleting entries                                              | T      | Buggy or compromised application code             | `AuditLogRepository`                | No update/delete on the entity or port; adapter uses `create`, never `upsert`                                                                                                    | Type-level: the methods do not exist                                                                                         | mitigated     |
| `AUD-T-4` | Direct `UPDATE` / `DELETE` using the application's database credentials                    | T      | Attacker holding the app DB role                  | Postgres                            | None yet: `verixa_app` is granted `UPDATE, DELETE` on all tables (`infra/postgres/02-init-app-role.sh`). `REVOKE` on the audit table is Issue 183                                | none                                                                                                                         | open          |
| `AUD-T-5` | Rewriting the whole chain from a point onward, recomputing every hash                      | T      | Operator or attacker with DB write                | `audit_log_entries`                 | `AnchorAuditLog` commits the head to Stellar, but anchoring is off unless configured and nothing schedules it (Issues 190A, 191)                                                 | `audit-log-entry.spec.ts` — "accepts a chain rewritten wholesale, which is the documented limit" proves the gap, not the fix | open          |
| `AUD-T-6` | Forked chain from concurrent appends                                                       | T      | Two concurrent writers (no attacker needed)       | `RecordAuditEvent`                  | `sequence` is `UNIQUE`; the second insert fails. The control exists, but nothing tests it against Postgres                                                                       | none — the in-memory fake mirrors the rule, which proves the fake, not the index                                             | open          |
| `AUD-T-7` | Metadata crafted to collide in the canonical form, allowing an undetectable edit           | T      | Producer-controlled metadata plus DB write        | `AuditLogEntry.canonicalize`        | None yet: metadata pairs are joined with `\x1F` without escaping, so `{a: "1", b: "2"}` and `{a: "1\x1Fb=2"}` hash identically. Belongs with log-injection hardening (Issue 196) | none                                                                                                                         | open          |
| `AUD-T-8` | Log injection: control characters or CSV delimiters in metadata corrupting exports or logs | T      | Any user whose input reaches metadata             | Export and structured logging       | Metadata stored as JSONB, never string-concatenated into SQL. Export encoding and adversarial fixtures are Issues 189, 196                                                       | none                                                                                                                         | open          |
| `AUD-T-9` | A forged anchor record claiming a commitment that never reached the ledger                 | T      | Crash mid-anchor, or a malicious operator         | `anchor_records`                    | Receipt saved only after the ledger accepts; anyone can re-check with `stellar-anchor verify` ([Stellar Anchoring](../guides/stellar-anchoring.md))                              | `packages/stellar-anchor` contract suite — "does not verify a different hash against the same reference"                     | mitigated     |
| `AUD-S-1` | Back-dating an event with a caller-supplied timestamp                                      | S      | Any producer of audit events                      | `RecordAuditEvent`                  | `RecordAuditEventCommand` has no timestamp field; `occurredAt` is stamped server-side at append                                                                                  | Type-level: the field does not exist                                                                                         | mitigated     |
| `AUD-R-1` | Losing events when an audit write fails                                                    | R      | Attacker able to break audit writes, or an outage | `RecordAuditEvent`                  | Failures swallowed so the audited operation is not falsely failed; reported to stderr by the composition root                                                                    | none                                                                                                                         | accepted-risk |
| `AUD-R-2` | Domain events that never reach the audit log                                               | R      | Any actor in an unsubscribed context              | Domain event publisher              | Subscribers for identity/credentials, sessions/RBAC and startup wiring are Issues 185, 186, 194                                                                                  | none                                                                                                                         | open          |
| `AUD-I-1` | Unauthorized or cross-organization reading of audit history                                | I      | Authenticated user of another tenant              | Query and export use cases          | Permission per organization, cross-organization refusal (Issue 199; in review). No read path exists on the default branch yet                                                    | none on the default branch                                                                                                   | open          |
| `AUD-R-3` | Privileged readers of the audit log leaving no trace                                       | R      | Legitimate auditor or insider                     | Query and export use cases          | Reads recorded as `audit.queried` / `audit.exported` before release, fail-closed (Issue 199; in review)                                                                          | none on the default branch                                                                                                   | open          |
| `AUD-I-2` | Audit contents disclosed through the public anchoring ledger                               | I      | Anyone reading the Stellar ledger                 | Stellar memo                        | Only the SHA-256 head hash is published, never contents (ADR-0003)                                                                                                               | `packages/stellar-anchor` contract suite — "rejects a hash that is not a 64-character hex SHA-256 digest"                    | mitigated     |
| `AUD-I-3` | Theft of the anchoring account's signing key                                               | I      | Anyone who can read process env, dumps or logs    | `STELLAR_ANCHOR_SECRET_KEY`         | KMS-backed signing and rotation runbook are Issue 190B                                                                                                                           | none                                                                                                                         | open          |
| `AUD-D-1` | Event bursts overwhelming audit writes, or anchoring silently stopping unfunded            | D      | Load spike, or an exhausted anchoring account     | Audit write path; anchoring account | Batched writer with bounded backpressure (Issue 193); balance monitoring and loud failure (Issue 190C)                                                                           | none                                                                                                                         | open          |

**`AUD-R-1`, accepted risk.** Audit recording sits beside the operation it
records, not in front of it: a login that succeeded is not reported as failed
because its audit write failed. The cost is that an attacker who can reliably
break audit writes can act unrecorded, and a write that fails leaves no gap in
the chain for `verifyChain` to find — the next write takes the same sequence
number. The compensating control is operational: every failure is reported by
the composition root, so a run of them is visible in process logs. Revisit once
Phase 18 observability exists, at which point a failed audit write should be a
metric with an alert, not a line on stderr. Reads of the audit log are the one
place this trade is reversed (Issue 199), because nothing has happened yet that
a refusal would misreport.

**`AUD-T-7`, found while compiling this register.** The canonical form sorts
metadata keys and joins `key=value` pairs with the ASCII unit separator, which
cannot collide by accident but can be forced by a value that contains the
separator. The consequence is narrow — exploiting it needs both control over a
metadata value at write time and database write access later — but it is
exactly the "undetectable edit" the chain exists to rule out. Escaping or
length-prefixing metadata in the canonical form is a hash-format change and
needs a migration story for existing chains, so it is recorded here and left to
its own issue rather than fixed as a side effect.

## Policy engine (`ABAC`)

Source: [Threat Model: Policy Engine & ABAC Evaluation](threat-model-abac.md).
IDs map one-to-one: `ABAC-S-1` is that document's S-1, and so on. The status
column differs from that document's "Residual Risk Stance" on purpose: it
records the state of the default branch, where `packages/authorization` does
not exist yet. Each row becomes `mitigated` when the named issue merges with a
test for the control.

| ID         | Threat                                             | STRIDE | Actor                                      | Entry point                   | Mitigation (planned)                                    | Status |
| :--------- | :------------------------------------------------- | :----- | :----------------------------------------- | :---------------------------- | :------------------------------------------------------ | :----- |
| `ABAC-S-1` | Client-side attribute forgery                      | S      | Authenticated client                       | Request headers and payload   | Issues 144, 145 — attributes from verified sources only | open   |
| `ABAC-S-2` | Resource attribute impersonation                   | S      | Authenticated client                       | `resourceRef` in PDP calls    | Issue 151 — resolver verifies tenant ownership          | open   |
| `ABAC-T-1` | Malicious or erroneous policy authoring            | T      | Rogue administrator or buggy management UI | Policy DSL                    | Issues 155, 156; versioning in 150                      | open   |
| `ABAC-T-2` | Direct database or cache modification of policies  | T      | Attacker with Postgres or Redis write      | Policy store and cache        | Issues 150, 154; tenant RLS                             | open   |
| `ABAC-T-3` | Parser exploitation through crafted DSL            | T      | Policy author                              | DSL parser                    | Issues 142, 143 — no `eval`, typed AST                  | open   |
| `ABAC-R-1` | Unaudited policy modifications                     | R      | Administrator                              | Policy publish                | Issue 150 — append-only policy versions                 | open   |
| `ABAC-R-2` | Opaque authorization decisions                     | R      | Any                                        | Policy decision point         | Issue 153 — structured decision record                  | open   |
| `ABAC-I-1` | Side-channel leakage through PDP error messages    | I      | Authenticated client                       | Authorization API responses   | Issue 153 — generic reason codes                        | open   |
| `ABAC-I-2` | Timing side channels in attribute resolution       | I      | Authenticated client                       | Attribute resolution pipeline | Issue 145 — short-circuit ordering                      | open   |
| `ABAC-D-1` | CPU exhaustion through complex conditions or ReDoS | D      | Policy author or client                    | Evaluation engine             | Issues 146, 147, 156                                    | open   |
| `ABAC-D-2` | Exhaustion of downstream attribute providers       | D      | High-volume client                         | Attribute resolution pipeline | Issues 152, 154 — RBAC fast path, caching               | open   |
| `ABAC-D-3` | Cache invalidation stampede                        | D      | Administrator publishing a hot policy      | Policy cache                  | Issue 154 — single-flight reload                        | open   |
| `ABAC-E-1` | RBAC permit overriding an ABAC deny                | E      | Authenticated user with a broad role       | Composition service           | Issue 152 — ABAC deny always wins                       | open   |
| `ABAC-E-2` | Wrong combining algorithm selected                 | E      | Policy author                              | Policy sets                   | Issue 148 — `deny-overrides` default                    | open   |
| `ABAC-E-3` | Stale cache granting revoked access                | E      | User whose access was revoked              | Policy cache                  | Issue 154 — invalidation on publish                     | open   |

The source document also lists three accepted risks (regex capability in
policies, cache-outage fallback latency, intra-request attribute staleness).
They are design decisions for a component that does not exist yet, so they
are recorded there and will be added here as `accepted-risk` rows, with their
reasoning, when the mitigations they qualify are merged.

## Related documentation

- [Threat Model Template](threat-model-template.md)
- [Threat Model: Policy Engine & ABAC Evaluation](threat-model-abac.md)
- [Authentication Flows](authentication-flows.md)
- [Phase 11 specification](../../planning/issues/phase-11-security-hardening.md)
