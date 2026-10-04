# Tutorial: Building a Tamper-Evident Audit Log

This walkthrough builds Verixa's audit trail (`packages/audit`) from the
question it exists to answer: _after something goes wrong, can we prove what
happened — even to someone who does not trust us?_

Every claim below points at the code or test that makes it true. Where the
code does not yet do something the design calls for, this guide says so and
names the roadmap issue that will; a tutorial that describes the finished
system as though it already existed would be teaching the wrong lesson about
audit logs in particular.

## 1. Why an audit log is not just a table

Most tables exist to be changed. A `users` row is updated when someone
changes their name; that is the point of it. An audit log is the opposite: it
is a record of facts that were true at a moment, and a fact does not get
"updated". If a login happened at 09:14, it happened at 09:14 forever.

That difference changes what we are defending against. A CRUD threat model
asks "who may write this row?". An audit log's threat model asks "who may
_rewrite history_, and would we notice?" — and the most dangerous answer is
someone with legitimate write access to the database: an insider, a
compromised service account, or an attacker who has already got in and now
wants to erase the evidence of how.

So the design has three layers, each covering what the previous one cannot:

| Layer              | Stops                                           | Cannot stop                                     |
| :----------------- | :---------------------------------------------- | :---------------------------------------------- |
| Append-only        | Honest code editing or deleting entries         | Anyone who bypasses the code and edits the rows |
| Hash chain         | Undetected edits and deletions of single rows   | A full rewrite of the chain from a point onward |
| External anchoring | A full rewrite, once the head has been anchored | Tampering since the most recent anchor          |

The rest of this guide builds them in that order.

## 2. Append-only: make the wrong operation unrepresentable

The cheapest defence is to make sure no code path _can_ modify an entry.
Not "we agreed not to" — there is simply no method to call.

**The entity has no mutators.**
[`AuditLogEntry`](../../../packages/audit/domain/entities/audit-log-entry.ts)
has `readonly` fields, a private constructor, and exactly two factories:
`append` (a new link at the end of a chain) and `reconstitute` (rebuilding a
row already read from the database). There is no `update`, no setter, and no
way to construct an entry at an arbitrary position.

**The port has no update or delete.**
[`AuditLogRepository`](../../../packages/audit/application/ports/audit-log-repository.ts)
offers `findLatest`, `append`, `findFrom` and `count`. The comment on it gives
the reason directly: a port offering a way to break append-only would make the
hash chain decorative, because "the first person in a hurry would reach for
it". Retention and erasure (Phase 24) are real requirements, and they will
arrive as an explicit, auditable operation rather than a method that was
quietly always there.

**The adapter uses `create`, never `upsert`.**
[`PrismaAuditLogRepository.append`](../../../packages/audit/infrastructure/persistence/prisma-audit-repositories.ts)
explains why: an upsert would silently overwrite an existing entry at the same
sequence — the one operation this table must refuse.

**The database refuses duplicates.** The
[migration](../../../packages/database/prisma/migrations/20260915120000_add_audit_log_and_anchors/migration.sql)
makes `sequence` _unique_, not merely indexed. Two concurrent appends both
read the same predecessor and both build an entry claiming the next sequence;
without the constraint both would commit and the chain would fork. With it,
the second insert fails. The in-memory fake
([`InMemoryAuditLogRepository`](../../../packages/audit/infrastructure/testing/in-memory-audit-repositories.ts))
enforces the same rule, so tests cannot pass against a forked chain that
production would have rejected.

**What is not built yet.** Everything above protects against _code_. Someone
connecting with `psql` can still run `UPDATE audit_log_entries ...`, because
the application's database role is still granted `UPDATE` and `DELETE` on
every table, this one included (`infra/postgres/02-init-app-role.sh`). Revoking those grants in a migration is Issue 183. Until then, the
next layer is what catches a direct edit.

## 3. The hash chain: making tampering visible

Append-only in code does nothing against someone who edits rows directly. We
cannot stop them, but we can make sure they cannot do it _quietly_.

### The mechanism

Each entry stores two hashes:

- `previousHash` — the `hash` of the entry before it, or
  [`GENESIS_HASH`](../../../packages/audit/domain/entities/audit-log-entry.ts)
  (64 zeroes) for the first entry;
- `hash` — `SHA-256` over this entry's content _including_ `previousHash`.

Because every hash covers its predecessor's hash, each entry commits to the
entire history before it. Change one field in entry 40 and its hash no longer
matches its content; fix up its hash and entry 41's `previousHash` no longer
matches; fix that and entry 41's own hash breaks — all the way to the head.
One edit becomes a rewrite of everything after it.

`append` takes the predecessor _entry_, not a bare hash. A caller cannot link
to a hash they made up; they have to have actually read the tail of the log.
[`RecordAuditEvent`](../../../packages/audit/application/use-cases/record-audit-event.ts)
is the one place that does that, and it is the entry point every producer is
given — nothing outside the package should be building entries itself.

### Canonical serialization: the part that is easy to get wrong

A hash is only useful if someone else can recompute it — possibly years from
now, possibly in another language, from the stored columns alone. That rules
out the obvious implementation, `sha256(JSON.stringify(entry))`, because
`JSON.stringify` output depends on JavaScript's property insertion order, which
is an accident of how the object happened to be built.

`AuditLogEntry.canonicalize` instead fixes the field order, sorts metadata
keys, and joins fields with newlines in a fixed count. The tests pin down each
property, and each one is a bug somebody has shipped somewhere:

- "hashes metadata independently of key insertion order" — two builds of the
  same entry must hash identically;
- "does not let different field values collide through concatenation" — an
  actor of `ab` with a subject of `c` must not hash the same as an actor of `a`
  with a subject of `bc`;
- "gives different hashes to entries differing only in one field".

All three are in
[`audit-log-entry.spec.ts`](../../../packages/audit/domain/entities/audit-log-entry.spec.ts).

### Tamper-evident is not tamper-proof

The chain makes tampering _detectable_. It does not make it impossible, and it
is worth saying precisely how it fails: an attacker with full write access can
rewrite the chain from any point forward, recomputing every hash. The result
is internally consistent and indistinguishable from the truth. There is a test
that asserts exactly this — "accepts a chain rewritten wholesale, which is the
documented limit" — because a limitation that is tested is one nobody can
forget about.

"We hash-chain our audit log" is often presented as though it were the whole
answer. Section 5 is why it is not.

## 4. Verification: turning a property into a check

A hash chain that nobody verifies proves nothing. Tamper evidence has to be
something you can _run_.

[`verifyChain`](../../../packages/audit/domain/entities/audit-log-entry.ts)
walks entries in order and reports the first break, as one of three distinct
reasons, because they mean different things to an investigator:

| Reason            | What it looks like                                   | Typical cause               |
| :---------------- | :--------------------------------------------------- | :-------------------------- |
| `content_altered` | An entry's stored hash no longer matches its content | A row was edited            |
| `link_broken`     | An intact entry does not follow its predecessor      | A row was deleted           |
| `sequence_gap`    | Numbering skips even though the hashes were fixed up | A deletion that was covered |

It reports only the _first_ break. Everything after an altered entry
mismatches as a consequence, and listing every downstream failure would bury
the one fact that matters under noise it caused. The tests "detects an
altered entry", "detects a deleted entry", "detects a truncated chain that was
renumbered" and "reports only the first break" cover each case, using the
fake repository's test-only `tamper` and `remove` methods — deliberately absent
from the port, because production code must have no way to do what those
methods do.

Crucially, `hasValidHash` _recomputes_ the digest from the content rather than
trusting the stored one. A stored hash read back and compared with itself
proves nothing: whoever edited the row edited the hash too.

A note on failure: when an audit write fails,
[`RecordAuditEvent`](../../../packages/audit/application/use-cases/record-audit-event.ts)
swallows the error rather than failing the user's already-completed login.
That is a real trade, and worth being precise about. A write that _fails_
leaves no mark in the chain at all — the next successful write simply takes
the same sequence number — so an attacker who can reliably break audit writes
can act unrecorded. What keeps that from being invisible is operational, not
cryptographic: the composition root (`apps/api/src/composition-root.ts`)
reports every failed write, so a run of them surfaces in the process logs. An
entry that _was_ written and later removed is a different matter; that is
exactly what `link_broken` catches.

**What is not built yet.** `verifyChain` is a function, not yet an operational
tool. The `VerifyAuditChain` use case and a `pnpm audit:verify-chain` command
that pages through the database and reports divergence are Issue 191.

## 5. Anchoring: taking the only copy away from the operator

The chain's weakness is that the operator holds the only copy. The fix is to
put a copy of _one hash_ somewhere the operator cannot rewrite.

[`AnchorAuditLog`](../../../packages/audit/application/use-cases/anchor-audit-log.ts)
periodically submits the current head hash to the Stellar public ledger
through the `HashAnchorPort`, and records the transaction reference in
`anchor_records`. Because the head hash commits to every entry beneath it,
anchoring one hash commits the whole log up to that point. A rewrite now also
has to alter a public ledger entry, which the operator cannot do — and anyone
can check, with no access to Verixa and no need to trust it.

Three details repay attention:

- **Only the hash is published.** Audit contents are precisely the records
  most likely to be sensitive; putting them on a public ledger would be an
  irreversible leak. A digest proves the records existed unchanged while
  revealing nothing about them.
- **The receipt is saved after the ledger accepts it**, never before. The
  reverse order lets a crash leave a record claiming an anchor that does not
  exist — a false proof, which is worse than a missing one.
- **Anchoring is periodic, not per entry.** One transaction per login would
  cost a fee and seconds each time for almost no benefit. The interval between
  anchors is the window in which undetected tampering is possible, and it is a
  knob an operator can turn.

The full decision, including the alternatives rejected, is
[ADR-0003](../../adr/0003-stellar-audit-anchoring.md); the operational guide
is [Stellar Anchoring](../stellar-anchoring.md). To watch the whole loop —
record, chain, anchor, then verify from the public ledger as a third party
would — run the demo in `packages/audit/scripts/anchor-demo.ts`:

```sh
pnpm --filter @verixa/audit demo
```

## 6. Reading the log: usability without new leaks

A write-only audit log is a compliance checkbox. To be useful, people have to
be able to query it and export it — and every way of reading it is a new way to
leak it. The design goal is that reading must never weaken what sections 2–5
built.

### Reads never touch the write path

Queries go through
[`AuditEventReader`](../../../packages/audit/application/ports/audit-event-reader.ts),
a separate port from `AuditLogRepository`. The repository must stay unscoped,
because appending and verification operate on the whole chain. The reader must
never be unscoped, because it answers one organization's questions about its
own history. Its criteria make `organizationId` _required_, and the use cases
fill it from the authorized organization rather than from caller input, so an
adapter never receives an unscoped read.

### Reading is privileged, and is itself audited

[`QueryAuditEvents`](../../../packages/audit/application/use-cases/query-audit-events.ts)
and
[`ExportAuditEvents`](../../../packages/audit/application/use-cases/export-audit-events.ts)
both go through
[`authorizeAndRecordAuditRead`](../../../packages/audit/application/audit-read-access.ts):
check `audit:query` or `audit:export` within the requested organization,
refuse any other organization, then append an `audit.queried` or
`audit.exported` entry _before_ returning anything. Refusals are recorded as
`audit.access_denied`.

The access log lives in the same hash chain as everything else. An auditor
who reads the log and then wants to hide having done so faces the same problem
as anyone else trying to remove an entry: `verifyChain` reports a
`link_broken` at the gap, and once the head has been anchored, a rewritten
chain no longer matches the hash on the ledger.

The full reasoning, including why cross-organization requests are refused
rather than silently rescoped and why a read that cannot be recorded is
refused, is in
[Audit Log Integrity](../../security/audit-log-integrity.md).

### Export streams, and is recorded when it starts

An organization's audit history grows without bound. An export that builds the
whole result in memory before sending it works in development and takes the
process down the first time a compliance request covers three years. So
`AuditEventReader.stream` returns an `AsyncIterable`, and `ExportAuditEvents`
hands that iterable back rather than an array: entries flow from storage to the
response one at a time, and memory use is bounded by the chunk, not the
history. Encoding each entry as CSV or JSON as it passes through belongs to
the interface layer.

The `audit.exported` entry is written before the first row is released, not
after the last. "Record a successful export" reads naturally as "record it on
completion", but rows leave the system from the first chunk; a client that
disconnects one row from the end would otherwise have taken almost everything
and left no trace. The test "records a successful export as an audit event
before any entry is released" asserts that the record exists while the stream
is still unconsumed.

### What an export can and cannot prove

Every exported entry carries its `hash` and `previousHash`. Each entry's own
hash can be recomputed from its content, so a recipient can check that no
individual entry was altered after it was written. But a _filtered_ export is
not contiguous — it skips every entry that did not match — so the links
between exported entries do not chain, and `verifyChain` over a filtered
export reports `link_broken` on the first gap. That is correct behaviour, not
a bug: proving that nothing was _removed_ requires the contiguous chain, which
is why verification walks the unscoped `AuditLogRepository` and anchoring
commits to the head of the whole log rather than to any one organization's
slice of it.

**What is not built yet.** The reader port and the access rules exist; the
production adapters behind them do not. Filter semantics, index-backed keyset
pagination (Issues 187, 188) and a memory-bounded Postgres streaming adapter
with CSV/JSON encoding (Issue 189) plug into `AuditEventReader`. Audit entries
do not yet carry an `organizationId` column (Issue 181), and the chain is
currently one global chain rather than one per organization (Issue 190).

## 7. What to take away

- **Append-only is enforced by the shape of the code**, not by convention: no
  mutator on the entity, no update on the port, `create` not `upsert`, and a
  unique constraint where the race lives. The database-grant backstop is still
  to come.
- **A hash chain gives tamper evidence, not tamper proofing.** It is only as
  good as the verification that runs over it, and it cannot tell a full
  rewrite from the truth on its own.
- **Anchoring removes the operator's monopoly on the evidence** by publishing
  one hash, never the contents, somewhere the operator cannot edit.
- **Every read path is a potential leak.** Reading the audit log requires its
  own permission, is refused across organizations, is recorded in the chain it
  reads, and fails closed when it cannot be recorded.
- **Stream anything that grows without bound**, and audit disclosure at the
  moment it starts.

## Related documentation

- [Audit Log Integrity](../../security/audit-log-integrity.md) — access
  control and self-auditing of reads.
- [ADR-0003: External audit-log anchoring via Stellar](../../adr/0003-stellar-audit-anchoring.md)
- [Stellar Anchoring](../stellar-anchoring.md) — operating the anchor.
- [Domain Modeling](../domain-modeling.md) — the layering and package-encapsulation
  rules this package follows.
- [Phase 10 specification](../../../planning/issues/phase-10-audit-logging.md)
