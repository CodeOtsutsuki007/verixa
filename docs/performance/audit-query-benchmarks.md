# Audit Query Benchmarks

Evidence for Issue 188 — the audit log's read paths stay index-backed as the
table grows. Recorded with `pnpm db:benchmark:audit` (alias for
`BENCH_ROWS=100000 pnpm --filter @verixa/database run benchmark:audit`).

This is the large, manual companion to
`tests/integration/audit-query-index-usage.spec.ts`, which asserts the same
paths use an index at a few thousand rows in CI. The test is the gate; this
script seeds six figures and prints `EXPLAIN (ANALYZE, BUFFERS)` for each path,
because the planner changes strategy at scale and a path that indexes at 5k
rows can flip to a scan at 500k.

## The query shapes

Every read goes through `PrismaAuditLogRepository.findWithFilters`
(`packages/audit/infrastructure/persistence/prisma-audit-repositories.ts`),
which always filters `sequence >= fromSequence`, optionally narrows by one of
`actor_id` / `subject_id` / `action` / a `occurred_at` range / the
`organizationId` JSON field, and always orders by `sequence ASC LIMIT n`. The
cursor column is `sequence`, not time — that is the shape the indexes have to
serve.

## The indexes

| Query path  | Index                              |
| ----------- | ---------------------------------- |
| actor       | `(actor_id, sequence)`             |
| subject     | `(subject_id, sequence)`           |
| action      | `(action, sequence)`               |
| date range  | `(occurred_at, sequence)`          |
| keyset only | unique `(sequence)` (pre-existing) |

Leading with the equality column and putting `sequence` second lets the
planner satisfy both the filter and the ordering from one index, so the
actor/subject/action paths need no sort. The range path still sorts, and
correctly so: a range on `occurred_at` leaves `sequence` unordered within the
index.

The single-column indexes on `occurred_at`, `actor_id` and `subject_id` were
dropped. A B-tree on `(a, b)` already answers `WHERE a = ?`, so keeping both
only added write cost to an append-only table — the one write path the audit
log has.

## How to record a run

```bash
docker compose up -d postgres
pnpm db:migrate:deploy
BENCH_ROWS=100000 pnpm db:benchmark:audit
```

The script seeds, runs `ANALYZE` (without fresh statistics the planner works
from defaults and the numbers mean nothing), prints each plan, and deletes the
rows it seeded on exit.

## Results

**Not yet recorded on this machine.** The table is deliberately empty rather
than filled with numbers copied from a run on different hardware — see the
warning in `docs/performance/baseline.md`, which applies here unchanged. A
benchmark number is only meaningful compared against itself, on the same
machine, measured the same way. Record your own before changing a query or an
index, and compare like with like.

| Path        | ≥100k rows config | Plan        | Sequential scan | Explicit sort |
| ----------- | ----------------- | ----------- | --------------- | ------------- |
| actor       | _to record_       | _to record_ | _to record_     | _to record_   |
| subject     | _to record_       | _to record_ | _to record_     | _to record_   |
| action      | _to record_       | _to record_ | _to record_     | _to record_   |
| date range  | _to record_       | _to record_ | _to record_     | expected: yes |
| keyset only | _to record_       | _to record_ | _to record_     | _to record_   |

**Environment:** _to be filled in when recorded — CPU, RAM, Postgres version,
containerized or not, local or remote._

## Known limitation: the `organizationId` filter

`organizationId` is stored inside the JSON `metadata` column, and
`findWithFilters` compares `metadata->>'organizationId' = ?`. That expression
cannot use a plain B-tree, and Prisma's `schema.prisma` cannot express the
functional index (`((metadata->>'organizationId'), sequence)`) that would
cover it. The path is therefore not index-backed today.

This is a deliberate stop rather than an oversight. The alternatives were:

- **A raw functional index added only in a migration.** It would make the
  query fast, but `prisma migrate diff` (the `db:drift` CI check) compares
  migrations against `schema.prisma`; an index the schema cannot express shows
  up as drift and fails the build. Prisma is the source of truth here, so an
  index it cannot model does not belong in the migration.
- **A first-class `organization_id` column**, populated from the event on
  append. That is the right long-term shape, but it belongs with the Phase 10
  `AuditEvent` persistence that does not exist yet (`AuditEvent` is a domain
  entity with no table). Adding it under Issue 188 would be a schema and
  mapper change the issue did not ask for.

The filter still works; it just falls back to reading the table. It should be
revisited when `AuditEvent` gains persistence, at which point the organisation
becomes a real column and the composite index becomes expressible.
