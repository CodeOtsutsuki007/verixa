import { randomUUID } from "node:crypto";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createTestPrismaClient, databaseAvailability } from "./helpers/database.js";

/**
 * Verifies each filter path in `PrismaAuditLogRepository.findWithFilters`
 * (Issue 187) is served by an index rather than a sequential scan (Issue 188).
 *
 * ## Why this seeds thousands of rows
 *
 * On a small table Postgres correctly prefers a sequential scan — reading a
 * few heap pages beats descending a B-tree and then visiting the heap anyway.
 * Asserting "index scan" against a hand-written three-row fixture would fail
 * for the right reason, and forcing the planner with `enable_seqscan = off`
 * would only prove Postgres obeys orders. Seeding past the point where a scan
 * stops being cheap is what makes the assertion a test of the schema: the
 * planner chooses the index freely.
 *
 * ## Why the target predicate is selective
 *
 * The same trap in the other direction: if the target actor owned every row,
 * `WHERE actor_id = $1` would match the whole table, a sequential scan would
 * be the faster plan, and demanding an index would demand the planner be
 * wrong. Each target value below owns a small slice of the table, so an index
 * is genuinely the better answer and selectivity — not luck — is what the
 * assertion rides on.
 *
 * The one filter path not asserted here is `organizationId`, which lives in
 * the JSON `metadata` column. `metadata->>'organizationId' = ?` cannot use a
 * plain B-tree, and Prisma's schema cannot express the functional index that
 * would cover it, so it stays a documented limitation rather than a passing
 * test — see docs/performance/audit-query-benchmarks.md.
 */
const available = await databaseAvailability();

const ROW_COUNT = 5000;
const TARGET_ROWS = 50;
const TARGET_ACTOR_ID = "00000000-0000-4000-9000-0000000000a1";
const TARGET_SUBJECT_ID = "00000000-0000-4000-9000-0000000000b1";
const TARGET_ACTION = "user.login_failed";

interface PlanRow {
  readonly "QUERY PLAN": string;
}

describe.skipIf(!available)("audit query index usage (Issue 188)", () => {
  const prisma = createTestPrismaClient();

  /**
   * Runs EXPLAIN and returns the plan as one string.
   *
   * Every parameter carries an explicit `::type` cast. `$queryRawUnsafe` binds
   * parameters as `text`; without a cast, `WHERE actor_id = $1` compares a
   * `uuid` column against `text`, which Postgres resolves by casting the
   * *column* — producing a plan that reads `(actor_id)::text = ...` and
   * seq-scans because an index on `actor_id` cannot answer a query about
   * `actor_id::text`. Casting the parameter instead of the column is what
   * makes this measure the schema.
   */
  async function explain(sql: string, ...params: unknown[]): Promise<string> {
    const rows = await prisma.$queryRawUnsafe<PlanRow[]>(`EXPLAIN ${sql}`, ...params);
    return rows.map((row) => row["QUERY PLAN"]).join("\n");
  }

  /** All three of these are index access; which one wins is the planner's call. */
  function expectIndexed(plan: string, table: string): void {
    const usesIndex = /Index (Only )?Scan|Bitmap Index Scan/.test(plan);
    expect(usesIndex, `Expected an index scan on ${table}, got:\n${plan}`).toBe(true);
  }

  beforeAll(async () => {
    await prisma.auditLogEntry.deleteMany({});

    const baseTime = new Date("2026-01-01T00:00:00.000Z").getTime();
    const rows = Array.from({ length: ROW_COUNT }, (_unused, offset) => {
      // The first TARGET_ROWS rows carry each target value; the rest are
      // spread over random values so no target owns more than a small slice.
      const isTarget = offset < TARGET_ROWS;
      return {
        id: randomUUID(),
        sequence: offset + 1,
        action: isTarget && offset % 2 === 0 ? TARGET_ACTION : "user.login_succeeded",
        actorId: isTarget ? TARGET_ACTOR_ID : randomUUID(),
        subjectId: isTarget ? TARGET_SUBJECT_ID : randomUUID(),
        metadata: { organizationId: randomUUID() },
        // Spread two hours; the target window below is the first minute.
        occurredAt: new Date(baseTime + offset * 1_500),
        previousHash: randomUUID().replace(/-/g, "").repeat(2),
        hash: `${randomUUID().replace(/-/g, "")}${randomUUID().replace(/-/g, "")}`,
      };
    });

    await prisma.auditLogEntry.createMany({ data: rows });

    // The planner works from statistics. Without fresh ones it may choose a
    // scan regardless of the indexes, making this a test of table staleness
    // rather than of the schema.
    await prisma.$executeRawUnsafe("ANALYZE audit_log_entries;");
  }, 180_000);

  afterAll(async () => {
    await prisma.auditLogEntry.deleteMany({});
    await prisma.$disconnect();
  }, 120_000);

  it("filters by actor using the (actor_id, sequence) index", async () => {
    const plan = await explain(
      "SELECT * FROM audit_log_entries WHERE sequence >= $1::int AND actor_id = $2::uuid ORDER BY sequence ASC LIMIT 50",
      1,
      TARGET_ACTOR_ID,
    );

    expectIndexed(plan, "audit_log_entries");
    expect(plan).not.toMatch(/Sort/);
  });

  it("filters by subject using the (subject_id, sequence) index", async () => {
    const plan = await explain(
      "SELECT * FROM audit_log_entries WHERE sequence >= $1::int AND subject_id = $2::uuid ORDER BY sequence ASC LIMIT 50",
      1,
      TARGET_SUBJECT_ID,
    );

    expectIndexed(plan, "audit_log_entries");
    expect(plan).not.toMatch(/Sort/);
  });

  it("filters by action using the (action, sequence) index", async () => {
    const plan = await explain(
      "SELECT * FROM audit_log_entries WHERE sequence >= $1::int AND action = $2::text ORDER BY sequence ASC LIMIT 50",
      1,
      TARGET_ACTION,
    );

    expectIndexed(plan, "audit_log_entries");
    expect(plan).not.toMatch(/Sort/);
  });

  it("filters by date range using the (occurred_at, sequence) index", async () => {
    // A selectively narrow tail of the spread, not "everything after the
    // epoch": a predicate matching most of the table is supposed to seq-scan.
    const windowStart = new Date(
      new Date("2026-01-01T00:00:00.000Z").getTime() + (ROW_COUNT - TARGET_ROWS) * 1_500,
    );

    const plan = await explain(
      "SELECT * FROM audit_log_entries WHERE sequence >= $1::int AND occurred_at >= $2::timestamptz ORDER BY sequence ASC LIMIT 50",
      1,
      windowStart,
    );

    // No "no Sort" assertion here, deliberately: the index is ordered by
    // (occurred_at, sequence), so a range on occurred_at leaves `sequence`
    // unordered and a sort is expected. It is the actor/subject/action paths —
    // equality on the leading column — that get ordering for free.
    expectIndexed(plan, "audit_log_entries");
  });

  it("walks the keyset via the unique sequence index", async () => {
    const plan = await explain(
      "SELECT * FROM audit_log_entries WHERE sequence >= $1::int ORDER BY sequence ASC LIMIT 50",
      ROW_COUNT - 100,
    );

    expectIndexed(plan, "audit_log_entries");
    expect(plan).not.toMatch(/Sort/);
  });
});
