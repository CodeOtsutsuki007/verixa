import { randomUUID } from "node:crypto";

import { PrismaClient } from "@prisma/client";

/**
 * Seeds the audit log at scale and reports the plan each query path gets
 * (Issue 188).
 *
 *   BENCH_ROWS=100000 pnpm --filter @verixa/database run benchmark:audit
 *
 * ## What this is for
 *
 * The index-usage test (`tests/integration/audit-query-index-usage.spec.ts`)
 * asserts that each path uses an index at a few thousand rows. This script is
 * the larger, manual counterpart: it seeds six figures, runs `EXPLAIN
 * (ANALYZE, BUFFERS)` for every filter path, and prints the real plans and
 * row estimates. That is the evidence the issue asks for, and it is the step
 * that catches a plan regression the smaller test is too small to trigger —
 * the planner switches strategies at scale, and a path that indexes at 5k
 * rows can flip to a scan at 500k.
 *
 * ## Why it is not part of the CI gate
 *
 * Seeding and analyzing six figures is minutes of work, not seconds, and the
 * result depends on the machine. A benchmark in CI would either be a flaky
 * gate or a number nobody trusts. The integration test stays in the gate; this
 * stays a tool you run when you change a query or an index.
 *
 * ## Reproducing the documented numbers
 *
 * See `docs/performance/audit-query-benchmarks.md`. Bring up Postgres
 * (`docker compose up -d postgres`), apply migrations, then run the command
 * above. The script cleans up the rows it seeded on exit.
 */
const ROWS = Number(process.env["BENCH_ROWS"] ?? 100_000);
const MARKER = "issue-188-benchmark";
const TARGET_ROWS = Math.max(50, Math.round(ROWS * 0.001));
const TARGET_ACTOR_ID = "00000000-0000-4000-9000-0000000000a1";
const TARGET_SUBJECT_ID = "00000000-0000-4000-9000-0000000000b1";
const TARGET_ACTION = "user.login_failed";
const BASE_TIME = new Date("2026-01-01T00:00:00.000Z").getTime();
const STEP_MS = 1_500;

interface PlanRow {
  readonly "QUERY PLAN": string;
}

const databaseUrl = process.env["DATABASE_URL"] ?? "postgres://verixa:verixa@localhost:5432/verixa";
const prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });

async function seed(): Promise<void> {
  const batchSize = 5_000;

  for (let start = 0; start < ROWS; start += batchSize) {
    const end = Math.min(start + batchSize, ROWS);
    const batch = Array.from({ length: end - start }, (_unused, offsetInBatch) => {
      const offset = start + offsetInBatch;
      const isTarget = offset < TARGET_ROWS;
      return {
        id: randomUUID(),
        sequence: offset + 1,
        action: isTarget && offset % 2 === 0 ? TARGET_ACTION : "user.login_succeeded",
        actorId: isTarget ? TARGET_ACTOR_ID : randomUUID(),
        subjectId: isTarget ? TARGET_SUBJECT_ID : randomUUID(),
        // The JSON metadata carries the organisation, as the real subscriber
        // writes it. It also carries the marker this script deletes by.
        metadata: { organizationId: randomUUID(), benchmark: MARKER },
        occurredAt: new Date(BASE_TIME + offset * STEP_MS),
        previousHash: randomUUID().replace(/-/g, "").repeat(2),
        hash: `${randomUUID().replace(/-/g, "")}${randomUUID().replace(/-/g, "")}`,
      };
    });

    await prisma.auditLogEntry.createMany({ data: batch });
    process.stdout.write(`\rseeded ${String(end)}/${String(ROWS)}`);
  }

  process.stdout.write("\n");
  await prisma.$executeRawUnsafe("ANALYZE audit_log_entries;");
}

async function explain(label: string, sql: string, ...params: unknown[]): Promise<void> {
  const started = performance.now();
  const rows = await prisma.$queryRawUnsafe<PlanRow[]>(
    `EXPLAIN (ANALYZE, BUFFERS) ${sql}`,
    ...params,
  );
  const elapsed = performance.now() - started;
  const plan = rows.map((row) => row["QUERY PLAN"]).join("\n");

  console.log(`\n## ${label}\n`);
  console.log(plan);

  const seqScan = /Seq Scan/.test(plan);
  const sort = /Sort Method|Sort\s+\(/.test(plan);
  console.log(
    `\nwall clock (incl. round trip): ${elapsed.toFixed(1)} ms` +
      ` | sequential scan: ${seqScan ? "YES" : "no"}` +
      ` | explicit sort: ${sort ? "yes" : "no"}`,
  );
}

async function cleanup(): Promise<void> {
  await prisma.auditLogEntry.deleteMany({
    where: { metadata: { path: ["benchmark"], equals: MARKER } },
  });
}

async function main(): Promise<void> {
  try {
    await prisma.$connect();
    console.log(`Benchmarking audit queries against ${databaseUrl.replace(/:[^:@]*@/, ":***@")}`);
    console.log(`Seeding ${String(ROWS)} rows (target slice: ${String(TARGET_ROWS)})\n`);

    await cleanup();
    await seed();

    const windowStart = new Date(BASE_TIME + (ROWS - TARGET_ROWS) * STEP_MS);

    await explain(
      "actor filter — (actor_id, sequence)",
      "SELECT * FROM audit_log_entries WHERE sequence >= $1::int AND actor_id = $2::uuid ORDER BY sequence ASC LIMIT 50",
      1,
      TARGET_ACTOR_ID,
    );
    await explain(
      "subject filter — (subject_id, sequence)",
      "SELECT * FROM audit_log_entries WHERE sequence >= $1::int AND subject_id = $2::uuid ORDER BY sequence ASC LIMIT 50",
      1,
      TARGET_SUBJECT_ID,
    );
    await explain(
      "action filter — (action, sequence)",
      "SELECT * FROM audit_log_entries WHERE sequence >= $1::int AND action = $2::text ORDER BY sequence ASC LIMIT 50",
      1,
      TARGET_ACTION,
    );
    await explain(
      "date range — (occurred_at, sequence)",
      "SELECT * FROM audit_log_entries WHERE sequence >= $1::int AND occurred_at >= $2::timestamptz ORDER BY sequence ASC LIMIT 50",
      1,
      windowStart,
    );
    await explain(
      "keyset only — unique (sequence)",
      "SELECT * FROM audit_log_entries WHERE sequence >= $1::int ORDER BY sequence ASC LIMIT 50",
      ROWS - 100,
    );
    await explain(
      "organisation metadata (known limitation: no index)",
      "SELECT * FROM audit_log_entries WHERE sequence >= $1::int AND metadata->>'organizationId' = $2::text ORDER BY sequence ASC LIMIT 50",
      1,
      "no-such-organisation",
    );
  } finally {
    await cleanup();
    await prisma.$disconnect();
  }
}

main().catch((error: unknown) => {
  console.error("Benchmark failed:", error);
  process.exitCode = 1;
});
