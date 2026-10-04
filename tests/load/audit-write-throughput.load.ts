import {
  type AuditDelegate,
  type AuditLogEntry,
  AuditLogEntryMapper,
  type AuditLogRepository,
  type AuditTransaction,
  BatchedAuditWriter,
  ChainConflictError,
  GENESIS_HASH,
  InMemoryAuditLogRepository,
  PrismaAuditLogRepository,
  RecordAuditEvent,
  type RecordAuditEventCommand,
  verifyChain,
} from "@verixa/audit";
import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import {
  createTestPrismaClient,
  databaseAvailability,
  testDatabaseUrl,
} from "../integration/helpers/database.js";

/**
 * Load test for the audit write path (Issue #134).
 *
 * Not part of the default CI run: it exists to produce numbers, and numbers
 * taken from a shared CI runner are not comparable to anything (`docs/
 * performance/baseline.md` makes that argument at length). Run it explicitly
 * with `pnpm test:load`.
 *
 * Two suites, because they answer different questions:
 *
 * 1. **Round trips**, measured against an instrumented repository with a stated
 *    per-statement latency. Deterministic, runs anywhere, and shows *why*
 *    batching wins: the cost is per round trip, and batching changes how many
 *    there are. The latency is a model, so the millisecond column is a model
 *    too — it is the ratio and the statement counts that are the finding.
 * 2. **Postgres**, when one is reachable. This is where a real number comes
 *    from, and it is the only suite whose timings belong in a document.
 *
 * Both suites assert chain integrity as well as throughput. A faster audit log
 * whose hash chain does not verify is not an optimization.
 */

const EVENTS = 2_000;
const BATCH_SIZE = 50;

/**
 * The assumed cost of one database round trip, in milliseconds.
 *
 * A model, not a measurement — see `docs/performance/baseline.md` for why no
 * single number is portable. Its only job is to make the *statement count*
 * difference show up in a timing, and the assertion that actually matters is on
 * the counts, which are exact. On Windows `setTimeout(1)` lands nearer 10 ms
 * than 1, so treat the millisecond column as indicative and the ratio as the
 * finding.
 */
const MODELLED_STATEMENT_LATENCY_MS = 1;

function commands(count: number): readonly RecordAuditEventCommand[] {
  return Array.from({ length: count }, (_, index) => ({
    action: "user.login_succeeded" as const,
    actorId: `actor-${String(index)}`,
  }));
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function measure(runs: () => Promise<void>): Promise<{ ms: number }> {
  const started = performance.now();
  await runs();
  return { ms: performance.now() - started };
}

/**
 * Counts statements and adds a fixed delay to each one.
 *
 * The delay stands in for the network round trip that dominates audit writes.
 * Counting is the more important half: it is exact, hardware-independent, and
 * it is the quantity the batched writer actually reduces.
 */
class InstrumentedAuditRepository implements AuditLogRepository {
  readonly statements: string[] = [];

  constructor(
    private readonly inner: AuditLogRepository,
    private readonly latencyMs: number,
  ) {}

  get statementCount(): number {
    return this.statements.length;
  }

  private async step(name: string): Promise<void> {
    this.statements.push(name);
    if (this.latencyMs > 0) {
      await sleep(this.latencyMs);
    }
  }

  async findLatest(): Promise<AuditLogEntry | undefined> {
    await this.step("findLatest");
    return this.inner.findLatest();
  }

  async append(
    entry: AuditLogEntry,
    expectedPreviousHash: string,
  ): Promise<Result<void, ChainConflictError>> {
    await this.step("append");
    return this.inner.append(entry, expectedPreviousHash);
  }

  async appendMany(
    entries: readonly AuditLogEntry[],
    expectedPreviousHash: string,
  ): Promise<Result<void, ChainConflictError>> {
    await this.step(`appendMany(${String(entries.length)})`);
    return this.inner.appendMany(entries, expectedPreviousHash);
  }

  async findFrom(fromSequence: number, limit: number): Promise<readonly AuditLogEntry[]> {
    await this.step("findFrom");
    return this.inner.findFrom(fromSequence, limit);
  }

  async count(): Promise<number> {
    await this.step("count");
    return this.inner.count();
  }
}

async function writePerEvent(repository: AuditLogRepository, count: number): Promise<void> {
  const recorder = new RecordAuditEvent(repository);
  const all = commands(count);
  for (const command of all) {
    await recorder.execute(command);
  }
}

async function writeBatched(repository: AuditLogRepository, count: number): Promise<void> {
  const writer = new BatchedAuditWriter(repository, {
    maxBatchSize: BATCH_SIZE,
    // No interval: the batch-size flush is what a saturated producer triggers,
    // and a timer would add nondeterministic waits to a measurement.
    flushIntervalMs: 3_600_000,
    maxQueueSize: count,
  });

  const all = commands(count);
  for (const command of all) {
    await writer.execute(command);
  }
  await writer.stop();
}

function report(label: string, ms: number, statements: number, events: number): void {
  const perEvent = ms / events;
  process.stdout.write(
    `${label}: ${ms.toFixed(0)} ms total, ${perEvent.toFixed(3)} ms/event, ${Math.round(events / (ms / 1000)).toLocaleString()} events/s, ${String(statements)} statements\n`,
  );
}

describe("audit write throughput (modelled round trips)", () => {
  const count = 200;

  it("compares per-event and batched writes under a stated latency model", async () => {
    const perEventStore = new InstrumentedAuditRepository(
      new InMemoryAuditLogRepository(),
      MODELLED_STATEMENT_LATENCY_MS,
    );
    const perEvent = await measure(() => writePerEvent(perEventStore, count));

    const batchedStore = new InstrumentedAuditRepository(
      new InMemoryAuditLogRepository(),
      MODELLED_STATEMENT_LATENCY_MS,
    );
    const batched = await measure(() => writeBatched(batchedStore, count));

    report("per-event ", perEvent.ms, perEventStore.statementCount, count);
    report("batched   ", batched.ms, batchedStore.statementCount, count);
    process.stdout.write(
      `ratio       ${(perEvent.ms / batched.ms).toFixed(1)}x faster, ` +
        `${(perEventStore.statementCount / batchedStore.statementCount).toFixed(1)}x fewer statements ` +
        `(batch size ${String(BATCH_SIZE)}, modelled latency ${String(MODELLED_STATEMENT_LATENCY_MS)} ms/statement)\n`,
    );

    // Exact, and the mechanism being demonstrated: one head read and one
    // insert per entry, versus one pair per batch.
    expect(perEventStore.statementCount).toBe(count * 2);
    expect(batchedStore.statementCount).toBe(Math.ceil(count / BATCH_SIZE) * 2);

    expect(batched.ms).toBeLessThan(perEvent.ms / 4);
  });

  it("leaves a verifiable chain and drops nothing", async () => {
    const repository = new InMemoryAuditLogRepository();
    await writeBatched(repository, count);

    const stored = await repository.findFrom(1, count + 10);
    expect(stored).toHaveLength(count);
    expect(stored[0]?.previousHash).toBe(GENESIS_HASH);
    expect(verifyChain(stored)).toBeUndefined();
    expect(await repository.count()).toBe(count);
  });

  it("keeps the queue bounded rather than growing with the producer", async () => {
    // The other half of the claim: bounded memory under a producer that
    // outruns the database. Latency here is what makes the queue back up.
    const overflowed: number[] = [];
    const store = new InstrumentedAuditRepository(
      new InMemoryAuditLogRepository(),
      MODELLED_STATEMENT_LATENCY_MS,
    );
    const writer = new BatchedAuditWriter(store, {
      maxBatchSize: BATCH_SIZE,
      flushIntervalMs: 3_600_000,
      maxQueueSize: 100,
      onOverflow: (r) => overflowed.push(r.overflowedTotal),
    });

    const all = commands(500);
    for (const command of all) {
      // Fire-and-forget, deliberately: `execute` returns once the entry is
      // offered, and an oversubscribed producer is the case being tested.
      void writer.execute(command);
    }

    expect(writer.pending).toBeLessThanOrEqual(100);
    expect(overflowed.length).toBeGreaterThan(0);

    await writer.stop();
    const written = await store.count();
    expect(written).toBeGreaterThan(0);
    expect(written + overflowed.length).toBe(500);
  });
});

const databaseAvailable = await databaseAvailability();

describe.skipIf(!databaseAvailable)("audit write throughput (Postgres)", () => {
  const prisma = createTestPrismaClient();

  const transaction: AuditTransaction = <T>(
    work: (entries: AuditDelegate) => Promise<T>,
  ): Promise<T> => prisma.$transaction(async (tx) => work(tx.auditLogEntry));

  function repository(): AuditLogRepository {
    return new PrismaAuditLogRepository(prisma.auditLogEntry, transaction);
  }

  async function truncate(): Promise<void> {
    await prisma.auditLogEntry.deleteMany({});
  }

  it(`writes ${String(EVENTS)} events per strategy against ${testDatabaseUrl()}`, async () => {
    // Warm up first: the first writes pay for connection setup and Prisma's
    // query engine starting, which are real but one-off (`baseline.md` makes
    // the same discard-the-cold-runs argument).
    await truncate();
    await writePerEvent(repository(), 20);

    await truncate();
    const perEvent = await measure(() => writePerEvent(repository(), EVENTS));

    await truncate();
    const batched = await measure(() => writeBatched(repository(), EVENTS));

    report("per-event ", perEvent.ms, EVENTS * 2, EVENTS);
    report("batched   ", batched.ms, Math.ceil(EVENTS / BATCH_SIZE) * 2, EVENTS);
    process.stdout.write(
      `ratio       ${(perEvent.ms / batched.ms).toFixed(1)}x (batch size ${String(BATCH_SIZE)})\n`,
    );

    expect(batched.ms).toBeLessThan(perEvent.ms);

    const stored = await prisma.auditLogEntry.findMany({
      orderBy: { sequence: "asc" },
    });
    expect(stored).toHaveLength(EVENTS);
    expect(verifyChain(stored.map((row) => AuditLogEntryMapper.toDomain(row)))).toBeUndefined();

    await truncate();
    await prisma.$disconnect();
  }, 180_000);
});
