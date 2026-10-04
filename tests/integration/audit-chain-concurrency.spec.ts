import {
  AuditLogEntry,
  AuditLogEntryMapper,
  type AuditDelegate,
  type AuditTransaction,
  ChainConflictError,
  GENESIS_HASH,
  PrismaAuditLogRepository,
  RecordAuditEvent,
  verifyChain,
} from "@verixa/audit";
import { Result } from "@verixa/shared-kernel";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createTestPrismaClient, databaseAvailability } from "./helpers/database.js";

/**
 * Concurrent appends against a real Postgres (Issue #128).
 *
 * `auditLogRepositoryContract` already asserts the serialization *protocol*
 * against both repository implementations, and `prisma-audit-repositories
 * .spec.ts` proves the adapter turns a unique-index violation into a retryable
 * conflict. What neither can prove is the thing only Postgres knows: that a
 * `READ COMMITTED` transaction does *not* stop two overlapping appends from
 * reading the same head, and that the unique index on `sequence` is therefore
 * doing the real work rather than the transaction.
 *
 * That distinction decides why the code looks the way it does. If a transaction
 * alone were sufficient, the head re-check inside `appendMany` would be the
 * whole mechanism and the `P2002` translation would be dead code. This file is
 * the evidence that it is not.
 *
 * Skips when no database is reachable, like the rest of this suite; CI sets
 * `REQUIRE_DATABASE_TESTS=1` so the skip cannot silently hide a broken
 * pipeline.
 */

const available = await databaseAvailability();

describe.skipIf(!available)("audit chain concurrency (Issue #128)", () => {
  const prisma = createTestPrismaClient();

  const transaction: AuditTransaction = <T>(
    work: (entries: AuditDelegate) => Promise<T>,
  ): Promise<T> => prisma.$transaction(async (tx) => work(tx.auditLogEntry));

  const repository = new PrismaAuditLogRepository(prisma.auditLogEntry, transaction);

  beforeAll(async () => {
    // A hash chain can only be verified from its first entry, so this file owns
    // the whole table for its duration. Nothing else in the suite writes
    // `audit_log_entry`, so the warning in `users-table.spec.ts` about blanket
    // deletes does not apply to a table with a single occupant.
    await prisma.auditLogEntry.deleteMany({});
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  async function storedChain(): Promise<ReturnType<typeof toEntries>> {
    return toEntries(await prisma.auditLogEntry.findMany({ orderBy: { sequence: "asc" } }));
  }

  function toEntries(
    rows: {
      id: string;
      sequence: number;
      action: string;
      actorId: string | null;
      subjectId: string | null;
      metadata: unknown;
      occurredAt: Date;
      previousHash: string;
      hash: string;
    }[],
  ) {
    return rows.map((row) => AuditLogEntryMapper.toDomain(row));
  }

  it("serializes two appends that both claim the same head", async () => {
    // Both writers start against an empty log, so both build a first entry that
    // claims sequence 1 and links to the genesis hash. Only one can commit; the
    // loser is expected to re-read and relink, which is what separates a
    // retryable conflict from a lost event.
    const recorder = new RecordAuditEvent(repository);

    const results = await Promise.all([
      recorder.execute({ action: "user.login_succeeded", actorId: "racer-a" }),
      recorder.execute({ action: "user.login_failed", actorId: "racer-b" }),
    ]);

    expect(results.filter((entry) => entry !== undefined)).toHaveLength(2);

    const chain = await storedChain();
    expect(chain).toHaveLength(2);
    expect(chain[0]?.sequence).toBe(1);
    expect(chain[0]?.previousHash).toBe(GENESIS_HASH);
    expect(chain[1]?.previousHash).toBe(chain[0]?.hash);
    expect(verifyChain(chain)).toBeUndefined();
  });

  it("refuses an append that names a stale head, and writes nothing", async () => {
    const head = await repository.findLatest();
    if (head === undefined) throw new Error("expected a head from the previous test");

    // The chain moves under the caller's feet.
    const rival = await new RecordAuditEvent(repository).execute({
      action: "user.login_succeeded",
      actorId: "rival",
    });
    expect(rival).toBeDefined();

    // An entry built against the superseded head is a fork. Inserting it would
    // produce two entries claiming to follow the same predecessor, and
    // `verifyChain` could no longer tell which history is the real one.
    const forked = AuditLogEntry.append({
      action: "user.locked_out",
      actorId: "fork",
      previous: head,
    });

    const outcome = await repository.append(forked, head.hash);
    expect(Result.isErr(outcome)).toBe(true);
    if (Result.isErr(outcome)) {
      expect(outcome.error).toBeInstanceOf(ChainConflictError);
      expect(outcome.error.actualPreviousHash).toBe(rival?.hash);
    }

    const chain = await storedChain();
    expect(chain).toHaveLength(3);
    expect(chain.map((entry) => entry.sequence)).toEqual([1, 2, 3]);
    expect(verifyChain(chain)).toBeUndefined();
  });
});
