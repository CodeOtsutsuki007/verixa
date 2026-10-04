import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import {
  type AuditAction,
  AuditLogEntry,
  GENESIS_HASH,
} from "../../domain/entities/audit-log-entry.js";
import { auditLogRepositoryContract } from "../testing/contracts/audit-log-repository.contract.js";

import {
  type AuditDelegate,
  AuditLogEntryMapper,
  PrismaAuditLogRepository,
} from "./prisma-audit-repositories.js";

type AuditRowInput = ReturnType<typeof AuditLogEntryMapper.toRow>;

function entryAfter(
  previous: AuditLogEntry | undefined,
  index: number,
  action: AuditAction = "user.login_succeeded",
): AuditLogEntry {
  return AuditLogEntry.append({
    action,
    actorId: `actor-${String(index)}`,
    previous,
    occurredAt: new Date(1_700_000_000_000 + index * 1000),
  });
}

/** Mirrors Prisma's `P2002`, the only error the adapter has to interpret. */
function uniqueViolation(): Error {
  return Object.assign(new Error("Unique constraint failed on the fields: (`sequence`)"), {
    code: "P2002",
  });
}

/**
 * A stand-in for the Prisma audit table, plus the transaction runner the
 * adapter is constructed with.
 *
 * Enforces the two unique constraints the schema declares (`sequence` and
 * `hash`) by raising the error Prisma raises, so the adapter's error
 * translation is exercised without a database. `createMany` is all-or-nothing
 * for the same reason a real multi-row statement is.
 *
 * Tests that need to interpose between the adapter's head read and its insert
 * wrap `createMany` (see the race case below) — that seam is the only way to
 * reproduce the window a compare-and-set read cannot close on its own.
 */
function fakeDatabase(): { table: AuditDelegate; rows: AuditRowInput[] } {
  const rows: AuditRowInput[] = [];

  const conflictsWith = (candidate: AuditRowInput, against: readonly AuditRowInput[]): boolean =>
    against.some((row) => row.sequence === candidate.sequence || row.hash === candidate.hash);

  const table: AuditDelegate = {
    findFirst: () => {
      const latest = [...rows].sort((a, b) => b.sequence - a.sequence)[0];
      return Promise.resolve(latest ?? null);
    },
    findMany: (args) =>
      Promise.resolve(
        rows
          .filter((row) => row.sequence >= args.where.sequence.gte)
          .sort((a, b) => a.sequence - b.sequence)
          .slice(0, args.take),
      ),
    create: (args) => {
      if (conflictsWith(args.data, rows)) {
        throw uniqueViolation();
      }
      rows.push(args.data);
      return Promise.resolve(args.data);
    },
    createMany: (args) => {
      const staged = [...rows];
      for (const candidate of args.data) {
        if (conflictsWith(candidate, staged)) {
          throw uniqueViolation();
        }
        staged.push(candidate);
      }
      rows.length = 0;
      rows.push(...staged);
      return Promise.resolve({ count: args.data.length });
    },
    count: () => Promise.resolve(rows.length),
  };

  return { table, rows };
}

/** The repository under test, over a fake table whose transactions are trivial. */
function buildRepository(table: AuditDelegate): PrismaAuditLogRepository {
  return new PrismaAuditLogRepository(table, (work) => Promise.resolve(work(table)));
}

describe("PrismaAuditLogRepository", () => {
  auditLogRepositoryContract(() => buildRepository(fakeDatabase().table));

  it("translates a unique-constraint violation into a retryable chain conflict", async () => {
    // At Postgres' default isolation two overlapping transactions can both read
    // the same head and both pass the check; the unique index on `sequence` is
    // what actually serializes them. This proves the adapter turns that index
    // violation into a conflict a caller can retry on, rather than letting a
    // database error escape from inside the transaction.
    const { table, rows } = fakeDatabase();
    const first = entryAfter(undefined, 0, "user.registered");

    const ours = entryAfter(first, 1, "user.login_failed");
    const racer = entryAfter(first, 1, "user.login_succeeded");

    let injected = false;
    const racedTable: AuditDelegate = {
      ...table,
      createMany: (args) => {
        if (!injected) {
          injected = true;
          // The racer commits while our transaction sits between its head read
          // and its insert. Both claim sequence 2 against the same head.
          rows.push(AuditLogEntryMapper.toRow(racer));
        }
        return table.createMany(args);
      },
    };
    const repository = buildRepository(racedTable);

    expect(Result.isOk(await repository.append(first, GENESIS_HASH))).toBe(true);
    const outcome = await repository.append(ours, first.hash);

    expect(Result.isErr(outcome)).toBe(true);
    if (Result.isErr(outcome)) {
      expect(outcome.error.code).toBe("AUDIT_CHAIN_CONFLICT");
      expect(outcome.error.actualPreviousHash).toBe(racer.hash);
    }
    expect(rows.some((row) => row.hash === ours.hash)).toBe(false);
    expect(await repository.count()).toBe(2);

    // The conflict is recoverable, which is the entire reason it is a `Result`
    // rather than a thrown error: retrying against the racer's head lands.
    expect(Result.isOk(await repository.append(entryAfter(racer, 2), racer.hash))).toBe(true);
    expect(await repository.count()).toBe(3);
  });

  it("opens one transaction per append and none for reads", async () => {
    // The property under test is that the head check and the insert are one
    // indivisible operation. Counting transactions asserts that shape cheaply,
    // and asserting reads open *none* is what stops the count being meaningful
    // only because everything is wrapped.
    const { table } = fakeDatabase();
    let opened = 0;
    const repository = new PrismaAuditLogRepository(table, (work) => {
      opened += 1;
      return Promise.resolve(work(table));
    });

    const first = entryAfter(undefined, 0, "user.registered");
    await repository.append(first, GENESIS_HASH);
    expect(opened).toBe(1);

    await repository.findLatest();
    await repository.findFrom(1, 10);
    await repository.count();
    expect(opened).toBe(1);

    expect(Result.isOk(await repository.appendMany([entryAfter(first, 1)], first.hash))).toBe(true);
    expect(opened).toBe(2);
  });

  it("inserts a batch with one statement rather than one per entry", async () => {
    // The throughput claim in docs/performance/audit-write-throughput.md rests
    // on this. A "batched" writer that still issues N inserts has changed the
    // code's shape and nothing else.
    const { table, rows } = fakeDatabase();
    let createCalls = 0;
    let createManyCalls = 0;
    let largestStatement = 0;

    const countingTable: AuditDelegate = {
      ...table,
      create: (args) => {
        createCalls += 1;
        return table.create(args);
      },
      createMany: (args) => {
        createManyCalls += 1;
        largestStatement = Math.max(largestStatement, args.data.length);
        return table.createMany(args);
      },
    };
    const repository = buildRepository(countingTable);

    const batch: AuditLogEntry[] = [entryAfter(undefined, 0, "user.registered")];
    for (let index = 1; index < 25; index += 1) {
      batch.push(entryAfter(batch[index - 1], index));
    }

    expect(Result.isOk(await repository.appendMany(batch, GENESIS_HASH))).toBe(true);
    expect(createManyCalls).toBe(1);
    expect(createCalls).toBe(0);
    expect(largestStatement).toBe(25);
    expect(rows.length).toBe(25);
  });
});
