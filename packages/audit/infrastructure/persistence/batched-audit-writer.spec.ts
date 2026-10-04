import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { AuditLogRepository } from "../../application/ports/audit-log-repository.js";
import { ChainConflictError } from "../../application/ports/audit-log-repository.js";
import type {
  AuditRecorder,
  RecordAuditEventCommand,
} from "../../application/use-cases/record-audit-event.js";
import { RecordAuditEvent } from "../../application/use-cases/record-audit-event.js";
import { AuditLogEntry, GENESIS_HASH, verifyChain } from "../../domain/entities/audit-log-entry.js";
import { InMemoryAuditLogRepository } from "../testing/in-memory-audit-repositories.js";

import {
  AuditQueueFullError,
  type AuditBatchFailureReport,
  type AuditOverflowReport,
  BatchedAuditWriter,
} from "./batched-audit-writer.js";

function commands(count: number, offset = 0): RecordAuditEventCommand[] {
  return Array.from({ length: count }, (_, index) => ({
    action: "user.login_succeeded" as const,
    actorId: `actor-${String(offset + index)}`,
  }));
}

describe("BatchedAuditWriter", () => {
  it("writes nothing until a flush", async () => {
    // The trade the writer makes: entries are queued, not immediately durable.
    // Pinning this is what makes the durability window in
    // docs/performance/audit-write-throughput.md a stated property rather than
    // a surprise.
    const repository = new InMemoryAuditLogRepository();
    const writer = new BatchedAuditWriter(repository, { maxBatchSize: 10 });

    expect(Result.isOk(writer.record(commands(3)[0]!))).toBe(true);
    expect(await repository.count()).toBe(0);
    expect(writer.pending).toBe(1);

    await writer.stop();
    expect(await repository.count()).toBe(1);
  });

  it("flushes automatically once a full batch is queued", async () => {
    const repository = new InMemoryAuditLogRepository();
    const writer = new BatchedAuditWriter(repository, { maxBatchSize: 5 });

    for (const command of commands(5)) {
      writer.record(command);
    }
    await writer.stop();

    expect(await repository.count()).toBe(5);
    expect(writer.stats().batches).toBe(1);
    expect(writer.stats().largestBatch).toBe(5);
  });

  it("writes a batch in one statement, preserving chain order", async () => {
    const repository = new InMemoryAuditLogRepository();
    const writer = new BatchedAuditWriter(repository, { maxBatchSize: 50 });

    for (const command of commands(50)) {
      writer.record(command);
    }
    await writer.stop();

    const stored = await repository.findFrom(1, 100);
    expect(stored.length).toBe(50);
    // One batch means one compare-and-set and one insert statement, which is the
    // whole throughput argument; anything else and the writer is decoration.
    expect(writer.stats().batches).toBe(1);
    // Order is preserved, and the chain is continuous — batching must not be
    // allowed to reorder or fork what it wrote.
    expect(stored.map((entry) => entry.actorId)).toEqual(
      commands(50).map((command) => command.actorId),
    );
    expect(verifyChain(stored)).toBeUndefined();
  });

  it("links a later batch onto the head the first batch left", async () => {
    const repository = new InMemoryAuditLogRepository();
    const writer = new BatchedAuditWriter(repository, { maxBatchSize: 4 });

    for (const command of commands(4)) {
      writer.record(command);
    }
    await writer.flush();
    for (const command of commands(4, 4)) {
      writer.record(command);
    }
    await writer.stop();

    const stored = await repository.findFrom(1, 100);
    expect(stored.map((entry) => entry.sequence)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(verifyChain(stored)).toBeUndefined();
  });

  it("refuses an entry once the queue is at its limit", () => {
    // Backpressure is only real if the queue has a ceiling. Without one,
    // sustained overload is a memory leak that ends by losing every queued
    // entry at once, in a crash nobody would connect to the audit log.
    const repository = new InMemoryAuditLogRepository();
    const writer = new BatchedAuditWriter(repository, {
      maxBatchSize: 1_000,
      maxQueueSize: 3,
    });

    for (const command of commands(3)) {
      expect(Result.isOk(writer.record(command))).toBe(true);
    }

    const overflow = writer.record(commands(1, 3)[0]!);

    expect(Result.isErr(overflow)).toBe(true);
    if (Result.isErr(overflow)) {
      expect(overflow.error).toBeInstanceOf(AuditQueueFullError);
      expect(overflow.error.code).toBe("AUDIT_QUEUE_FULL");
    }
    expect(writer.pending).toBe(3);
  });

  it("reports every refused entry through onOverflow with a running total", () => {
    // The acceptance criterion is that overflow is *measured*, not silently
    // dropped. A caller that only gets `false` cannot alert on a loss rate, and
    // an operator who cannot alert on it will discover the gap during an audit.
    const repository = new InMemoryAuditLogRepository();
    const reports: AuditOverflowReport[] = [];
    const writer = new BatchedAuditWriter(repository, {
      maxBatchSize: 1_000,
      maxQueueSize: 1,
      onOverflow: (report) => reports.push(report),
    });

    writer.record(commands(1)[0]!);
    writer.record({ action: "user.login_failed", actorId: "loser-1" });
    writer.record({ action: "user.password_reset_requested", actorId: "loser-2" });

    expect(reports.map((report) => report.overflowedTotal)).toEqual([1, 2]);
    expect(reports.map((report) => report.dropped.action)).toEqual([
      "user.login_failed",
      "user.password_reset_requested",
    ]);
    expect(reports[1]?.queueLimit).toBe(1);
    expect(writer.stats().overflowed).toBe(2);
  });

  it("keeps everything it accepted, refusing only what it said it refused", async () => {
    // The promise `record()` makes: accepted means written. Evicting an
    // accepted entry to make room would break that, which is why overflow
    // refuses the newest entry instead of the oldest.
    const repository = new InMemoryAuditLogRepository();
    const writer = new BatchedAuditWriter(repository, {
      maxBatchSize: 1_000,
      maxQueueSize: 5,
    });

    const accepted = commands(5);
    for (const command of accepted) {
      expect(Result.isOk(writer.record(command))).toBe(true);
    }
    expect(Result.isErr(writer.record({ action: "user.login_failed", actorId: "refused" }))).toBe(
      true,
    );
    await writer.stop();

    const stored = await repository.findFrom(1, 100);
    expect(stored.map((entry) => entry.actorId)).toEqual(accepted.map((c) => c.actorId));
    expect(stored.some((entry) => entry.actorId === "refused")).toBe(false);
  });

  it("never lets the queue exceed its limit, however fast entries arrive", () => {
    const repository = new InMemoryAuditLogRepository();
    const writer = new BatchedAuditWriter(repository, {
      maxBatchSize: 1_000,
      maxQueueSize: 10,
    });

    let refused = 0;
    for (const command of commands(500)) {
      if (Result.isErr(writer.record(command))) {
        refused += 1;
      }
      expect(writer.pending).toBeLessThanOrEqual(10);
    }

    expect(refused).toBe(490);
    expect(writer.pending).toBe(10);
  });

  it("re-links a batch onto a head that moved and still writes it", async () => {
    // A competing writer -- another process, or a direct `RecordAuditEvent` call
    // that bypasses this queue -- can take the head between our read and our
    // insert. The batch has to survive that by relinking, not by being dropped,
    // and must not be written twice in the process.
    const repository = new InMemoryAuditLogRepository();
    const competitor = AuditLogEntry.append({ action: "user.registered" });

    let conflictsForced = false;
    const racing: AuditLogRepository = {
      findLatest: () => repository.findLatest(),
      findFrom: (from, limit) => repository.findFrom(from, limit),
      count: () => repository.count(),
      append: (each, expected) => repository.append(each, expected),
      appendMany: (entries, expected) => {
        if (!conflictsForced) {
          conflictsForced = true;
          // The competitor lands first, so the writer's expectation of the head
          // is now stale and its batch must be refused, not half-applied.
          return repository
            .append(competitor, expected)
            .then(() => repository.appendMany(entries, expected));
        }
        return repository.appendMany(entries, expected);
      },
    };

    const writer = new BatchedAuditWriter(racing, { maxBatchSize: 3, maxFlushAttempts: 3 });
    for (const command of commands(3)) {
      writer.record(command);
    }
    await writer.stop();

    // Competitor first, then our three, re-chained onto it.
    const stored = await repository.findFrom(1, 10);
    expect(stored.length).toBe(4);
    expect(stored[0]?.hash).toBe(competitor.hash);
    expect(verifyChain(stored)).toBeUndefined();
    expect(writer.stats().written).toBe(3);
    expect(writer.stats().conflicts).toBe(1);
    expect(writer.pending).toBe(0);
  });

  it("reports a batch it could not write rather than losing it silently", async () => {
    const rejecting: AuditLogRepository = {
      findLatest: () => Promise.resolve(undefined),
      findFrom: () => Promise.resolve([]),
      count: () => Promise.resolve(0),
      append: () => Promise.resolve(Result.err(new ChainConflictError(GENESIS_HASH, GENESIS_HASH))),
      appendMany: () =>
        Promise.resolve(Result.err(new ChainConflictError(GENESIS_HASH, GENESIS_HASH))),
    };
    const failures: AuditBatchFailureReport[] = [];
    const writer = new BatchedAuditWriter(rejecting, {
      maxBatchSize: 2,
      maxFlushAttempts: 2,
      onBatchFailure: (report) => failures.push(report),
    });

    writer.record(commands(1)[0]!);
    writer.record(commands(1, 1)[0]!);
    await writer.stop();

    expect(failures).toHaveLength(1);
    expect(failures[0]?.commands).toHaveLength(2);
    expect(failures[0]?.attempts).toBe(2);
    expect(failures[0]?.error).toBeInstanceOf(ChainConflictError);
    // The failed batch left the queue (it was reported, not retried forever),
    // and the report carries the entries so a caller can replay them.
    expect(writer.pending).toBe(0);
    expect(writer.stats().failedBatches).toBe(1);
    expect(writer.stats().conflicts).toBe(2);
    expect(writer.stats().overflowed).toBe(0);
  });

  it("flushes on the configured interval while running", async () => {
    const repository = new InMemoryAuditLogRepository();
    let tick: (() => void) | undefined;
    const writer = new BatchedAuditWriter(repository, {
      maxBatchSize: 1_000,
      flushIntervalMs: 10,
      setInterval: (callback) => {
        tick = callback;
        return { clear: () => (tick = undefined) };
      },
    });

    writer.start();
    writer.record(commands(1)[0]!);
    expect(await repository.count()).toBe(0);

    // The interval fires; the writer's callback deliberately does not await the
    // flush, so the test waits on it through `flush()` rather than a timer.
    tick?.();
    await writer.flush();
    expect(await repository.count()).toBe(1);

    await writer.stop();
    expect(tick).toBeUndefined();
  });

  it("drains the queue on stop, so shutdown does not lose accepted entries", async () => {
    const repository = new InMemoryAuditLogRepository();
    const writer = new BatchedAuditWriter(repository, { maxBatchSize: 1_000 });

    for (const command of commands(20)) {
      writer.record(command);
    }
    await writer.stop();

    expect(writer.pending).toBe(0);
    expect(await repository.count()).toBe(20);
  });

  it("coalesces concurrent flushes into one", async () => {
    const repository = new InMemoryAuditLogRepository();
    const writer = new BatchedAuditWriter(repository, { maxBatchSize: 1_000 });

    for (const command of commands(6)) {
      writer.record(command);
    }

    await Promise.all([writer.flush(), writer.flush(), writer.flush()]);

    expect(writer.stats().batches).toBe(1);
    expect(await repository.count()).toBe(6);
  });

  describe("as an AuditRecorder", () => {
    // The port is what lets `apps/api` swap writers without touching call
    // sites, so conformance is asserted rather than assumed: same argument,
    // same never-rejects contract, same "undefined means not written".
    it("satisfies the recorder port that RecordAuditEvent satisfies", async () => {
      const writer = new BatchedAuditWriter(new InMemoryAuditLogRepository(), {
        maxBatchSize: 10,
      });
      const recorder: AuditRecorder = writer;

      const entry = await recorder.execute(commands(1)[0]!);
      expect(entry).toBeUndefined();

      await writer.stop();
      expect(writer.stats().written).toBe(1);
    });

    it("resolves rather than rejecting when the queue refuses the entry", async () => {
      // A route awaiting `execute()` must not turn backpressure into a 500. The
      // refusal is reported through `onOverflow` as a metric; the call site just
      // carries on.
      const overflowed: AuditOverflowReport[] = [];
      const writer = new BatchedAuditWriter(new InMemoryAuditLogRepository(), {
        maxBatchSize: 1_000,
        maxQueueSize: 1,
        onOverflow: (report) => overflowed.push(report),
      });

      await expect(writer.execute(commands(1)[0]!)).resolves.toBeUndefined();
      await expect(writer.execute(commands(1, 1)[0]!)).resolves.toBeUndefined();

      expect(overflowed).toHaveLength(1);
      expect(writer.pending).toBe(1);

      await writer.stop();
    });

    it("is interchangeable with RecordAuditEvent at the call site", async () => {
      // The whole point of the port: `apps/api` holds one `AuditRecorder` and a
      // deployment chooses the strategy. Asserted by assigning both
      // implementations to the same variable rather than by reading comments.
      const repository = new InMemoryAuditLogRepository();
      const writer = new BatchedAuditWriter(repository, { maxBatchSize: 10 });
      const recorders: AuditRecorder[] = [new RecordAuditEvent(repository), writer];

      for (const recorder of recorders) {
        await recorder.execute(commands(1)[0]!);
      }
      await writer.stop();

      const stored = await repository.findFrom(1, 10);
      expect(stored).toHaveLength(2);
      expect(verifyChain(stored)).toBeUndefined();
    });
  });
});
