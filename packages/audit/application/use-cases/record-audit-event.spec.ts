import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import {
  type AuditAction,
  AuditLogEntry,
  GENESIS_HASH,
  verifyChain,
} from "../../domain/entities/audit-log-entry.js";
import { InMemoryAuditLogRepository } from "../../infrastructure/testing/in-memory-audit-repositories.js";
import type { AuditLogRepository } from "../ports/audit-log-repository.js";
import { ChainConflictError } from "../ports/audit-log-repository.js";

import { recordAuditEventBatch, RecordAuditEvent } from "./record-audit-event.js";

function entry(action: AuditAction, previous: AuditLogEntry | undefined): AuditLogEntry {
  return AuditLogEntry.append({ action, previous });
}

/**
 * A repository that loses the first `rejections` appends, inserting a
 * competing entry each time so the head genuinely moves.
 *
 * Modelling the competition as an actual write rather than a canned error
 * matters: the assertion is about what the retry *links onto*, and a fake that
 * rejected without moving the head would let an implementation that retried
 * against the stale head pass.
 */
function contendedRepository(rejections: number): {
  repository: AuditLogRepository;
  inner: InMemoryAuditLogRepository;
  appendAttempts: () => number;
} {
  const inner = new InMemoryAuditLogRepository();
  let remaining = rejections;
  let attempts = 0;

  const repository: AuditLogRepository = {
    findLatest: () => inner.findLatest(),
    findFrom: (from, limit) => inner.findFrom(from, limit),
    count: () => inner.count(),
    appendMany: (entries, expected) => inner.appendMany(entries, expected),
    append: async (entryToWrite, expectedPreviousHash) => {
      attempts += 1;
      if (remaining > 0) {
        remaining -= 1;
        const head = await inner.findLatest();
        const competitor = entry("user.login_succeeded", head);
        await inner.append(competitor, head?.hash ?? GENESIS_HASH);
        const moved = await inner.findLatest();
        return Result.err(
          new ChainConflictError(expectedPreviousHash, moved?.hash ?? GENESIS_HASH),
        );
      }
      return inner.append(entryToWrite, expectedPreviousHash);
    },
  };

  return { repository, inner, appendAttempts: () => attempts };
}

describe("RecordAuditEvent", () => {
  it("links onto the current head and returns what it wrote", async () => {
    const repository = new InMemoryAuditLogRepository();

    const recorded = await new RecordAuditEvent(repository).execute({ action: "user.registered" });

    expect(recorded?.previousHash).toBe(GENESIS_HASH);
    expect((await repository.findLatest())?.hash).toBe(recorded?.hash);
  });

  it("chains successive events onto each other", async () => {
    const repository = new InMemoryAuditLogRepository();
    const recorder = new RecordAuditEvent(repository);

    const first = await recorder.execute({ action: "user.registered" });
    const second = await recorder.execute({ action: "user.login_succeeded" });

    expect(second?.previousHash).toBe(first?.hash);
    expect(second?.sequence).toBe(2);
  });

  it("re-reads the head and retries after losing a race", async () => {
    const { repository, inner, appendAttempts } = contendedRepository(1);

    const recorded = await new RecordAuditEvent(repository).execute({
      action: "user.login_failed",
    });

    expect(appendAttempts()).toBe(2);
    expect(recorded).toBeDefined();
    expect(await inner.count()).toBe(2);
    // The retry linked onto the competitor's entry rather than forking off the
    // head it had originally read — the difference between a serialization
    // protocol and a lost write.
    const stored = await inner.findFrom(1, 10);
    expect(recorded?.previousHash).toBe(stored[0]?.hash);
    expect(recorded?.sequence).toBe(2);
    expect((await inner.findLatest())?.hash).toBe(recorded?.hash);
  });

  it("gives up after the configured attempts and reports through onError", async () => {
    // Bounded rather than unbounded: a subscriber that spins on contention turns
    // a throughput problem into an outage. Reporting the abandonment is what
    // makes the resulting gap visible instead of merely absent.
    const { repository, inner } = contendedRepository(10);
    const errors: unknown[] = [];

    const recorded = await new RecordAuditEvent(
      repository,
      (error) => errors.push(error),
      3,
    ).execute({ action: "user.locked_out" });

    expect(recorded).toBeUndefined();
    expect(errors).toHaveLength(1);
    expect((errors[0] as Error).message).toContain("3 consecutive chain races");
    // Our entry never landed. The three rows present are the competing writers
    // that beat us on each attempt, so nothing we were asked to write was
    // duplicated or partially applied.
    expect(inner.all().map((each) => each.action)).toEqual([
      "user.login_succeeded",
      "user.login_succeeded",
      "user.login_succeeded",
    ]);
    expect(await inner.count()).toBe(3);
  });

  it("never throws, whatever the repository does", async () => {
    // The audited operation already succeeded. Surfacing a failed audit write as
    // a thrown error would report to the user a login failure that did not
    // happen — see the class comment.
    const failing: AuditLogRepository = {
      findLatest: () => Promise.reject(new Error("connection lost")),
      append: () => Promise.reject(new Error("unreachable")),
      appendMany: () => Promise.reject(new Error("unreachable")),
      findFrom: () => Promise.reject(new Error("unreachable")),
      count: () => Promise.reject(new Error("unreachable")),
    };
    const errors: unknown[] = [];

    await expect(
      new RecordAuditEvent(failing, (error) => errors.push(error)).execute({
        action: "user.login_failed",
      }),
    ).resolves.toBeUndefined();

    expect(errors).toHaveLength(1);
  });

  it("preserves a fixed occurredAt the caller supplies", async () => {
    // Recording an event that already happened must not redate it to "now", or
    // the log stops being evidence of when things occurred.
    const repository = new InMemoryAuditLogRepository();
    const occurredAt = new Date("2026-01-01T00:00:00.000Z");

    const recorded = await new RecordAuditEvent(repository).execute({
      action: "user.email_verified",
      occurredAt,
    });

    expect(recorded?.occurredAt.toISOString()).toBe(occurredAt.toISOString());
  });

  it("leaves no sequence gap when an append fails and is retried", async () => {
    // Sequence continuity is what `verifyChain` reports a gap against, so a
    // rejected append must consume no number -- otherwise an unrelated reader
    // could not tell a lost race from a deleted record.
    const { repository, inner } = contendedRepository(1);
    const recorder = new RecordAuditEvent(repository);
    await recorder.execute({ action: "user.registered" });
    await recorder.execute({ action: "user.login_succeeded" });

    const stored = await inner.findFrom(1, 10);
    expect(stored.map((each) => each.sequence)).toEqual([1, 2, 3]);
    expect(verifyChain(stored)).toBeUndefined();
  });
});

describe("recordAuditEventBatch", () => {
  it("writes several events as one atomic chain extension", async () => {
    const repository = new InMemoryAuditLogRepository();

    const entries = await recordAuditEventBatch(
      repository,
      [
        { action: "user.registered" },
        { action: "user.login_succeeded" },
        { action: "user.login_failed" },
      ],
      () => undefined,
    );

    expect(entries).toHaveLength(3);
    expect(await repository.count()).toBe(3);
    const stored = await repository.findFrom(1, 10);
    expect(stored.map((each) => each.sequence)).toEqual([1, 2, 3]);
    for (let index = 1; index < stored.length; index += 1) {
      expect(stored[index]?.previousHash).toBe(stored[index - 1]?.hash);
    }
  });

  it("writes nothing when the batch loses the compare-and-set", async () => {
    const repository = new InMemoryAuditLogRepository();
    await recordAuditEventBatch(repository, [{ action: "user.registered" }], () => undefined);
    const head = await repository.findLatest();

    // The batch is offered against a head that no longer exists. A partial
    // write would be indistinguishable from tampering, so refusal means refusal
    // for all of it.
    const stale: AuditLogRepository = {
      findLatest: () => repository.findLatest(),
      findFrom: (from, limit) => repository.findFrom(from, limit),
      count: () => repository.count(),
      append: (each, expected) => repository.append(each, expected),
      appendMany: () =>
        Promise.resolve(
          Result.err(new ChainConflictError(head?.hash ?? "", head?.hash ?? GENESIS_HASH)),
        ),
    };
    const errors: unknown[] = [];

    const entries = await recordAuditEventBatch(
      stale,
      [{ action: "user.login_succeeded" }, { action: "user.login_failed" }],
      (error) => errors.push(error),
    );

    expect(entries).toHaveLength(0);
    expect(errors).toHaveLength(1);
    expect(await repository.count()).toBe(1);
  });

  it("does not query the repository at all for an empty batch", async () => {
    let calls = 0;
    const counting: AuditLogRepository = {
      findLatest: () => {
        calls += 1;
        return Promise.resolve(undefined);
      },
      append: () => Promise.resolve(Result.ok(undefined)),
      appendMany: () => Promise.resolve(Result.ok(undefined)),
      findFrom: () => Promise.resolve([]),
      count: () => Promise.resolve(0),
    };

    expect(await recordAuditEventBatch(counting, [], () => undefined)).toHaveLength(0);
    expect(calls).toBe(0);
import { describe, expect, it } from "vitest";

import { AuditLogEntry, GENESIS_HASH } from "../../domain/entities/audit-log-entry.js";
import { InMemoryAuditLogRepository } from "../../infrastructure/testing/in-memory-audit-repositories.js";

import { RecordAuditEvent } from "./record-audit-event.js";

describe("RecordAuditEvent", () => {
  it("starts the chain at the genesis link when the log is empty", async () => {
    const repository = new InMemoryAuditLogRepository();

    const entry = await new RecordAuditEvent(repository).execute({
      action: "user.login_succeeded",
      actorId: "user-1",
      subjectId: "user-1",
    });

    expect(entry).toBeInstanceOf(AuditLogEntry);
    expect(entry?.sequence).toBe(1);
    expect(entry?.previousHash).toBe(GENESIS_HASH);
    expect(entry?.hasValidHash).toBe(true);
    expect(await repository.count()).toBe(1);
  });

  it("links each entry to the entry it read as the tail", async () => {
    const repository = new InMemoryAuditLogRepository();
    const record = new RecordAuditEvent(repository);

    const first = await record.execute({ action: "user.registered" });
    const second = await record.execute({ action: "user.email_verified" });

    expect(second?.previousHash).toBe(first?.hash);
    expect(second?.sequence).toBe(2);
    expect(repository.all().map((entry) => entry.sequence)).toEqual([1, 2]);
  });

  it("defaults metadata to an empty object rather than leaving it undefined", async () => {
    const repository = new InMemoryAuditLogRepository();

    const entry = await new RecordAuditEvent(repository).execute({ action: "user.locked_out" });

    expect(entry?.metadata).toEqual({});
  });

  it("preserves actor, subject and metadata from the command", async () => {
    const repository = new InMemoryAuditLogRepository();

    const entry = await new RecordAuditEvent(repository).execute({
      action: "user.password_reset_completed",
      actorId: "admin-1",
      subjectId: "user-9",
      metadata: { ip: "203.0.113.7" },
    });

    expect(entry?.actorId).toBe("admin-1");
    expect(entry?.subjectId).toBe("user-9");
    expect(entry?.metadata).toEqual({ ip: "203.0.113.7" });
  });

  describe("when the write fails", () => {
    /** A repository whose append always rejects, standing in for an outage. */
    function failingRepository(): InMemoryAuditLogRepository {
      const repository = new InMemoryAuditLogRepository();
      repository.findLatest = () => Promise.reject(new Error("connection lost"));
      return repository;
    }

    it("returns undefined instead of throwing at the audited operation", async () => {
      const record = new RecordAuditEvent(failingRepository());

      await expect(record.execute({ action: "user.login_succeeded" })).resolves.toBeUndefined();
    });

    it("reports the failure through the error handler so the gap is not silent", async () => {
      const seen: unknown[] = [];
      const record = new RecordAuditEvent(failingRepository(), (error) => seen.push(error));

      await record.execute({ action: "user.login_succeeded" });

      expect(seen).toHaveLength(1);
      expect((seen[0] as Error).message).toBe("connection lost");
    });

    it("swallows the failure even with no handler registered", async () => {
      const repository = new InMemoryAuditLogRepository();
      repository.append = () => Promise.reject(new Error("unique_violation"));
      repository.findLatest = () =>
        Promise.resolve(AuditLogEntry.append({ action: "user.registered" }));

      const entry = await new RecordAuditEvent(repository).execute({ action: "user.registered" });

      expect(entry).toBeUndefined();
    });
  });
});
