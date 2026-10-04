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
