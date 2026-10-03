import { describe, expect, it } from "vitest";

import { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";

import {
  InMemoryAnchorRecordRepository,
  InMemoryAuditLogRepository,
} from "./in-memory-audit-repositories.js";

function entry(
  previous: AuditLogEntry | undefined,
  action: "user.registered" | "user.login_failed" = "user.registered",
): AuditLogEntry {
  return AuditLogEntry.append({
    action,
    actorId: previous === undefined ? "actor-1" : "actor-2",
    subjectId: "subject-1",
    metadata: { organizationId: previous === undefined ? "org-a" : "org-b" },
    previous,
    occurredAt: new Date(1_700_000_000_000 + (previous?.sequence ?? 0) * 1000),
  });
}

async function seeded(): Promise<InMemoryAuditLogRepository> {
  const repository = new InMemoryAuditLogRepository();
  let previous: AuditLogEntry | undefined;
  for (let index = 0; index < 4; index += 1) {
    const next = entry(previous, index === 1 ? "user.login_failed" : "user.registered");
    await repository.append(next);
    previous = next;
  }
  return repository;
}

describe("InMemoryAuditLogRepository", () => {
  it("rejects a second entry claiming a sequence already used", async () => {
    const repository = await seeded();
    const third = repository.all()[2]!;

    // A fork: a second entry built from the same predecessor, so it claims
    // sequence 4 a second time. The real table refuses this on a unique index,
    // and a fake that accepted it would let tests pass against a log
    // production would reject.
    const fork = entry(third);

    await expect(repository.append(fork)).rejects.toThrow("sequence 4 already exists");
    expect(await repository.count()).toBe(4);
  });

  it("reads the tail without reading the log", async () => {
    const repository = await seeded();

    const latest = await repository.findLatest();

    expect(latest?.sequence).toBe(4);
  });

  it("returns undefined for the tail of an empty log", async () => {
    expect(await new InMemoryAuditLogRepository().findLatest()).toBeUndefined();
  });

  it("returns entries from the requested sequence onward, capped at the limit", async () => {
    const repository = await seeded();

    const page = await repository.findFrom(3, 2);

    expect(page.map((e) => e.sequence)).toEqual([3, 4]);
    expect(await repository.findFrom(5, 10)).toEqual([]);
  });

  describe("filtered queries", () => {
    it("honours each filter on its own", async () => {
      const repository = await seeded();

      const byActor = await repository.findWithFilters({
        filters: { actorId: "actor-2" },
        fromSequence: 1,
        limit: 10,
      });
      const byAction = await repository.findWithFilters({
        filters: { action: "user.login_failed" },
        fromSequence: 1,
        limit: 10,
      });
      const byOrganization = await repository.findWithFilters({
        filters: { organizationId: "org-b" },
        fromSequence: 1,
        limit: 10,
      });
      const byDate = await repository.findWithFilters({
        filters: {
          fromDate: new Date(1_700_000_001_000),
          toDate: new Date(1_700_000_002_000),
        },
        fromSequence: 1,
        limit: 10,
      });

      expect(byActor.map((e) => e.sequence)).toEqual([2, 3, 4]);
      expect(byAction.map((e) => e.sequence)).toEqual([2]);
      expect(byOrganization.map((e) => e.sequence)).toEqual([2, 3, 4]);
      expect(byDate.map((e) => e.sequence)).toEqual([2, 3]);
    });

    it("treats the cursor as a lower bound on sequence, not an offset", async () => {
      const repository = await seeded();

      const page = await repository.findWithFilters({
        filters: {},
        fromSequence: 3,
        limit: 10,
      });

      expect(page.map((e) => e.sequence)).toEqual([3, 4]);
    });

    it("applies the limit after filtering", async () => {
      const repository = await seeded();

      const page = await repository.findWithFilters({
        filters: { actorId: "actor-2" },
        fromSequence: 1,
        limit: 2,
      });

      expect(page.map((e) => e.sequence)).toEqual([2, 3]);
    });
  });

  describe("tampering primitives used by verification tests", () => {
    it("replaces an entry in place so its hash no longer matches its content", async () => {
      const repository = await seeded();
      const original = repository.all()[1]!;
      const rewritten = AuditLogEntry.reconstitute({
        ...original,
        action: "user.login_failed",
        metadata: { organizationId: "org-a" },
      });

      repository.tamper(2, rewritten);

      expect(repository.all()[2]?.previousHash).toBe(original.hash);
      expect(await repository.count()).toBe(4);
    });

    it("does nothing when tampering with a sequence that is not there", async () => {
      const repository = await seeded();

      repository.tamper(99, entry(undefined));

      expect(await repository.count()).toBe(4);
    });

    it("removes an entry, leaving the gap a deletion is expected to leave", async () => {
      const repository = await seeded();

      repository.remove(2);

      expect(repository.all().map((e) => e.sequence)).toEqual([1, 3, 4]);
      expect(await repository.count()).toBe(3);
    });

    it("does nothing when removing a sequence that is not there", async () => {
      const repository = await seeded();

      repository.remove(99);

      expect(await repository.count()).toBe(4);
    });

    it("hands out a copy, so mutating the result cannot rewrite the log", async () => {
      const repository = await seeded();

      const exported = repository.all() as AuditLogEntry[];
      exported.pop();

      expect(await repository.count()).toBe(4);
    });
  });
});

describe("InMemoryAnchorRecordRepository", () => {
  const record = (
    sequence: number,
  ): {
    sequence: number;
    chainHash: string;
    anchorRef: string;
    network: string;
    anchoredAt: Date;
  } => ({
    sequence,
    chainHash: `hash-${String(sequence)}`,
    anchorRef: `tx-${String(sequence)}`,
    network: "stellar:testnet",
    anchoredAt: new Date(1_700_000_000_000 + sequence * 1000),
  });

  it("reports nothing as latest before the first anchor", async () => {
    expect(await new InMemoryAnchorRecordRepository().findLatest()).toBeUndefined();
  });

  it("returns the most recently saved record first when listing history", async () => {
    const repository = new InMemoryAnchorRecordRepository();
    await repository.save(record(1));
    await repository.save(record(2));

    expect((await repository.findLatest())?.sequence).toBe(2);
    expect((await repository.findAll(10)).map((r) => r.sequence)).toEqual([2, 1]);
    expect((await repository.findAll(1)).map((r) => r.sequence)).toEqual([2]);
  });
});
