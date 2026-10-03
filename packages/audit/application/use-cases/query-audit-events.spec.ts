import { describe, expect, it } from "vitest";

import { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";
import { InMemoryAuditLogRepository } from "../../infrastructure/testing/in-memory-audit-repositories.js";

import { QueryAuditEvents } from "./query-audit-events.js";

/**
 * Seeds a log whose entries differ along every axis the use case filters on,
 * so a filter test can assert *which* entries came back rather than merely how
 * many — a predicate that silently matched nothing would still return a count
 * of zero for a bug that should have returned four.
 */
async function seed(): Promise<InMemoryAuditLogRepository> {
  const repository = new InMemoryAuditLogRepository();
  let previous: AuditLogEntry | undefined;

  const fixtures: ReadonlyArray<{
    actorId: string;
    subjectId: string;
    action: "user.login_succeeded" | "user.login_failed";
    organizationId?: string;
    occurredAt: Date;
  }> = [
    {
      actorId: "admin-1",
      subjectId: "user-1",
      action: "user.login_succeeded",
      organizationId: "org-a",
      occurredAt: new Date("2026-01-02T00:00:00.000Z"),
    },
    {
      actorId: "user-2",
      subjectId: "user-2",
      action: "user.login_failed",
      organizationId: "org-a",
      occurredAt: new Date("2026-01-05T00:00:00.000Z"),
    },
    {
      actorId: "user-2",
      subjectId: "user-2",
      action: "user.login_succeeded",
      organizationId: "org-b",
      occurredAt: new Date("2026-01-09T00:00:00.000Z"),
    },
    {
      actorId: "user-3",
      subjectId: "user-3",
      action: "user.login_failed",
      occurredAt: new Date("2026-01-11T00:00:00.000Z"),
    },
  ];

  for (const fixture of fixtures) {
    const entry = AuditLogEntry.append({
      action: fixture.action,
      actorId: fixture.actorId,
      subjectId: fixture.subjectId,
      metadata:
        fixture.organizationId === undefined ? {} : { organizationId: fixture.organizationId },
      previous,
      occurredAt: fixture.occurredAt,
    });
    await repository.append(entry);
    previous = entry;
  }

  return repository;
}

function sequences(entries: readonly AuditLogEntry[]): number[] {
  return entries.map((entry) => entry.sequence);
}

describe("QueryAuditEvents", () => {
  it("returns the whole log with no filter and no cursor", async () => {
    const query = new QueryAuditEvents(await seed());

    const result = await query.execute({});

    expect(sequences(result.entries)).toEqual([1, 2, 3, 4]);
    expect(result.hasMore).toBe(false);
    expect(result.nextCursor).toBeUndefined();
  });

  it("defaults the page size to 50", async () => {
    const repository = await seed();
    const spy = spyOnPaging(repository);

    await new QueryAuditEvents(repository).execute({});

    expect(spy.params.at(-1)?.limit).toBe(51);
  });

  describe("filters", () => {
    it("narrows to one actor", async () => {
      const result = await new QueryAuditEvents(await seed()).execute({
        filters: { actorId: "user-2" },
      });

      expect(sequences(result.entries)).toEqual([2, 3]);
    });

    it("narrows to one subject", async () => {
      const result = await new QueryAuditEvents(await seed()).execute({
        filters: { subjectId: "user-1" },
      });

      expect(sequences(result.entries)).toEqual([1]);
    });

    it("narrows to one action", async () => {
      const result = await new QueryAuditEvents(await seed()).execute({
        filters: { action: "user.login_failed" },
      });

      expect(sequences(result.entries)).toEqual([2, 4]);
    });

    it("narrows to one organization", async () => {
      const result = await new QueryAuditEvents(await seed()).execute({
        filters: { organizationId: "org-b" },
      });

      expect(sequences(result.entries)).toEqual([3]);
    });

    it("applies a date range inclusively", async () => {
      const result = await new QueryAuditEvents(await seed()).execute({
        filters: {
          fromDate: new Date("2026-01-05T00:00:00.000Z"),
          toDate: new Date("2026-01-09T00:00:00.000Z"),
        },
      });

      expect(sequences(result.entries)).toEqual([2, 3]);
    });

    it("combines filters that must all hold", async () => {
      const result = await new QueryAuditEvents(await seed()).execute({
        filters: { actorId: "user-2", action: "user.login_succeeded" },
      });

      expect(sequences(result.entries)).toEqual([3]);
    });

    it("yields nothing for a filter no entry satisfies", async () => {
      const result = await new QueryAuditEvents(await seed()).execute({
        filters: { actorId: "nobody" },
      });

      expect(result.entries).toEqual([]);
      expect(result.hasMore).toBe(false);
      expect(result.nextCursor).toBeUndefined();
    });
  });

  describe("cursor pagination", () => {
    it("continues after the cursor rather than replaying it", async () => {
      const result = await new QueryAuditEvents(await seed()).execute({ cursor: 2 });

      expect(sequences(result.entries)).toEqual([3, 4]);
    });

    it("reports the last returned sequence as the next cursor", async () => {
      const query = new QueryAuditEvents(await seed());

      const first = await query.execute({ limit: 2 });
      const second = await query.execute({ limit: 2, cursor: first.nextCursor });

      expect(first.hasMore).toBe(true);
      expect(first.nextCursor).toBe(2);
      expect(sequences(second.entries)).toEqual([3, 4]);
      expect(second.hasMore).toBe(false);
    });

    it("walks a full page boundary without duplicating an entry", async () => {
      const query = new QueryAuditEvents(await seed());

      const all: number[] = [];
      let cursor: number | undefined;
      for (let guard = 0; guard < 10; guard += 1) {
        const page = await query.execute({ limit: 1, cursor });
        all.push(...sequences(page.entries));
        if (!page.hasMore) break;
        cursor = page.nextCursor;
      }

      expect(all).toEqual([1, 2, 3, 4]);
    });

    it("keeps the cursor in the same units as the filter, not the row count", async () => {
      const result = await new QueryAuditEvents(await seed()).execute({
        cursor: 1,
        filters: { action: "user.login_succeeded" },
      });

      expect(sequences(result.entries)).toEqual([3]);
    });
  });
});

/** Records the parameters the use case passes down, to assert page sizing. */
function spyOnPaging(repository: InMemoryAuditLogRepository): { params: { limit: number }[] } {
  const params: { limit: number }[] = [];
  const original = repository.findWithFilters.bind(repository);
  repository.findWithFilters = (input) => {
    params.push({ limit: input.limit });
    return original(input);
  };
  return { params };
}
