import { Result } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";
import { AUDIT_PERMISSIONS, type AuditReader } from "../../domain/policies/audit-access-policy.js";
import {
  InMemoryAuditEventReader,
  InMemoryAuditLogRepository,
} from "../../infrastructure/testing/in-memory-audit-repositories.js";
import { AuditReadNotRecordedError } from "../audit-read-access.js";

import { MAX_AUDIT_QUERY_PAGE_SIZE, QueryAuditEvents } from "./query-audit-events.js";
import { RecordAuditEvent } from "./record-audit-event.js";

const auditor: AuditReader = {
  actorId: "auditor-1",
  organizationId: "org-a",
  permissions: new Set([AUDIT_PERMISSIONS.query]),
};

function entries(count: number, actorId = "user-1"): AuditLogEntry[] {
  const chain: AuditLogEntry[] = [];
  for (let index = 0; index < count; index += 1) {
    chain.push(
      AuditLogEntry.append({ action: "user.login_succeeded", actorId, previous: chain.at(-1) }),
    );
  }
  return chain;
}

/** An audit store that is down: every append fails. */
class UnavailableAuditLogRepository extends InMemoryAuditLogRepository {
  override append(): Promise<void> {
    return Promise.reject(new Error("connection refused"));
  }
}

describe("QueryAuditEvents", () => {
  let auditLog: InMemoryAuditLogRepository;
  let events: InMemoryAuditEventReader;
  let queryAuditEvents: QueryAuditEvents;

  beforeEach(() => {
    auditLog = new InMemoryAuditLogRepository();
    events = new InMemoryAuditEventReader();
    queryAuditEvents = new QueryAuditEvents(events, new RecordAuditEvent(auditLog));
  });

  it("returns the reader's own organization's entries", async () => {
    const own = entries(2);
    events.seed("org-a", ...own);
    events.seed("org-b", ...entries(3));

    const result = await queryAuditEvents.execute({ reader: auditor, organizationId: "org-a" });

    expect(Result.isOk(result) && result.value).toEqual(own);
  });

  it("records the query itself as an audit event, naming who asked and for what", async () => {
    await queryAuditEvents.execute({
      reader: auditor,
      organizationId: "org-a",
      actorId: "user-1",
      from: new Date("2026-01-01T00:00:00.000Z"),
    });

    const [recorded] = auditLog.all();
    expect(recorded?.action).toBe("audit.queried");
    expect(recorded?.actorId).toBe("auditor-1");
    expect(recorded?.subjectId).toBe("org-a");
    expect(recorded?.metadata).toEqual({
      organizationId: "org-a",
      "filter.actorId": "user-1",
      "filter.from": "2026-01-01T00:00:00.000Z",
    });
  });

  it("rejects a cross-organization query without reading anything", async () => {
    events.seed("org-b", ...entries(3));

    const result = await queryAuditEvents.execute({ reader: auditor, organizationId: "org-b" });

    expect(Result.isErr(result) && result.error.code).toBe("AUDIT_ACCESS_DENIED");
    expect(events.reads).toEqual([]);
  });

  it("records the refused cross-organization attempt", async () => {
    await queryAuditEvents.execute({ reader: auditor, organizationId: "org-b" });

    const [recorded] = auditLog.all();
    expect(recorded?.action).toBe("audit.access_denied");
    expect(recorded?.actorId).toBe("auditor-1");
    expect(recorded?.subjectId).toBe("org-b");
    expect(recorded?.metadata).toMatchObject({
      operation: "query",
      reason: "cross_organization",
      actorOrganizationId: "org-a",
    });
  });

  it("rejects a reader without audit:query", async () => {
    const result = await queryAuditEvents.execute({
      reader: { ...auditor, permissions: new Set() },
      organizationId: "org-a",
    });

    expect(Result.isErr(result) && result.error.code).toBe("AUDIT_ACCESS_DENIED");
    expect(events.reads).toEqual([]);
  });

  it("refuses to read when the query cannot be recorded", async () => {
    events.seed("org-a", ...entries(1));
    const unrecorded = new QueryAuditEvents(
      events,
      new RecordAuditEvent(new UnavailableAuditLogRepository()),
    );

    const result = await unrecorded.execute({ reader: auditor, organizationId: "org-a" });

    expect(Result.isErr(result) && result.error).toBeInstanceOf(AuditReadNotRecordedError);
    expect(events.reads).toEqual([]);
  });

  it("caps the page size so a query cannot stand in for an export", async () => {
    events.seed("org-a", ...entries(MAX_AUDIT_QUERY_PAGE_SIZE + 20));

    const result = await queryAuditEvents.execute({
      reader: auditor,
      organizationId: "org-a",
      limit: 1_000_000,
    });

    expect(Result.isOk(result) && result.value.length).toBe(MAX_AUDIT_QUERY_PAGE_SIZE);
  });

  it("scopes the read to the authorized organization", async () => {
    await queryAuditEvents.execute({ reader: auditor, organizationId: "org-a" });

    expect(events.reads).toHaveLength(1);
    expect(events.reads[0]?.organizationId).toBe("org-a");
  });
});
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
