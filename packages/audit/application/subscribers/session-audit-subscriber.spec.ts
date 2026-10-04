import { describe, expect, it } from "vitest";

import { InMemoryAuditLogRepository } from "../../infrastructure/testing/in-memory-audit-repositories.js";
import { RecordAuditEvent } from "../use-cases/record-audit-event.js";

import {
  SessionCreatedAuditSubscriber,
  type SessionCreatedEvent,
  SessionRevokedAuditSubscriber,
  type SessionRevokedEvent,
} from "./session-audit-subscriber.js";

/**
 * Exercises subscribers against the real `RecordAuditEvent` and an in-memory
 * log rather than a mocked recorder. What has to be proven is that an event
 * arriving over the publisher boundary ends up as an entry in the audit log,
 * and a mock would only prove the subscriber called the method it was told to
 * call — the mapping, the metadata and the chained append would all go
 * unexamined.
 */
function harness(): {
  repository: InMemoryAuditLogRepository;
  created: SessionCreatedAuditSubscriber;
  revoked: SessionRevokedAuditSubscriber;
} {
  const repository = new InMemoryAuditLogRepository();
  const recordEvent = new RecordAuditEvent(repository);
  return {
    repository,
    created: new SessionCreatedAuditSubscriber(recordEvent),
    revoked: new SessionRevokedAuditSubscriber(recordEvent),
  };
}

const occurredAt = new Date("2026-01-01T09:00:00.000Z");

function sessionCreated(
  context: { ipAddress: string; userAgent: string } | undefined = undefined,
): SessionCreatedEvent {
  return {
    eventName: "sessions.session.created",
    aggregateId: "session-1",
    occurredAt,
    userId: "user-1",
    sessionId: "session-1",
    ...context,
  };
}

function sessionRevoked(reason?: string): SessionRevokedEvent {
  return {
    eventName: "sessions.session.revoked",
    aggregateId: "session-1",
    occurredAt,
    userId: "user-1",
    sessionId: "session-1",
    ...(reason === undefined ? {} : { reason }),
  };
}

describe("SessionCreatedAuditSubscriber", () => {
  it("records a successful login attributed to the user", async () => {
    const { repository, created } = harness();

    await created.handle(sessionCreated());

    const entry = await repository.findLatest();
    expect(entry?.action).toBe("user.login_succeeded");
    expect(entry?.actorId).toBe("user-1");
    expect(entry?.subjectId).toBe("user-1");
    expect(entry?.metadata).toEqual({ sessionId: "session-1" });
  });

  it("carries the client context through to metadata when it is present", async () => {
    const { repository, created } = harness();

    await created.handle(sessionCreated({ ipAddress: "203.0.113.7", userAgent: "curl/8.9.1" }));

    const entry = await repository.findLatest();
    expect(entry?.metadata).toEqual({
      sessionId: "session-1",
      ipAddress: "203.0.113.7",
      userAgent: "curl/8.9.1",
    });
  });

  it("omits context keys the event did not carry rather than storing empty strings", async () => {
    const { repository, created } = harness();
    const partial: SessionCreatedEvent = {
      eventName: "sessions.session.created",
      aggregateId: "session-1",
      occurredAt,
      userId: "user-1",
      sessionId: "session-1",
      userAgent: "curl/8.9.1",
    };

    await created.handle(partial);

    expect(Object.keys((await repository.findLatest())?.metadata ?? {})).toEqual([
      "sessionId",
      "userAgent",
    ]);
  });
});

describe("SessionRevokedAuditSubscriber", () => {
  it("records the revocation with the session it withdrew", async () => {
    const { repository, revoked } = harness();

    await revoked.handle(sessionRevoked());

    const entry = await repository.findLatest();
    expect(entry?.actorId).toBe("user-1");
    expect(entry?.metadata).toEqual({ sessionId: "session-1" });
  });

  it("keeps the stated reason, which is the part an investigator needs", async () => {
    const { repository, revoked } = harness();

    await revoked.handle(sessionRevoked("user signed out"));

    const entry = await repository.findLatest();
    expect(entry?.metadata).toEqual({ sessionId: "session-1", reason: "user signed out" });
  });

  it("appends to the same chain as the creation that precedes it", async () => {
    const { repository, created, revoked } = harness();

    await created.handle(sessionCreated());
    await revoked.handle(sessionRevoked());

    const entries = repository.all();
    expect(entries).toHaveLength(2);
    expect(entries[1]?.previousHash).toBe(entries[0]?.hash);
    expect(entries[1]?.sequence).toBe(2);
    expect(entries.every((entry) => entry.hasValidHash)).toBe(true);
  });
});
