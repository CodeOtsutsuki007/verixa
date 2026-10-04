import type { DomainEvent, DomainEventHandler, DomainEventPublisher } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { AuditLogRepository } from "../../application/ports/audit-log-repository.js";
import { RecordAuditEvent } from "../../application/use-cases/record-audit-event.js";
import { InMemoryAuditLogRepository } from "../testing/in-memory-audit-repositories.js";

import { IdentityCredentialsAuditSubscriber } from "./identity-credentials-audit-subscriber.js";

class FakePublisher implements DomainEventPublisher {
  private readonly handlers = new Map<string, DomainEventHandler[]>();

  async publish(event: DomainEvent): Promise<void> {
    await Promise.all(
      (this.handlers.get(event.eventName) ?? []).map(async (handler) => handler(event)),
    );
  }

  subscribe<E extends DomainEvent>(eventName: string, handler: DomainEventHandler<E>): void {
    const handlers = this.handlers.get(eventName) ?? [];
    handlers.push(handler as DomainEventHandler);
    this.handlers.set(eventName, handlers);
  }
}

function event(
  eventName: string,
  aggregateId: string,
  fields: Readonly<Record<string, unknown>> = {},
): DomainEvent {
  return { eventName, aggregateId, occurredAt: new Date(1_700_000_000_000), ...fields };
}

describe("IdentityCredentialsAuditSubscriber", () => {
  it("records one correctly mapped audit entry for each supported event", async () => {
    const publisher = new FakePublisher();
    const repository = new InMemoryAuditLogRepository();
    new IdentityCredentialsAuditSubscriber(publisher, new RecordAuditEvent(repository));

    await publisher.publish(
      event("identity.user.registered", "user-1", { email: "user@example.test" }),
    );
    await publisher.publish(
      event("credentials.user.password_changed", "user-1", { method: "reset" }),
    );
    await publisher.publish(
      event("credentials.user.account_locked", "user-1", { reason: "too many attempts" }),
    );

    expect(repository.all()).toHaveLength(3);
    expect(repository.all().map((entry) => entry.action)).toEqual([
      "user.registered",
      "user.password_changed",
      "user.locked_out",
    ]);
    expect(repository.all()[0]?.metadata).toEqual({ email: "user@example.test" });
    expect(repository.all()[1]?.metadata).toEqual({ method: "reset" });
  });

  it("maps identity status changes without leaking an unknown event shape", async () => {
    const publisher = new FakePublisher();
    const repository = new InMemoryAuditLogRepository();
    new IdentityCredentialsAuditSubscriber(publisher, new RecordAuditEvent(repository));

    await publisher.publish(
      event("identity.user.status_changed", "user-1", {
        previousStatus: "pending",
        newStatus: "active",
        reason: "email verified",
      }),
    );

    expect(repository.all()[0]?.action).toBe("user.status_changed");
    expect(repository.all()[0]?.metadata).toEqual({
      previousStatus: "pending",
      newStatus: "active",
      reason: "email verified",
    });
  });

  it("contains audit-store failures instead of rejecting publisher delivery", async () => {
    const publisher = new FakePublisher();
    const errors: unknown[] = [];
    const repository: AuditLogRepository = {
      findLatest: () => Promise.reject(new Error("audit store unavailable")),
      append: () => Promise.resolve(),
      findFrom: () => Promise.resolve([]),
      findWithFilters: () => Promise.resolve([]),
      count: () => Promise.resolve(0),
    };
    const record = new RecordAuditEvent(repository, (error) => errors.push(error));
    new IdentityCredentialsAuditSubscriber(publisher, record);

    await expect(
      publisher.publish(event("identity.user.registered", "user-1")),
    ).resolves.toBeUndefined();

    expect(errors).toHaveLength(1);
  });
});
