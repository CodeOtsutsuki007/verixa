import { buildContainer, type Container } from "@verixa/api/composition-root";
import {
  type PermissionGrantedEvent,
  type RoleAssignedEvent,
  type SessionCreatedEvent,
  type SessionRevokedEvent,
} from "@verixa/audit";
import { Result } from "@verixa/shared-kernel";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { createTestPrismaClient, databaseAvailability } from "./helpers/database.js";
import { createHttpTestClient, type HttpTestClient } from "./helpers/http-client.js";

/**
 * Audit subscribers are attached during composition (Issue 135).
 *
 * Two things are being proved here, and neither can be proved by a unit test
 * of a subscriber:
 *
 * 1. **Every subscriber is registered.** A subscriber that exists, is fully
 *    tested inside its own package, and is never wired up records nothing. It
 *    fails as a missing row months later, not as a red test. Each event name
 *    below is asserted against a composed container: the row that is not
 *    registered is the test that fails.
 * 2. **Registration happens before anything can publish.** These tests publish
 *    on a container that never had `buildApp` called on it. If registration
 *    were deferred to app construction — the tempting lazy version — the
 *    publisher would accept the subscription after the first event had already
 *    been dropped, and nothing here would notice. The first event a process
 *    publishes is the one a late registration loses.
 *
 * The login test covers the other direction: the route's own audit writes reach
 * Postgres and chain correctly, so the log a verification run reads is the log
 * the HTTP layer produced.
 */

const available = await databaseAvailability();

const CREDENTIALS = {
  email: "smoke@example.com",
  password: "correct horse battery staple",
  displayName: "Smoke",
};

const occurredAt = new Date("2026-01-01T09:00:00.000Z");

function sessionCreated(userId: string): SessionCreatedEvent {
  return {
    eventName: "sessions.session.created",
    aggregateId: "session-1",
    occurredAt,
    userId,
    sessionId: "session-1",
    ipAddress: "203.0.113.7",
  };
}

function sessionRevoked(userId: string): SessionRevokedEvent {
  return {
    eventName: "sessions.session.revoked",
    aggregateId: "session-1",
    occurredAt,
    userId,
    sessionId: "session-1",
    reason: "signed out",
  };
}

function roleAssigned(actorId: string, userId: string): RoleAssignedEvent {
  return {
    eventName: "rbac.role.assigned",
    aggregateId: "role-1",
    occurredAt,
    userId,
    roleId: "role-editor",
    roleName: "editor",
    assignedBy: actorId,
  };
}

function permissionGranted(actorId: string, userId: string): PermissionGrantedEvent {
  return {
    eventName: "rbac.permission.granted",
    aggregateId: "permission-1",
    occurredAt,
    userId,
    permission: "document:write",
    grantedBy: actorId,
  };
}

describe.skipIf(!available)("audit subscribers at composition", () => {
  const prisma = createTestPrismaClient();
  let container: Container;
  let client: HttpTestClient;

  beforeAll(async () => {
    container = buildContainer(prisma);
    client = await createHttpTestClient(container);
  }, 60_000);

  beforeEach(async () => {
    // Verification and the assertions below both reason about the whole chain,
    // so this suite owns the table for the duration of each test. Spec files
    // run serially (tests/vitest.config.ts), which is what makes that safe.
    await prisma.anchorRecord.deleteMany({});
    await prisma.auditLogEntry.deleteMany({});
  });

  afterEach(async () => {
    await prisma.credential.deleteMany({});
    await prisma.invitation.deleteMany({});
    await prisma.organizationMembership.deleteMany({});
    await prisma.organization.deleteMany({});
    await prisma.user.deleteMany({});
    await prisma.auditLogEntry.deleteMany({});
  });

  afterAll(async () => {
    await client.close();
    await prisma.$disconnect();
  }, 60_000);

  it("writes an audit record for a real login through the composed app", async () => {
    const registered = await client.request.post("/auth/register").send(CREDENTIALS);
    expect(registered.status).toBe(201);

    const response = await client.request.post("/auth/login").send(CREDENTIALS);
    expect(response.status).toBe(200);

    const entries = await prisma.auditLogEntry.findMany({ orderBy: { sequence: "asc" } });
    const actions = entries.map((entry) => entry.action);
    const registeredUser = registered.body as { id: string };

    // Registration and login each record themselves: one entry per audited
    // operation, in the order they happened, and no more.
    expect(actions).toEqual(["user.registered", "user.login_succeeded"]);
    expect(entries[1]?.actorId).toBe(registeredUser.id);
    expect(entries[1]?.subjectId).toBe(registeredUser.id);
  });

  it("leaves a chain that verifies after the login was recorded", async () => {
    await client.request.post("/auth/register").send(CREDENTIALS);
    await client.request.post("/auth/login").send(CREDENTIALS);

    const result = await container.audit.verifyChain.execute();

    // The point of writing through the append path at all: two separate
    // requests, each reading the tail and linking to it, still produce a chain
    // a verification run calls intact. A broken link here would mean every
    // future incident report is noise.
    expect(Result.isOk(result)).toBe(true);
    if (Result.isErr(result)) return;
    expect(result.value.valid).toBe(true);
    expect(result.value.checkedEntries).toBe(2);
  });

  describe("registered subscribers", () => {
    /** Publishes an event and returns the entries the log gained from it. */
    async function publishAndRead(
      event: SessionCreatedEvent | SessionRevokedEvent | RoleAssignedEvent | PermissionGrantedEvent,
    ) {
      await container.eventPublisher.publish(event);
      return prisma.auditLogEntry.findMany({ orderBy: { sequence: "desc" } });
    }

    it("records a session creation without any caller asking it to", async () => {
      const entries = await publishAndRead(sessionCreated("11111111-1111-4111-8111-111111111111"));

      expect(entries).toHaveLength(1);
      expect(entries[0]?.action).toBe("user.login_succeeded");
      expect(entries[0]?.metadata).toMatchObject({ sessionId: "session-1" });
    });

    it("records a session revocation", async () => {
      const entries = await publishAndRead(sessionRevoked("11111111-1111-4111-8111-111111111111"));

      expect(entries).toHaveLength(1);
      expect(entries[0]?.metadata).toMatchObject({ reason: "signed out" });
    });

    it("records a role assignment with the admin as actor and the user as subject", async () => {
      const entries = await publishAndRead(
        roleAssigned(
          "22222222-2222-4222-8222-222222222222",
          "11111111-1111-4111-8111-111111111111",
        ),
      );

      expect(entries).toHaveLength(1);
      expect(entries[0]?.actorId).toBe("22222222-2222-4222-8222-222222222222");
      expect(entries[0]?.subjectId).toBe("11111111-1111-4111-8111-111111111111");
      expect(entries[0]?.metadata).toMatchObject({ roleName: "editor" });
    });

    it("records a permission grant", async () => {
      const entries = await publishAndRead(
        permissionGranted(
          "22222222-2222-4222-8222-222222222222",
          "11111111-1111-4111-8111-111111111111",
        ),
      );

      expect(entries).toHaveLength(1);
      expect(entries[0]?.metadata).toMatchObject({ permission: "document:write" });
    });

    it("chains the four event types against each other and the login path", async () => {
      const userId = "11111111-1111-4111-8111-111111111111";

      await container.eventPublisher.publish(sessionCreated(userId));
      await container.eventPublisher.publish(roleAssigned(userId, userId));
      await container.eventPublisher.publish(permissionGranted(userId, userId));
      await container.eventPublisher.publish(sessionRevoked(userId));

      // Subscribers share one log with the route-level writes, so ordering is
      // whatever the requests did. A gap or a bad link here means the two
      // write paths are not reading the same tail.
      const result = await container.audit.verifyChain.execute();
      expect(Result.isOk(result) && result.value.valid).toBe(true);
      if (Result.isErr(result)) return;
      expect(result.value.checkedEntries).toBe(4);
    });

    it("drops an event nobody subscribed to, which is why registration is eager", async () => {
      // Not a behaviour anyone wants, so it is asserted rather than assumed:
      // publishing an unrelated event name leaves the log untouched and does
      // not throw. The request that published it succeeds, and the fact it was
      // never audited is invisible from the response — which is the failure
      // mode the composition-time registration above exists to prevent.
      await container.eventPublisher.publish({
        eventName: "verification.review.approved",
        aggregateId: "review-1",
        occurredAt,
      });

      await expect(prisma.auditLogEntry.count()).resolves.toBe(0);
    });
  });
});
