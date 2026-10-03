import { PrismaClient } from "@verixa/database";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { PrismaSessionRepository } from "../persistence/prisma-session-repository.js";
import { sessionRepositoryContract } from "./contracts/session-repository.contract.js";

/**
 * Database helpers for test setup. These are light wrappers around standard
 * test database configuration.
 */
const DEFAULT_TEST_DATABASE_URL = "postgres://verixa:verixa@localhost:5432/verixa_test";

function testDatabaseUrl(): string {
  return process.env["TEST_DATABASE_URL"] ?? DEFAULT_TEST_DATABASE_URL;
}

async function canConnect(hostname: string, port: number): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1000);
    const socket = await (await import("node:net")).createConnection({
      host: hostname,
      port,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    socket.destroy();
    return true;
  } catch {
    return false;
  }
}

async function isDatabaseAvailable(): Promise<boolean> {
  const url = new URL(testDatabaseUrl());
  return canConnect(url.hostname, Number(url.port || 5432));
}

async function databaseAvailability(): Promise<boolean> {
  const available = await isDatabaseAvailable();

  if (!available && process.env["REQUIRE_DATABASE_TESTS"] === "1") {
    throw new Error(
      `REQUIRE_DATABASE_TESTS=1 but no database is reachable at ${testDatabaseUrl()}. ` +
        "Database-backed tests must not silently skip in CI.",
    );
  }

  return available;
}

function createTestPrismaClient(): PrismaClient {
  return new PrismaClient({ datasources: { db: { url: testDatabaseUrl() } } });
}

/**
 * Run the SessionRepository contract test suite against PrismaSessionRepository
 * with a real Postgres database.
 *
 * Skips when no database is reachable, so `pnpm test` passes on a fresh clone
 * without Docker. CI sets REQUIRE_DATABASE_TESTS=1 so the skip cannot hide a
 * misconfigured pipeline.
 *
 * The same contract test suite runs against InMemorySessionRepository (in
 * in-memory-session-repository.spec.ts) and against this Prisma adapter,
 * verifying they both satisfy the same behavioral contract.
 */

const available = await databaseAvailability();

describe.skipIf(!available)("PrismaSessionRepository (Issue 083)", () => {
  let prisma: PrismaClient;
  const createdSessionIds: string[] = [];

  beforeAll(() => {
    prisma = createTestPrismaClient();
  });

  afterEach(async () => {
    // Clean up only the sessions created by this test run, by id.
    if (createdSessionIds.length > 0) {
      await prisma.session.deleteMany({ where: { id: { in: createdSessionIds } } });
      createdSessionIds.length = 0;
    }
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  // Default expiry policy for tests
  const testExpiryPolicy = await import("../../domain/value-objects/session-expiry-policy.js").then(
    (m) => new m.SessionExpiryPolicy("sliding", 15 * 60 * 1000),
  );

  describe("contract tests", () => {
    // Run the full contract suite against the Prisma adapter
    sessionRepositoryContract(() => new PrismaSessionRepository(prisma, testExpiryPolicy));
  });

  describe("index verification", () => {
    it("(userId, expiresAt) index is used for findActiveByUserId queries", async () => {
      const { createId } = await import("@verixa/shared-kernel");
      const { Session } = await import("../../domain/entities/session.js");

      const repository = new PrismaSessionRepository(prisma, testExpiryPolicy);
      const userId = createId<"UserId">();
      const session = Session.create({
        id: createId<"SessionId">(),
        userId,
        expiryPolicy: testExpiryPolicy,
      });

      createdSessionIds.push(session.id);
      await repository.save(session);

      // Verify the index is used by running EXPLAIN ANALYZE on the actual query pattern.
      // The query plan should show an Index Scan on sessions_user_id_expires_at_idx,
      // not a Seq Scan or Index Only Scan without the index.
      const explainResult = await prisma.$queryRawUnsafe<
        Array<{ "QUERY PLAN": string }>
      >(
        `EXPLAIN (FORMAT JSON, ANALYZE) 
         SELECT * FROM sessions 
         WHERE user_id = $1::uuid AND status = 'active' AND expires_at > now()`,
        userId,
      );

      const plan = JSON.stringify(explainResult);

      // Verify that the query plan includes an index scan on the expected index.
      // The index name is "sessions_user_id_expires_at_idx" as defined in the migration.
      expect(plan).toContain("sessions_user_id_expires_at_idx");

      // Also verify the query doesn't use a Seq Scan (sequential table scan),
      // which would indicate the index wasn't used.
      expect(plan).not.toMatch(/Seq Scan.*sessions/);

      // Functional test: verify the query returns the expected session
      const results = await repository.findActiveByUserId(userId);
      expect(results).toHaveLength(1);
      expect(results[0]?.id).toBe(session.id);
    });

    it("expiresAt index is used for expiry sweep queries", async () => {
      const { createId } = await import("@verixa/shared-kernel");
      const { Session } = await import("../../domain/entities/session.js");

      const repository = new PrismaSessionRepository(prisma, testExpiryPolicy);
      const userId = createId<"UserId">();

      // Create a session with a past expiry time to simulate an expired session
      const expiredSession = Session.reconstitute({
        id: createId<"SessionId">(),
        userId,
        createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
        lastSeenAt: new Date(Date.now() - 1 * 60 * 60 * 1000), // 1 hour ago
        expiresAt: new Date(Date.now() - 30 * 60 * 1000), // 30 minutes ago
        revokedAt: undefined,
        status: "active",
        expiryPolicy: testExpiryPolicy,
      });

      createdSessionIds.push(expiredSession.id);
      await repository.save(expiredSession);

      // Verify the expiresAt index is used for the expiry sweep query.
      // The expiry sweep query pattern: "SELECT * FROM sessions WHERE expires_at < now()"
      const explainResult = await prisma.$queryRawUnsafe<
        Array<{ "QUERY PLAN": string }>
      >(
        `EXPLAIN (FORMAT JSON, ANALYZE) 
         SELECT * FROM sessions 
         WHERE expires_at < now()`,
      );

      const plan = JSON.stringify(explainResult);

      // Verify the index is used.
      expect(plan).toContain("sessions_expires_at_idx");

      // Verify no sequential scan is used.
      expect(plan).not.toMatch(/Seq Scan.*sessions/);
    });
  });
});
