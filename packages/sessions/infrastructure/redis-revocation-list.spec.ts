import { Redis } from "ioredis";
import { afterAll, afterEach, describe, expect, it } from "vitest";

import { createSessionId } from "../domain/value-objects/session-id.js";

import { RedisRevocationList } from "./redis-revocation-list.js";
import { revocationListContract } from "./testing/contracts/revocation-list.contract.js";
import { startTestRedis, type TestRedis } from "./testing/redis-harness.js";

/**
 * Runs the same {@link revocationListContract} the in-memory fake passes against
 * a real Redis, plus the two guarantees only a real store can make: that entries
 * actually expire, and that the adapter fails closed when Redis is unreachable.
 *
 * Skips when no Redis is reachable and Docker isn't available; see
 * `redis-harness.ts`. `REQUIRE_REDIS_TESTS=1` turns the skip into a failure.
 */

const redis = await startTestRedis();

describe.skipIf(redis === undefined)("RedisRevocationList (real Redis)", () => {
  // Safe under skipIf: this body only runs when redis is defined.
  const test = redis as TestRedis;

  afterEach(async () => {
    // Keep each test's keys from leaking into the next.
    await test.client.flushall();
  });

  afterAll(async () => {
    await test.stop();
  });

  revocationListContract(() => new RedisRevocationList(test.client));

  it("stops reporting a session as revoked after the Redis TTL expires", async () => {
    const list = new RedisRevocationList(test.client);
    const sessionId = createSessionId();

    await list.revoke(sessionId, 1);
    expect(await list.isRevoked(sessionId)).toBe(true);

    // Redis's minimum EX granularity is one second; wait comfortably past it.
    await new Promise((resolve) => setTimeout(resolve, 1500));

    expect(await list.isRevoked(sessionId)).toBe(false);
  });

  it("stores the entry under the configured key prefix", async () => {
    const list = new RedisRevocationList(test.client, { keyPrefix: "denylist:" });
    const sessionId = createSessionId();

    await list.revoke(sessionId, 60);

    await expect(test.client.exists(`denylist:${sessionId}`)).resolves.toBe(1);
  });
});

// Runs everywhere — it needs an *unreachable* Redis, not a working one, so it is
// deliberately outside the skipIf above.
describe("RedisRevocationList fail-closed behavior", () => {
  it("treats a session as revoked when Redis cannot be reached", async () => {
    // Port 6390 has nothing listening; with the offline queue disabled the
    // command rejects immediately rather than buffering until a (never-arriving)
    // connection succeeds.
    const unreachable = new Redis({
      host: "127.0.0.1",
      port: 6390,
      lazyConnect: true,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
      retryStrategy: () => null,
    });
    unreachable.on("error", () => {
      /* expected: there is nothing to connect to */
    });

    const list = new RedisRevocationList(unreachable);

    // The safety-critical assertion: cannot check ⇒ assume revoked.
    await expect(list.isRevoked(createSessionId())).resolves.toBe(true);

    unreachable.disconnect();
  });
});
