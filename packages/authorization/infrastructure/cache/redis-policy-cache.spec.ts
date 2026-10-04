import { Redis } from "ioredis";
import { afterAll, afterEach, describe, expect, it } from "vitest";

import type { CachedPolicy, PolicyCacheKey } from "../../application/ports/policy-cache.js";

import { RedisPolicyCache } from "./redis-policy-cache.js";
import { ResilientPolicyCache } from "./resilient-policy-cache.js";
import { policyCacheContract } from "./testing/policy-cache-contract.js";
import { startTestRedis, type TestRedis } from "./testing/redis-harness.js";

/**
 * Runs the same {@link policyCacheContract} the in-memory adapter passes against
 * a real Redis, plus the two guarantees only a real store can make: that entries
 * actually expire, and that a publish invalidates the previous generation's
 * entries immediately.
 *
 * Skips when no Redis is reachable and `TEST_REDIS_URL` is unset; see
 * `testing/redis-harness.ts`. `REQUIRE_REDIS_TESTS=1` turns the skip into a
 * failure, which is what the CI job does.
 */

const redis = await startTestRedis();

const KEY: PolicyCacheKey = { resourceType: "document", action: "document:read" };
const OTHER_KEY: PolicyCacheKey = { resourceType: "document", action: "document:write" };

function entry(marker: string, policyVersion = "v1"): CachedPolicy<{ marker: string }> {
  return { value: { marker }, policyVersion, cachedAt: new Date().toISOString() };
}

describe.skipIf(redis === undefined)("RedisPolicyCache (real Redis)", () => {
  // Safe under skipIf: this body only runs when redis is defined.
  const test = redis as TestRedis;

  afterEach(async () => {
    // Each test starts from an empty keyspace, so a leftover entry can never make
    // a missing-invalidation bug look like a hit.
    await test.client.flushall();
  });

  afterAll(async () => {
    await test.stop();
  });

  policyCacheContract(() => new RedisPolicyCache(test.client));

  it("stops serving an entry after the Redis TTL expires", async () => {
    const cache = new RedisPolicyCache(test.client);

    await cache.set(KEY, entry("read-ast"), { ttlSeconds: 1 });
    expect((await cache.get<{ marker: string }>(KEY))?.value).toEqual({ marker: "read-ast" });

    // Redis's minimum EX granularity is one second; wait comfortably past it.
    await new Promise((resolve) => setTimeout(resolve, 1500));

    await expect(cache.get(KEY)).resolves.toBeUndefined();
  });

  it("makes every entry of a resource type unreachable on invalidation, immediately", async () => {
    const cache = new RedisPolicyCache(test.client);

    await cache.set(KEY, entry("read-ast"));
    await cache.set(OTHER_KEY, entry("write-ast"));

    // What a policy publish calls. The assertion is that the very next read
    // misses — no TTL wait, no propagation delay to reason about.
    await cache.invalidateResourceType("document");

    await expect(cache.get(KEY)).resolves.toBeUndefined();
    await expect(cache.get(OTHER_KEY)).resolves.toBeUndefined();
  });

  it("does not make another resource type's entries unreachable", async () => {
    const cache = new RedisPolicyCache(test.client);
    const invoice: PolicyCacheKey = { resourceType: "invoice", action: "invoice:read" };

    await cache.set(KEY, entry("read-ast"));
    await cache.set(invoice, entry("invoice-ast"));

    await cache.invalidateResourceType("document");

    expect((await cache.get<{ marker: string }>(invoice))?.value).toEqual({
      marker: "invoice-ast",
    });
  });

  it("stores entries under the configured key prefix", async () => {
    const cache = new RedisPolicyCache(test.client, { keyPrefix: "test:policy:" });

    await cache.set(KEY, entry("read-ast"));

    const keys = await test.client.keys("test:policy:*");
    expect(keys.length).toBeGreaterThan(0);
  });

  it("treats a value it cannot parse as a miss rather than a failed request", async () => {
    const cache = new RedisPolicyCache(test.client);

    await cache.set(KEY, entry("read-ast"));
    const firstKey = (await test.client.keys("policy:cache:entry:*"))[0];
    if (firstKey === undefined) {
      throw new Error("expected the adapter to have written exactly one entry key");
    }
    // Corrupt the entry in place, whatever the adapter chose to name it.
    await test.client.set(firstKey, "not json", "EX", 60);

    // A corrupt entry is a miss: the caller recomputes from the source of truth,
    // which is always correct, instead of the request failing.
    await expect(cache.get(KEY)).resolves.toBeUndefined();
    expect(await test.client.exists(firstKey)).toBe(0);
  });
});

// Runs everywhere — it needs an *unreachable* Redis, not a working one, so it is
// deliberately outside the skipIf above.
describe("RedisPolicyCache failure behaviour", () => {
  function unreachableRedis(): Redis {
    // Port 6390 has nothing listening; with the offline queue disabled the command
    // rejects immediately rather than buffering until a (never-arriving)
    // connection succeeds.
    const client = new Redis({
      host: "127.0.0.1",
      port: 6390,
      lazyConnect: true,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
      retryStrategy: () => null,
    });
    client.on("error", () => {
      /* expected: there is nothing to connect to */
    });
    return client;
  }

  it("lets the failure propagate, so the caller decides what an outage means", async () => {
    const client = unreachableRedis();
    const cache = new RedisPolicyCache(client);

    await expect(cache.get(KEY)).rejects.toThrowError();
    await expect(cache.set(KEY, entry("read-ast"))).rejects.toThrowError();
    await expect(cache.invalidateResourceType("document")).rejects.toThrowError();

    client.disconnect();
  });

  it("degrades to a miss once wrapped in the resilient decorator", async () => {
    const client = unreachableRedis();
    const degraded: string[] = [];
    const cache = new ResilientPolicyCache(new RedisPolicyCache(client), {
      onDegrade: (operation) => degraded.push(operation),
    });

    // The acceptance criterion: cache unavailability degrades to direct
    // evaluation (a miss the caller resolves itself) instead of failing.
    await expect(cache.get(KEY)).resolves.toBeUndefined();
    await cache.set(KEY, entry("read-ast"));
    expect(degraded).toEqual(["get", "set"]);

    client.disconnect();
  });
});
