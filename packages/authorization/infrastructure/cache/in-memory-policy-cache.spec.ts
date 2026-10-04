import { describe, expect, it } from "vitest";

import type { CachedPolicy, PolicyCacheKey } from "../../application/ports/policy-cache.js";

import { InMemoryPolicyCache } from "./in-memory-policy-cache.js";
import { policyCacheContract } from "./testing/policy-cache-contract.js";

const KEY: PolicyCacheKey = { resourceType: "document", action: "document:read" };

function entry(marker: string, policyVersion = "v1"): CachedPolicy<{ marker: string }> {
  return { value: { marker }, policyVersion, cachedAt: new Date().toISOString() };
}

// The Redis adapter is held to the same expectations, so the fake and the real
// store are actually interchangeable rather than merely similar.
policyCacheContract(() => new InMemoryPolicyCache());

describe("InMemoryPolicyCache", () => {
  it("expires an entry once its TTL passes on the injected clock", async () => {
    let now = 0;
    const cache = new InMemoryPolicyCache({ now: () => now });

    await cache.set(KEY, entry("read-ast"), { ttlSeconds: 30 });
    expect((await cache.get<{ marker: string }>(KEY))?.value).toEqual({ marker: "read-ast" });

    // 29.999s later the entry is still live — a TTL that expired early would be
    // a correctness bug for the caller relying on the memory bound.
    now = 29_999;
    expect((await cache.get<{ marker: string }>(KEY))?.value).toEqual({ marker: "read-ast" });

    now = 30_000;
    await expect(cache.get(KEY)).resolves.toBeUndefined();
  });

  it("applies the configured default TTL when a caller names none", async () => {
    let now = 0;
    const cache = new InMemoryPolicyCache({ defaultTtlSeconds: 5, now: () => now });

    await cache.set(KEY, entry("read-ast"));

    now = 4_000;
    expect((await cache.get<{ marker: string }>(KEY))?.value).toEqual({ marker: "read-ast" });

    now = 5_000;
    await expect(cache.get(KEY)).resolves.toBeUndefined();
  });

  it("reports the generations an entry written now would live under", async () => {
    const cache = new InMemoryPolicyCache();

    expect(cache.generationOf("document")).toBe("0:0");

    await cache.invalidateResourceType("document");
    expect(cache.generationOf("document")).toBe("0:1");
    // A different resource type keeps its generation: invalidation is scoped to
    // what actually changed, not global for convenience.
    expect(cache.generationOf("invoice")).toBe("0:0");

    await cache.invalidateAll();
    expect(cache.generationOf("document")).toBe("1:1");
    expect(cache.generationOf("invoice")).toBe("1:0");
  });

  it("makes entries written under a superseded generation unreachable at once", async () => {
    const cache = new InMemoryPolicyCache();

    await cache.set(KEY, entry("stale-ast", "v1"));
    await cache.invalidateResourceType("document");

    // Not merely expired — the key the reader computes no longer matches the key
    // the entry was written under, which is what "no stale window" means.
    await expect(cache.get(KEY)).resolves.toBeUndefined();

    await cache.set(KEY, entry("fresh-ast", "v2"));
    const reread = await cache.get<{ marker: string }>(KEY);
    expect(reread?.value).toEqual({ marker: "fresh-ast" });
    expect(reread?.policyVersion).toBe("v2");
  });
});
