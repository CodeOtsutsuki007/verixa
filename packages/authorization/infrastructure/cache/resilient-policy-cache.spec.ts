import { describe, expect, it } from "vitest";

import type {
  CachedPolicy,
  PolicyCache,
  PolicyCacheKey,
  PolicyCacheSetOptions,
} from "../../application/ports/policy-cache.js";

import { InMemoryPolicyCache } from "./in-memory-policy-cache.js";
import { ResilientPolicyCache } from "./resilient-policy-cache.js";
import { policyCacheContract } from "./testing/policy-cache-contract.js";

const KEY: PolicyCacheKey = { resourceType: "document", action: "document:read" };

const ENTRY: CachedPolicy<{ marker: string }> = {
  value: { marker: "read-ast" },
  policyVersion: "v1",
  cachedAt: new Date().toISOString(),
};

/** A port that fails everything, standing in for an unreachable Redis. */
class UnavailablePolicyCache implements PolicyCache {
  readonly operations: string[] = [];

  async get<TValue>(_key: PolicyCacheKey): Promise<CachedPolicy<TValue> | undefined> {
    this.operations.push("get");
    throw new Error("redis is unreachable");
  }

  async set<TValue>(
    _key: PolicyCacheKey,
    _entry: CachedPolicy<TValue>,
    _options?: PolicyCacheSetOptions,
  ): Promise<void> {
    this.operations.push("set");
    throw new Error("redis is unreachable");
  }

  async invalidate(_key: PolicyCacheKey): Promise<void> {
    this.operations.push("invalidate");
    throw new Error("redis is unreachable");
  }

  async invalidateResourceType(_resourceType: string): Promise<void> {
    this.operations.push("invalidateResourceType");
    throw new Error("redis is unreachable");
  }

  async invalidateAll(): Promise<void> {
    this.operations.push("invalidateAll");
    throw new Error("redis is unreachable");
  }
}

/** A healthy store double, so the no-degradation path is covered too. */
class WorkingPolicyCache implements PolicyCache {
  private stored: { value: unknown; policyVersion: string; cachedAt: string } | undefined;

  async get<TValue>(_key: PolicyCacheKey): Promise<CachedPolicy<TValue> | undefined> {
    if (this.stored === undefined) {
      return undefined;
    }
    return { ...this.stored, value: this.stored.value as TValue };
  }

  async set<TValue>(_key: PolicyCacheKey, entry: CachedPolicy<TValue>): Promise<void> {
    this.stored = entry;
  }

  async invalidate(_key: PolicyCacheKey): Promise<void> {
    this.stored = undefined;
  }

  async invalidateResourceType(_resourceType: string): Promise<void> {
    this.stored = undefined;
  }

  async invalidateAll(): Promise<void> {
    this.stored = undefined;
  }
}

// Wrapping is not a special mode: a decorated cache is held to the same contract
// suite as the undecorated one, which is what makes "swap the decorator in" a
// safe change to make.
policyCacheContract(() => new ResilientPolicyCache(new InMemoryPolicyCache()));

describe("ResilientPolicyCache", () => {
  it("turns a failed read into a miss — never into a decision", async () => {
    const delegate = new UnavailablePolicyCache();
    const degraded: string[] = [];
    const cache = new ResilientPolicyCache(delegate, {
      onDegrade: (operation) => degraded.push(operation),
    });

    // The call resolves: the caller recomputes from the source of truth, which is
    // the whole point of degrading rather than failing the request.
    await expect(cache.get(KEY)).resolves.toBeUndefined();
    expect(degraded).toEqual(["get"]);
  });

  it("keeps serving writes and invalidations when the store is down", async () => {
    const delegate = new UnavailablePolicyCache();
    const degraded: string[] = [];
    const cache = new ResilientPolicyCache(delegate, {
      onDegrade: (operation) => degraded.push(operation),
    });

    await cache.set(KEY, ENTRY);
    await cache.invalidate(KEY);
    await cache.invalidateResourceType("document");
    await cache.invalidateAll();

    expect(delegate.operations).toEqual([
      "set",
      "invalidate",
      "invalidateResourceType",
      "invalidateAll",
    ]);
    // Every degradation is reported: an outage nobody can see is an outage nobody
    // fixes, and a stale window an invalidation failed to close has to be
    // observable somewhere.
    expect(degraded).toEqual(["set", "invalidate", "invalidateResourceType", "invalidateAll"]);
  });

  it("passes a healthy cache through unchanged", async () => {
    const degraded: string[] = [];
    const cache = new ResilientPolicyCache(new WorkingPolicyCache(), {
      onDegrade: (operation) => degraded.push(operation),
    });

    await cache.set(KEY, ENTRY);
    const read = await cache.get<{ marker: string }>(KEY);
    expect(read?.value).toEqual({ marker: "read-ast" });

    await cache.invalidateAll();
    await expect(cache.get(KEY)).resolves.toBeUndefined();
    expect(degraded).toEqual([]);
  });

  it("needs no degradation handler to stay functional", async () => {
    const cache = new ResilientPolicyCache(new UnavailablePolicyCache());

    await expect(cache.get(KEY)).resolves.toBeUndefined();
    await cache.set(KEY, ENTRY);
  });
});
