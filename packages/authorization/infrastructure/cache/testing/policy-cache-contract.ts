import { describe, expect, it } from "vitest";

import type {
  CachedPolicy,
  PolicyCache,
  PolicyCacheKey,
} from "../../../application/ports/policy-cache.js";

/**
 * The behaviour every {@link PolicyCache} must have, run against each adapter.
 *
 * Repetition of the contract-suite convention Phase 03 established for
 * repositories: the in-memory adapter and the Redis adapter are only
 * interchangeable if they are held to one written set of expectations, and a
 * contract that lives in only one of the two specs is a contract nobody
 * maintains. TTL *expiry* is deliberately not in here — it needs a clock or a
 * sleep, so each adapter proves it its own way — but the "zero TTL caches
 * nothing" rule is, because it is the one TTL rule both can satisfy identically.
 */

const DOCUMENT_READ: PolicyCacheKey = { resourceType: "document", action: "document:read" };
const DOCUMENT_WRITE: PolicyCacheKey = { resourceType: "document", action: "document:write" };
const INVOICE_READ: PolicyCacheKey = { resourceType: "invoice", action: "invoice:read" };

/** A stand-in for whatever gets cached (a compiled AST today), shaped as data. */
interface TestPayload {
  readonly marker: string;
}

function cached(marker: string, policyVersion: string): CachedPolicy<TestPayload> {
  return { value: { marker }, policyVersion, cachedAt: new Date().toISOString() };
}

async function markerOf(cache: PolicyCache, key: PolicyCacheKey): Promise<string | undefined> {
  const entry = await cache.get<TestPayload>(key);
  return entry?.value.marker;
}

export function policyCacheContract(createCache: () => PolicyCache): void {
  describe("PolicyCache contract", () => {
    it("reports a miss for a key that was never written", async () => {
      const cache = createCache();

      await expect(cache.get(DOCUMENT_READ)).resolves.toBeUndefined();
    });

    it("round-trips a value together with the policy version it came from", async () => {
      const cache = createCache();
      const value = { rules: [{ effect: "PERMIT", condition: { attribute: "resource.ownerId" } }] };

      await cache.set(DOCUMENT_READ, {
        value,
        policyVersion: "policy-v3",
        cachedAt: new Date().toISOString(),
      });

      const entry = await cache.get<typeof value>(DOCUMENT_READ);
      // The nested structure has to survive intact: a cache that mangles the AST
      // it hands back is worse than no cache, because the mangling is silent.
      expect(entry?.value).toEqual(value);
      // The version is the caller's, not one the cache invented — a reader
      // compares it against the active version to refuse a stale entry.
      expect(entry?.policyVersion).toBe("policy-v3");
    });

    it("keeps entries for different keys independent", async () => {
      const cache = createCache();

      await cache.set(DOCUMENT_READ, cached("read-ast", "v1"));
      await cache.set(DOCUMENT_WRITE, cached("write-ast", "v1"));
      await cache.set(INVOICE_READ, cached("invoice-ast", "v1"));

      expect(await markerOf(cache, DOCUMENT_READ)).toBe("read-ast");
      expect(await markerOf(cache, DOCUMENT_WRITE)).toBe("write-ast");
      expect(await markerOf(cache, INVOICE_READ)).toBe("invoice-ast");
    });

    it("stops serving an entry as soon as it is invalidated", async () => {
      const cache = createCache();

      await cache.set(DOCUMENT_READ, cached("read-ast", "v1"));
      await cache.invalidate(DOCUMENT_READ);

      await expect(cache.get(DOCUMENT_READ)).resolves.toBeUndefined();
    });

    it("invalidates one key without disturbing its neighbours", async () => {
      const cache = createCache();

      await cache.set(DOCUMENT_READ, cached("read-ast", "v1"));
      await cache.set(DOCUMENT_WRITE, cached("write-ast", "v1"));

      await cache.invalidate(DOCUMENT_READ);

      await expect(cache.get(DOCUMENT_READ)).resolves.toBeUndefined();
      expect(await markerOf(cache, DOCUMENT_WRITE)).toBe("write-ast");
    });

    it("invalidates every entry of one resource type and nothing else", async () => {
      const cache = createCache();

      await cache.set(DOCUMENT_READ, cached("read-ast", "v1"));
      await cache.set(DOCUMENT_WRITE, cached("write-ast", "v1"));
      await cache.set(INVOICE_READ, cached("invoice-ast", "v1"));

      // This is the operation a policy publish calls: the new version targets
      // documents, so every document entry must be unreachable immediately.
      await cache.invalidateResourceType("document");

      await expect(cache.get(DOCUMENT_READ)).resolves.toBeUndefined();
      await expect(cache.get(DOCUMENT_WRITE)).resolves.toBeUndefined();
      expect(await markerOf(cache, INVOICE_READ)).toBe("invoice-ast");
    });

    it("invalidates everything on request", async () => {
      const cache = createCache();

      await cache.set(DOCUMENT_READ, cached("read-ast", "v1"));
      await cache.set(INVOICE_READ, cached("invoice-ast", "v1"));

      await cache.invalidateAll();

      await expect(cache.get(DOCUMENT_READ)).resolves.toBeUndefined();
      await expect(cache.get(INVOICE_READ)).resolves.toBeUndefined();
    });

    it("writes nothing for a non-positive TTL, rather than caching something unreadable", async () => {
      const cache = createCache();

      await cache.set(DOCUMENT_READ, cached("read-ast", "v1"), { ttlSeconds: 0 });

      await expect(cache.get(DOCUMENT_READ)).resolves.toBeUndefined();
    });

    it("lets a re-written key supersede the previous value", async () => {
      const cache = createCache();

      await cache.set(DOCUMENT_READ, cached("old-ast", "v1"));
      await cache.set(DOCUMENT_READ, cached("new-ast", "v2"));

      const entry = await cache.get<TestPayload>(DOCUMENT_READ);
      expect(entry?.value).toEqual({ marker: "new-ast" });
      expect(entry?.policyVersion).toBe("v2");
    });
  });
}
