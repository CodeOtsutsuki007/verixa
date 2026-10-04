/**
 * The {@link PolicyCache} port: a store for values derived from the *policy set*
 * (compiled policy ASTs, and optionally decisions) rather than from a resource.
 *
 * Issue 154 (roadmap 154). The port is deliberately generic over the cached
 * value and free of anything Redis-, AST-, or decision-shaped: the same
 * interface has to serve a parsed AST for `(resourceType, action)` and a short
 * TTL decision for `(subject, action, resource)`, and an implementation should
 * not have to know which of the two it is holding.
 *
 * ## Why caching authorization is different
 *
 * A stale entry in an ordinary read cache is a UX glitch. A stale entry here can
 * be a `DENY → PERMIT` transition, which is a security bug — so the contract
 * below is stricter than "call these methods and it'll be fast":
 *
 * - **Invalidation is a hard requirement, not a TTL hope.** Publishing a policy
 *   version (Issue 150) must make the entries derived from the previous version
 *   unreachable *immediately*. Implementations therefore namespace entries under
 *   a *generation* that invalidation advances, instead of deleting keys one by
 *   one or scanning for them: advancing a generation is one atomic write, cannot
 *   partially fail, and needs no `SCAN`/`KEYS` (which are unsafe on a shared
 *   Redis and would themselves be an availability risk on a large keyspace).
 * - **Every entry carries the policy version it was derived from.** A reader must
 *   compare {@link CachedPolicy.policyVersion} against the version it believes is
 *   active and treat a mismatch as a **miss**. That check is what bounds the
 *   stale-policy window to "no longer than the time between a version being
 *   published and this node's next read", which is zero for the reading node and
 *   a documented one-cache-write for other nodes. TTL is a *memory* bound, not
 *   the correctness mechanism.
 * - **A miss and a failure are indistinguishable to a reader.** `get` returns
 *   `undefined` for both, which is what makes "Redis is down" degrade into direct
 *   evaluation rather than into a failed request (see `ResilientPolicyCache`).
 *   A reader must never treat "I could not ask the cache" as "the cached answer
 *   was no" — that is how a cache outage turns into an authorization decision.
 * - **Reads are optional; writes and invalidations are not silent.** `set` and the
 *   `invalidate*` methods are allowed to throw, because a caller that thinks it
 *   invalidated and did not has a stale-policy window it does not know about.
 *   Callers that would rather keep serving than fail a request wrap the adapter in
 *   {@link ResilientPolicyCache} and accept a *reported* degradation.
 */

/** What a cached entry is keyed by: the policy target selector, not the request. */
export interface PolicyCacheKey {
  /** Resource type the policy targets, e.g. `document`. */
  readonly resourceType: string;
  /** Action the policy targets, e.g. `document:read`. */
  readonly action: string;
}

/** A cached value plus the provenance needed to refuse it. */
export interface CachedPolicy<TValue> {
  readonly value: TValue;
  /**
   * Version of the policy set `value` was derived from. A reader compares this
   * against the active version and treats a mismatch as a miss (threat E-3).
   */
  readonly policyVersion: string;
  /** When the entry was written (ISO-8601), for operational visibility. */
  readonly cachedAt: string;
}

/** Options accepted by {@link PolicyCache.set}. */
export interface PolicyCacheSetOptions {
  /**
   * Time-to-live in seconds. Bounds memory, not correctness: an entry that
   * outlives its policy version is refused by the version check, not by expiry.
   */
  readonly ttlSeconds?: number;
}

/** Port implemented by the in-memory adapter and the Redis adapter. */
export interface PolicyCache {
  /**
   * Reads the entry for `key`.
   *
   * @returns the entry, or `undefined` for a miss — including when the entry
   * existed but has expired. A miss is not an error and must not throw.
   */
  get<TValue>(key: PolicyCacheKey): Promise<CachedPolicy<TValue> | undefined>;

  /**
   * Writes `entry` for `key`.
   *
   * A write must be visible to a `get` for the same key on this node before this
   * promise resolves; cross-node visibility is bounded by the store's replication,
   * which is why readers rely on the version check rather than on write
   * visibility.
   */
  set<TValue>(
    key: PolicyCacheKey,
    entry: CachedPolicy<TValue>,
    options?: PolicyCacheSetOptions,
  ): Promise<void>;

  /**
   * Invalidates one key — the narrow form, for a single policy whose target
   * selector changed while its version stayed put.
   */
  invalidate(key: PolicyCacheKey): Promise<void>;

  /**
   * Invalidates every entry for one resource type. This is the operation a
   * publish of a policy targeting that resource type must call before it
   * reports success.
   */
  invalidateResourceType(resourceType: string): Promise<void>;

  /** Invalidates everything, for operations that cannot name what they changed. */
  invalidateAll(): Promise<void>;
}
