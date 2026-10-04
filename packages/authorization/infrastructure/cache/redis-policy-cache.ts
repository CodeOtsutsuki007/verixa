import type { Redis } from "ioredis";

import type {
  CachedPolicy,
  PolicyCache,
  PolicyCacheKey,
  PolicyCacheSetOptions,
} from "../../application/ports/policy-cache.js";

/** Default TTL for entries that do not name one: five minutes. */
export const DEFAULT_POLICY_CACHE_TTL_SECONDS = 300;

export interface RedisPolicyCacheOptions {
  /**
   * Namespace prepended to every key. Keeps the policy cache from colliding with
   * anything else sharing the same Redis, and makes `SCAN policy:cache:*` a
   * meaningful operational query.
   */
  readonly keyPrefix?: string;
  /** TTL applied when a caller does not pass one. */
  readonly defaultTtlSeconds?: number;
}

const DEFAULT_KEY_PREFIX = "policy:cache:";

/**
 * A Redis-backed {@link PolicyCache}.
 *
 * ## Generations instead of deletion
 *
 * Two counters per prefix hold the state that matters: a global generation and one
 * per resource type. An entry key embeds the generations that were current when it
 * was written, so:
 *
 * - `invalidateResourceType("document")` is a single `INCR` — atomic, O(1), and
 *   it makes every entry written under the previous generation unreachable in the
 *   same instant. No `SCAN`, no `KEYS`, no read-modify-write that could half-fail
 *   and leave some entries live.
 * - An entry's key is a *set* of generations, so invalidating one resource type
 *   leaves every other type's entries reachable, which is the granularity a policy
 *   publish actually has.
 *
 * The superseded keys are left to their TTL. That is the memory cost of making
 * invalidation atomic and instant, and it is bounded: keyspace size is
 * `live entries + entries written within one TTL of the last publish`, and TTL is
 * a memory bound rather than a correctness one because every entry also carries the
 * policy version its reader checks against.
 *
 * ## Failure behaviour
 *
 * Every method lets Redis errors propagate. That is deliberate: this adapter's
 * contract is "the store is reachable and it obeyed", and the decision to keep
 * serving through an outage belongs one level up, in `ResilientPolicyCache`, where
 * it can also be *reported*. A `get` that silently turned a connection error into
 * "not cached" would look identical to a healthy miss from the outside, and the
 * resulting stampede on Postgres would arrive with no signal explaining it.
 *
 * ## Why the client is injected
 *
 * The adapter takes a connected client rather than constructing one, and imports
 * `ioredis` only as a *type* — which is why `ioredis` is a devDependency of this
 * package rather than a runtime dependency of it. That keeps the cache
 * implementable without a Redis client at all (the contract suite runs the
 * in-memory adapter for deployments that have none), lets tests drive it with a
 * client they own, and leaves connection lifecycle, TLS and pooling to the
 * composition root that owns those concerns anyway.
 *
 * ## Values must be JSON-serializable
 *
 * Entries are stored as JSON, so a cached value has to survive `JSON.stringify`
 * round-tripping. Both intended payloads (a compiled policy AST, a decision DTO)
 * are plain data by construction; a value carrying `Map`, `Date` or class
 * instances would silently lose that structure, which is why the contract suite
 * pins the round-trip with a nested object.
 */
export class RedisPolicyCache implements PolicyCache {
  private readonly keyPrefix: string;
  private readonly defaultTtlSeconds: number;

  constructor(
    private readonly redis: Redis,
    options: RedisPolicyCacheOptions = {},
  ) {
    this.keyPrefix = options.keyPrefix ?? DEFAULT_KEY_PREFIX;
    this.defaultTtlSeconds = options.defaultTtlSeconds ?? DEFAULT_POLICY_CACHE_TTL_SECONDS;
  }

  async get<TValue>(key: PolicyCacheKey): Promise<CachedPolicy<TValue> | undefined> {
    const generations = await this.currentGenerations(key.resourceType);
    const stored = await this.redis.get(this.entryKey(key, generations));

    // A missing key is a miss; so is a value written under a generation that has
    // since been superseded (that key is simply no longer the one we look at).
    if (stored === null) {
      return undefined;
    }

    try {
      const parsed = JSON.parse(stored) as CachedPolicy<TValue>;
      return parsed;
    } catch {
      // A value this adapter cannot read is a miss, not a request failure: the
      // caller recomputes from the source of truth, which is always correct.
      // Deleting it keeps a corrupt entry from being re-read until its TTL.
      await this.redis.del(this.entryKey(key, generations));
      return undefined;
    }
  }

  async set<TValue>(
    key: PolicyCacheKey,
    entry: CachedPolicy<TValue>,
    options: PolicyCacheSetOptions = {},
  ): Promise<void> {
    const ttlSeconds = options.ttlSeconds ?? this.defaultTtlSeconds;
    if (ttlSeconds <= 0) {
      // A non-positive TTL can never be read back; Redis would also reject a
      // zero or negative EX. Write nothing rather than pretend to cache.
      return;
    }

    const generations = await this.currentGenerations(key.resourceType);
    // EX, not a manual expiry: Redis then evicts the superseded entries for us.
    await this.redis.set(
      this.entryKey(key, generations),
      JSON.stringify(entry),
      "EX",
      // Round up: flooring a fractional second would let an entry expire a hair
      // before the caller's intended window closed.
      Math.ceil(ttlSeconds),
    );
  }

  async invalidate(key: PolicyCacheKey): Promise<void> {
    const generations = await this.currentGenerations(key.resourceType);
    await this.redis.del(this.entryKey(key, generations));
  }

  async invalidateResourceType(resourceType: string): Promise<void> {
    await this.redis.incr(this.generationKey(resourceType));
  }

  async invalidateAll(): Promise<void> {
    await this.redis.incr(this.globalGenerationKey());
  }

  private async currentGenerations(resourceType: string): Promise<string> {
    const [global, resource] = await this.redis.mget(
      this.globalGenerationKey(),
      this.generationKey(resourceType),
    );
    return `${global ?? "0"}:${resource ?? "0"}`;
  }

  private entryKey(key: PolicyCacheKey, generations: string): string {
    return `${this.keyPrefix}entry:${generations}:${key.resourceType}:${key.action}`;
  }

  private generationKey(resourceType: string): string {
    return `${this.keyPrefix}gen:${resourceType}`;
  }

  private globalGenerationKey(): string {
    return `${this.keyPrefix}gen:`;
  }
}
