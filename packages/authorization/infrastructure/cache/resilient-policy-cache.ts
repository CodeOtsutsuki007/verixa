import type {
  CachedPolicy,
  PolicyCache,
  PolicyCacheKey,
  PolicyCacheSetOptions,
} from "../../application/ports/policy-cache.js";

/** Called once per degraded operation, so a cache outage is visible rather than silent. */
export type PolicyCacheDegradationHandler = (operation: string, error: unknown) => void;

export interface ResilientPolicyCacheOptions {
  /**
   * Observed whenever an operation is degraded. Wire this to the logger/metrics
   * of the surrounding context — an unavailable cache that nobody can see is an
   * unavailable cache nobody will fix, and the second thing it does after
   * logging is stop absorbing a stampede.
   */
  readonly onDegrade?: PolicyCacheDegradationHandler;
}

/**
 * Makes cache unavailability degrade to direct evaluation instead of failing
 * requests — the second acceptance criterion of Issue 154.
 *
 * ## What it absorbs, and what it does not
 *
 * - `get` failures become a **miss** (`undefined`). A reader that gets a miss
 *   computes the value the way it would on a cold cache, which is exactly the
 *   behaviour a Redis outage should produce: slower, still correct, still
 *   fail-closed, because nothing here invents a value.
 *   `undefined` can only ever mean "not cached", never "not permitted".
 * - `set` failures are **swallowed**: a cache that cannot be written is still
 *   serving, and failing the request would turn a performance optimization into
 *   an availability dependency.
 * - `invalidate` failures are swallowed *and reported*, which is the one place
 *   this class trades something real. A publish that could not invalidate leaves
 *   the documented stale window (bounded by TTL and by the version check on
 *   read) rather than failing the publish. The alternative — propagate, and let
 *   a Redis hiccup block policy publishing — is worse: publishing is the
 *   operation that *removes* authority, and refusing it leaves the old, broader
 *   policy in force indefinitely.
 *
 * This is a decorator rather than behaviour baked into the adapters so the tests
 * can assert both halves: the adapter's own contract (a Redis failure
 * propagates) and this class's degradation (a wrapped failure becomes a miss).
 */
export class ResilientPolicyCache implements PolicyCache {
  private readonly onDegrade: PolicyCacheDegradationHandler | undefined;

  constructor(
    private readonly delegate: PolicyCache,
    options: ResilientPolicyCacheOptions = {},
  ) {
    this.onDegrade = options.onDegrade;
  }

  async get<TValue>(key: PolicyCacheKey): Promise<CachedPolicy<TValue> | undefined> {
    try {
      return await this.delegate.get<TValue>(key);
    } catch (error) {
      this.report("get", error);
      return undefined;
    }
  }

  async set<TValue>(
    key: PolicyCacheKey,
    entry: CachedPolicy<TValue>,
    options?: PolicyCacheSetOptions,
  ): Promise<void> {
    try {
      await this.delegate.set(key, entry, options);
    } catch (error) {
      this.report("set", error);
    }
  }

  async invalidate(key: PolicyCacheKey): Promise<void> {
    try {
      await this.delegate.invalidate(key);
    } catch (error) {
      this.report("invalidate", error);
    }
  }

  async invalidateResourceType(resourceType: string): Promise<void> {
    try {
      await this.delegate.invalidateResourceType(resourceType);
    } catch (error) {
      this.report("invalidateResourceType", error);
    }
  }

  async invalidateAll(): Promise<void> {
    try {
      await this.delegate.invalidateAll();
    } catch (error) {
      this.report("invalidateAll", error);
    }
  }

  private report(operation: string, error: unknown): void {
    this.onDegrade?.(operation, error);
  }
}
