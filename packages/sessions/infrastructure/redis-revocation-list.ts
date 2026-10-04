import type { Redis } from "ioredis";

import type { RevocationList } from "../application/ports/revocation-list.js";
import type { SessionId } from "../domain/value-objects/session-id.js";

export interface RedisRevocationListOptions {
  /**
   * Namespace prepended to every session id before it becomes a Redis key.
   * Keeps the deny-list from colliding with anything else sharing the same
   * Redis, and makes `SCAN revoked:session:*` a meaningful operational query.
   */
  readonly keyPrefix?: string;
}

const DEFAULT_KEY_PREFIX = "revoked:session:";

/**
 * A Redis-backed {@link RevocationList}.
 *
 * Each revoked session is one key, set with a Redis `EX` expiry equal to the
 * remaining access-token lifetime the caller supplies. Redis evicts the key when
 * that expiry passes, so the deny-list garbage-collects itself and its size
 * tracks the access-token TTL rather than the all-time count of revocations —
 * the property that makes checking it on every request affordable.
 *
 * ## Fail-closed, and why
 *
 * The interesting decision is what {@link isRevoked} does when Redis is
 * unreachable. Two choices:
 *
 * - **Fail open** — "can't check, assume not revoked" — keeps logins working
 *   during a Redis outage, at the cost of honoring tokens that may have been
 *   revoked. A revoked (possibly stolen) session silently regains access for
 *   the duration of the outage.
 * - **Fail closed** — "can't check, assume revoked" — refuses those tokens,
 *   at the cost of turning a Redis outage into an auth outage.
 *
 * This adapter **fails closed**. The deny-list exists specifically to shut down
 * sessions believed compromised; an implementation that quietly stops enforcing
 * it the moment its datastore hiccups defeats the reason it was built. An auth
 * outage is loud, bounded, and pages someone; a revocation-bypass window is
 * silent and is exactly the state an attacker with a revoked token is waiting
 * for. Availability is recoverable; a re-admitted stolen session may not be.
 *
 * The tradeoff is real and is accepted deliberately — see
 * `docs/security/token-design.md`. It also raises the stakes on Redis
 * availability (replication, health checks), which is the correct place to
 * spend the effort. Callers that genuinely need fail-open for a specific,
 * lower-stakes path can wrap this and catch — but the safe default is not
 * theirs to forget.
 *
 * {@link revoke}, by contrast, lets errors propagate. A revocation that failed
 * to persist has not happened, and the caller (a logout, a reset) needs to know
 * that and retry or surface it — swallowing it would report success for a
 * session that is still live.
 */
export class RedisRevocationList implements RevocationList {
  private readonly keyPrefix: string;

  constructor(
    private readonly redis: Redis,
    options: RedisRevocationListOptions = {},
  ) {
    this.keyPrefix = options.keyPrefix ?? DEFAULT_KEY_PREFIX;
  }

  async revoke(sessionId: SessionId, ttlSeconds: number): Promise<void> {
    // A non-positive TTL means no live token could still reference this session,
    // so there is nothing to deny — writing a key that instantly expires (or,
    // for a zero/negative EX, that Redis would reject) buys nothing.
    if (ttlSeconds <= 0) {
      return;
    }
    // Round up: a fractional second lost to flooring would let the deny-list
    // entry expire a hair before the last token it needs to outlive.
    await this.redis.set(this.keyFor(sessionId), "1", "EX", Math.ceil(ttlSeconds));
  }

  async isRevoked(sessionId: SessionId): Promise<boolean> {
    try {
      const exists = await this.redis.exists(this.keyFor(sessionId));
      return exists === 1;
    } catch {
      // Fail closed. See the class comment: a session we cannot confirm is safe
      // is treated as revoked, not waved through.
      return true;
    }
  }

  private keyFor(sessionId: SessionId): string {
    return `${this.keyPrefix}${sessionId}`;
  }
}
