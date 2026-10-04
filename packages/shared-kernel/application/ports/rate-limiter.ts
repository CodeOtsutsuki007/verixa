/**
 * RateLimiter port — cross-cutting concern for abuse-sensitive operations.
 *
 * Defines the seam between use cases and rate limiting infrastructure.
 * Wired from day one even before the real limiter exists (no-op until Phase 15).
 * Avoids a painful retrofit later.
 *
 * See `docs/security/authentication-flows.md` for the rate limiting strategy.
 */

export interface RateLimitKey {
  /** The type of action being rate-limited */
  action: "login" | "register" | "password-reset" | "email-verification";
  /** Identifier for the subject — IP address, email, or userId */
  identifier: string;
  /** Optional namespace for multi-tenant isolation */
  namespace?: string;
}

export interface RateLimitResult {
  /** Whether the request is allowed to proceed */
  allowed: boolean;
  /** Remaining attempts before limit is hit */
  remaining: number;
  /** When the limit resets (Unix timestamp in ms) */
  resetAt: number;
  /** Total limit for this window */
  limit: number;
}

export interface RateLimiter {
  /**
   * Check if the action is allowed for this identifier.
   * Must be called BEFORE the use case executes its core logic.
   * If not allowed, the use case must throw RateLimitExceededError.
   */
  check(key: RateLimitKey): Promise<RateLimitResult>;

  /**
   * Record a failed attempt (e.g. wrong password).
   * Increments the counter for stricter limiting on abuse patterns.
   */
  recordFailure(key: RateLimitKey): Promise<void>;

  /**
   * Reset the limit for a key after a successful operation.
   * e.g. successful login resets the login attempt counter.
   */
  reset(key: RateLimitKey): Promise<void>;
}

/** Thrown by use cases when rate limit is exceeded */
export class RateLimitExceededError extends Error {
  constructor(
    public readonly key: RateLimitKey,
    public readonly resetAt: number,
    public readonly limit: number,
  ) {
    super(
      `Rate limit exceeded for ${key.action} on ${key.identifier}. ` +
        `Resets at ${new Date(resetAt).toISOString()}`,
    );
    this.name = "RateLimitExceededError";
  }
}
