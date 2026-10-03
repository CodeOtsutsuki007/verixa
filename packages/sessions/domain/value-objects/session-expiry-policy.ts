import { ValidationError } from "@verixa/shared-kernel";

export type ExpiryMode = "sliding" | "absolute";

interface SessionExpiryPolicyProps {
  readonly mode: ExpiryMode;
  readonly durationMs: number;
}

/**
 * A configurable session expiry policy supporting two modes:
 *
 * - **Sliding**: Each `touch()` extends `expiresAt` forward by the policy's
 *   configured duration from "now". Feels seamless to users but can persist
 *   indefinitely under continuous activity, potentially violating compliance
 *   requirements that bound maximum session lifetime.
 *
 * - **Absolute**: A hard cutoff set at session creation that `touch()` never
 *   moves. User activity is tracked (via `lastSeenAt`) but doesn't grant
 *   extra time. Guarantees a bounded maximum session lifetime at the cost of
 *   forced re-login even for active users once the cutoff passes.
 *
 * ## Design rationale
 *
 * This value object embeds the expiry behavior so that a `Session` entity's
 * `touch()` method can be genuinely pluggable and testable against either
 * mode, without hardcoding one strategy. The policy is immutable and
 * compared by value, which is the defining property of value objects.
 */
export class SessionExpiryPolicy {
  readonly mode: ExpiryMode;
  readonly durationMs: number;

  private constructor(props: SessionExpiryPolicyProps) {
    this.mode = props.mode;
    this.durationMs = props.durationMs;
  }

  /**
   * Creates a sliding-expiry policy: each `touch()` resets `expiresAt` to
   * now + `durationMs`.
   *
   * @param durationMs - Duration in milliseconds; must be positive.
   * @returns The created policy, or an error if validation fails.
   */
  static sliding(durationMs: number): SessionExpiryPolicy {
    if (!Number.isFinite(durationMs) || durationMs <= 0) {
      throw new ValidationError(
        `Sliding policy duration must be a positive number, got ${durationMs}`,
        { durationMs: ["must_be_positive_number"] },
      );
    }

    return new SessionExpiryPolicy({ mode: "sliding", durationMs });
  }

  /**
   * Creates an absolute-expiry policy: `expiresAt` is set at session
   * creation and never changes, regardless of `touch()` calls.
   *
   * @param durationMs - Duration in milliseconds from session creation;
   *   must be positive.
   * @returns The created policy, or an error if validation fails.
   */
  static absolute(durationMs: number): SessionExpiryPolicy {
    if (!Number.isFinite(durationMs) || durationMs <= 0) {
      throw new ValidationError(
        `Absolute policy duration must be a positive number, got ${durationMs}`,
        { durationMs: ["must_be_positive_number"] },
      );
    }

    return new SessionExpiryPolicy({ mode: "absolute", durationMs });
  }

  /**
   * Computes the new `expiresAt` for the given `previousExpiresAt` when
   * `touch()` is called at `touchedAt`.
   *
   * - **Sliding**: returns `touchedAt + durationMs` (activity extends expiry).
   * - **Absolute**: returns `previousExpiresAt` unchanged (activity ignored).
   */
  computeNewExpiresAt(previousExpiresAt: Date, touchedAt: Date): Date {
    if (this.mode === "sliding") {
      return new Date(touchedAt.getTime() + this.durationMs);
    }

    // Absolute mode: expiresAt never changes
    return previousExpiresAt;
  }

  /**
   * Whether this policy is equal to another, by value.
   * Two policies are equal if they have the same mode and duration.
   */
  equals(other: SessionExpiryPolicy): boolean {
    return this.mode === other.mode && this.durationMs === other.durationMs;
/**
 * Configurable expiry policy for sessions.
 *
 * Two modes, each with distinct security/UX tradeoffs:
 * - **Sliding expiry:** extends `expiresAt` every time the session is touched
 *   (a request is made). Feels seamless (session never expires during active use),
 *   but can accumulate to arbitrarily long effective lifetimes under continuous
 *   activity. A background task that exercises a compromised session token
 *   indefinitely would prevent it from ever expiring.
 * - **Absolute expiry:** `expiresAt` is fixed when the session is created and
 *   never extended, regardless of activity. Guarantees that every session is
 *   bounded by a maximum absolute age. Trades UX (session expires mid-request
 *   if activity lapsed longer than the configured interval) for stronger
 *   worst-case security (even continuous reuse of a stolen token expires).
 *
 * Real production deployments typically combine both: absolute expiry on the
 * refresh token (e.g., 7 days) to bound long-term exposure, and sliding expiry
 * on the access token (e.g., 15 minutes sliding per access) to avoid constant
 * re-authentication. That design appears in Phase 05 (Issue 089).
 */
export type SessionExpiryMode = "sliding" | "absolute";

export class SessionExpiryPolicy {
  /**
   * @param mode - "sliding" to extend expiresAt on activity, "absolute" to ignore it
   * @param intervalMs - milliseconds the session should remain valid for
   */
  constructor(
    readonly mode: SessionExpiryMode,
    readonly intervalMs: number,
  ) {}

  /**
   * The timestamp when a freshly-created session with this policy would expire.
   * Input is the session's `createdAt`.
   */
  expiresAt(createdAt: Date): Date {
    return new Date(createdAt.getTime() + this.intervalMs);
  }

  /**
   * For a session with this policy, compute the new expiry if it's touched now.
   * - Sliding: extends to now + interval
   * - Absolute: returns the original expiresAt unchanged
   */
  maybeExtendExpiry(currentExpiresAt: Date, touchedNow: Date): Date {
    if (this.mode === "sliding") {
      return new Date(touchedNow.getTime() + this.intervalMs);
    }
    // Absolute mode ignores activity — return the original expiry unchanged
    return currentExpiresAt;
  }

  /**
   * Is the session expired at the given timestamp?
   */
  isExpired(expiresAt: Date, asOf: Date = new Date()): boolean {
    return asOf > expiresAt;
  }
}
﻿export class SessionExpiryPolicy {}
