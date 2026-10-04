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
  }
}
