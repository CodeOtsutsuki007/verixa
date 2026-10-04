import type { MfaMethodType } from "../entities/mfa-method.js";

/**
 * Evidence that a user re-verified an enrolled second factor at a point in
 * time, scoped narrowly in time rather than re-issuing a full session.
 *
 * A long-lived session token only proves the session was established at some
 * point. Possessing it a week later — a stolen laptop left unlocked, a token
 * lifted from a shared machine — is not evidence the user is present *now*.
 * A step-up assertion is the narrower, shorter-lived claim that they are.
 */
export class StepUpAssertion {
  private constructor(
    public readonly userId: string,
    public readonly methodType: MfaMethodType,
    public readonly verifiedAt: Date,
    public readonly expiresAt: Date,
  ) {}

  /**
   * Issues an assertion valid for `maxAgeSeconds` from `now`.
   *
   * Deliberately wall-clock based and short: the assertion is a bearer claim,
   * so its lifetime is the worst-case window in which it could be replayed if
   * intercepted.
   */
  static issue(
    userId: string,
    methodType: MfaMethodType,
    maxAgeSeconds: number,
    now: Date = new Date(),
  ): StepUpAssertion {
    return new StepUpAssertion(
      userId,
      methodType,
      now,
      new Date(now.getTime() + maxAgeSeconds * 1_000),
    );
  }

  /** Rehydrates an assertion from persistence. */
  static from(params: {
    userId: string;
    methodType: MfaMethodType;
    verifiedAt: Date;
    expiresAt: Date;
  }): StepUpAssertion {
    return new StepUpAssertion(
      params.userId,
      params.methodType,
      params.verifiedAt,
      params.expiresAt,
    );
  }

  /** Whether the assertion is still valid at `now`. */
  isFreshAt(now: Date = new Date()): boolean {
    return now < this.expiresAt;
  }
}
