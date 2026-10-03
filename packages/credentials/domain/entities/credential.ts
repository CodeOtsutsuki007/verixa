import { createId, type Id } from "@verixa/shared-kernel";

import { type LockoutPolicy, lockDurationMs } from "../value-objects/lockout-policy.js";
import { type PasswordHistoryPolicy } from "../value-objects/password-history-policy.js";

export type CredentialId = Id<"CredentialId">;

/**
 * A `UserId` from the identity context, referenced by value.
 *
 * Declared locally rather than imported so the *domain* layer of credentials
 * depends on nothing outside itself. The application layer does import
 * `@verixa/identity`'s public API; the domain layer stays inert. See
 * docs/guides/domain-modeling.md on referencing other contexts by id.
 */
export type CredentialUserId = Id<"UserId">;

interface CredentialProps {
  readonly id: CredentialId;
  readonly userId: CredentialUserId;
  readonly passwordHash: string;
  /** Consecutive failures since the last success. Reset by a successful login. */
  readonly failedAttempts: number;
  /** When the current lock expires, or `undefined` when not locked. */
  readonly lockedUntil: Date | undefined;
  /**
   * Ordered list of previous password hashes (most recent first).
   * Current password is NOT in this list — it is in passwordHash.
   * Capped at PasswordHistoryPolicy.depth entries.
   */
  readonly passwordHistory: string[];
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

const REDACTED = "[REDACTED]";

/**
 * How a user proves who they are — deliberately a separate aggregate from
 * `User`.
 *
 * Splitting them answers a question that arrives later and is expensive to
 * retrofit: what happens when a user has *no* password? An SSO-only account,
 * a passkey-only account, or a service account all have an identity and no
 * credential. With the hash on `User`, those become a nullable column plus a
 * rule nothing enforces. As a separate aggregate, "no credential row" says it
 * exactly, and adding a second authentication method later means a new
 * aggregate rather than more nullable columns on `User`.
 *
 * It also narrows exposure. Loading a user for a profile page does not load
 * their password hash, because it isn't there.
 */
export class Credential {
  readonly id: CredentialId;
  readonly userId: CredentialUserId;
  readonly passwordHash: string;
  readonly failedAttempts: number;
  readonly lockedUntil: Date | undefined;
  readonly passwordHistory: string[];
  readonly createdAt: Date;
  readonly updatedAt: Date;

  private constructor(props: CredentialProps) {
    this.id = props.id;
    this.userId = props.userId;
    this.passwordHash = props.passwordHash;
    this.failedAttempts = props.failedAttempts;
    this.lockedUntil = props.lockedUntil;
    this.passwordHistory = props.passwordHistory;
    this.createdAt = props.createdAt;
    this.updatedAt = props.updatedAt;
  }

  /**
   * Creates a credential from an **already-hashed** password.
   *
   * The signature is the point: there is no factory taking a `RawPassword`,
   * so this aggregate cannot hash — and therefore cannot hash *wrongly*, or
   * accidentally store a plaintext. Hashing belongs to the `PasswordHasher`
   * port, and the use case is responsible for calling it first. A domain
   * entity that could hash would need to know the algorithm, which is exactly
   * what the port exists to keep out of the domain.
   */
  static create(params: { userId: CredentialUserId; passwordHash: string }): Credential {
    const now = new Date();
    return new Credential({
      id: createId<"CredentialId">(),
      userId: params.userId,
      passwordHash: params.passwordHash,
      failedAttempts: 0,
      lockedUntil: undefined,
      passwordHistory: [],
      createdAt: now,
      updatedAt: now,
    });
  }

  /** Rebuilds from already-trusted data (a database row). */
  static reconstitute(props: CredentialProps): Credential {
    return new Credential(props);
  }

  /**
   * Replaces the stored hash — a password change, or a transparent rehash
   * after cost parameters rise (see `PasswordHasher.needsRehash`).
   *
   * Takes a hash, never a plaintext, for the same reason as {@link create}.
   */
  withPasswordHash(passwordHash: string): Credential {
    // Clears the lockout too. A password change is a legitimate owner
    // demonstrating control of the account, so carrying a lock across it
    // would leave them locked out of the credential they just set -- and
    // after a reset (Issue 070) that is the one moment they have no way to
    // wait it out, because the failures were not theirs.
    return new Credential({
      ...this,
      passwordHash,
      failedAttempts: 0,
      lockedUntil: undefined,
      updatedAt: new Date(),
    });
  }

  /** Whether the credential is locked at `now`. */
  isLockedAt(now: Date): boolean {
    return this.lockedUntil !== undefined && this.lockedUntil.getTime() > now.getTime();
  }

  /**
   * Records one failed attempt, locking the credential once the policy's
   * threshold is reached.
   *
   * The counter keeps climbing while locked rather than stopping at the
   * threshold, which is what makes the backoff exponential: each further
   * attempt during or after a lock earns a longer next one.
   */
  recordFailedAttempt(policy: LockoutPolicy, now: Date = new Date()): Credential {
    const failedAttempts = this.failedAttempts + 1;
    const duration = lockDurationMs(failedAttempts, policy);

    return new Credential({
      ...this,
      failedAttempts,
      lockedUntil: duration === 0 ? this.lockedUntil : new Date(now.getTime() + duration),
      updatedAt: now,
    });
  }

  /**
   * Clears the failure counter and any lock, after a successful login.
   *
   * Returns `this` unchanged when there is nothing to clear. That is not a
   * micro-optimisation: without it every successful login would write a row
   * that differs only in `updatedAt`, turning the hottest read path in the
   * system into a write on each request.
   */
  recordSuccessfulAttempt(now: Date = new Date()): Credential {
    if (this.failedAttempts === 0 && this.lockedUntil === undefined) {
      return this;
    }

    return new Credential({
      ...this,
      failedAttempts: 0,
      lockedUntil: undefined,
      updatedAt: now,
    });
  }

  /**
   * Checks whether a candidate plaintext password matches the current password
   * or any entry in the password history.
   *
   * Uses async comparison (argon2) for each entry. Short-circuits on first match.
   *
   * @param candidatePassword - Plaintext password to check
   * @param comparePassword - Injected comparison function (e.g., PasswordHasher.verify)
   * @returns true if candidate matches current or any history entry
   */
  async isPasswordReused(
    candidatePassword: string,
    comparePassword: (plain: string, hash: string) => Promise<boolean>,
  ): Promise<boolean> {
    // Check current password first
    const matchesCurrent = await comparePassword(candidatePassword, this.passwordHash);
    if (matchesCurrent) return true;

    // Check history entries (most recent first — short-circuit on match)
    for (const historicHash of this.passwordHistory) {
      const matches = await comparePassword(candidatePassword, historicHash);
      if (matches) return true;
    }

    return false;
  }

  /**
   * Rotates the password: pushes current hash to history, sets new hash,
   * and caps history at the policy depth.
   *
   * Called instead of directly mutating passwordHash to maintain history
   * invariants.
   *
   * @param newPasswordHash - Already-hashed new password
   * @param historyPolicy - Configuration for history depth
   */
  rotatePassword(newPasswordHash: string, historyPolicy: PasswordHistoryPolicy): Credential {
    // Push current to front of history (most recent first)
    const newHistory = [this.passwordHash, ...this.passwordHistory].slice(0, historyPolicy.depth);

    return new Credential({
      ...this,
      passwordHash: newPasswordHash,
      passwordHistory: newHistory,
      failedAttempts: 0,
      lockedUntil: undefined,
      updatedAt: new Date(),
    });
  }

  /**
   * The hash is a secret, so it is redacted from every serialization path —
   * the same four escape routes `RawPassword` closes.
   *
   * A password hash is not as damaging as a plaintext, but it is not
   * harmless: leak it and an attacker can grind it offline at their own pace,
   * against a target they now know exists. It has no business in a log line
   * or an API response.
   */
  toJSON(): Record<string, unknown> {
    return {
      id: this.id,
      userId: this.userId,
      passwordHash: REDACTED,
      failedAttempts: this.failedAttempts,
      lockedUntil: this.lockedUntil,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
    };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): Record<string, unknown> {
    return this.toJSON();
  }
}
