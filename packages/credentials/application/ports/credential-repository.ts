import type { Credential, CredentialUserId } from "../../domain/entities/credential.js";

/**
 * Metrics on stale credentials — those below current cost parameters.
 *
 * Credentials at older argon2 parameters cannot be upgraded without the
 * plaintext, which only exists during login. Dormant accounts may sit at
 * weak parameters for years. This metric exposes the scope of the problem:
 * how many accounts are affected, and how old the oldest one is.
 *
 * See `docs/security/password-storage.md#dormant-accounts-the-password-upgrade-gap`.
 */
export interface StaleCredentialMetrics {
  /** Total count of credentials below current cost parameters. */
  readonly count: number;
  /** ISO 8601 timestamp of the oldest stale credential. */
  readonly oldestCreatedAt: Date | null;
  /** ISO 8601 timestamp of the median (50th percentile) creation time. */
  readonly medianCreatedAt: Date | null;
  /** ISO 8601 timestamp of the 95th percentile creation time. */
  readonly p95CreatedAt: Date | null;
}

/**
 * Persistence contract for `Credential`. Mirrors the conventions in
 * `@verixa/identity`'s repository ports.
 *
 * - `findByUserId` returns `undefined` when the user has no credential. That
 *   is an ordinary state, not an error: SSO-only and passkey-only accounts
 *   legitimately have none, which is the reason credentials are a separate
 *   aggregate at all.
 * - `save` is an idempotent upsert.
 * - `deleteByUserId` supports removing password authentication without
 *   deleting the user — needed when someone moves to SSO, and by the erasure
 *   work in Phase 24.
 * - `getStaleCredentialMetrics` exposes the count and age distribution of
 *   credentials below current cost parameters, for visibility into dormant
 *   account security posture.
 */
export interface CredentialRepository {
  findByUserId(userId: CredentialUserId): Promise<Credential | undefined>;
  save(credential: Credential): Promise<void>;
  deleteByUserId(userId: CredentialUserId): Promise<void>;
  /**
   * Metrics on credentials below current cost parameters.
   *
   * Called with the current hasher so it can determine which hashes are stale.
   * Returns count, oldest, median, and 95th-percentile creation dates.
   */
  getStaleCredentialMetrics(currentHasher: {
    needsRehash(encodedHash: string): boolean;
  }): Promise<StaleCredentialMetrics>;
}
