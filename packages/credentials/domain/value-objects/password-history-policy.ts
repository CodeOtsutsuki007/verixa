/**
 * Configuration for password history and reuse prevention.
 *
 * Separated from `Credential` so the depth is configuration rather than
 * a rule baked into the aggregate — a deployment facing leaked password
 * databases can increase reuse prevention without a code change.
 */
export interface PasswordHistoryPolicy {
  /** Number of previous passwords stored and checked for reuse. */
  readonly depth: number;
}

/**
 * Default depth: last 5 passwords cannot be reused.
 *
 * NIST SP 800-63B endorses reuse prevention even as it deprioritizes forced
 * rotation. N=5 balances security (prevents trivial "change and change back"
 * bypasses of the reset flow) vs. friction (users seldom rotate more than
 * every few years, so history rarely constrains them).
 */
export const DEFAULT_PASSWORD_HISTORY_POLICY: PasswordHistoryPolicy = {
  depth: 5,
};
