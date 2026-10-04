/**
 * How long an audit trail is kept before its contents become candidates for
 * archival or erasure — and the deliberate limit of what this seam does.
 *
 * ## Why the seam exists now
 *
 * Retention shapes the schema and the query path: what gets indexed, whether
 * old rows stay in the primary table or move, and how a compliance request
 * addresses a record that is no longer where it was written. Those are
 * expensive to retrofit, so the contract is defined here while the log is
 * small.
 *
 * What is *not* defined here is deletion. Deciding that a record may be erased
 * is a legal judgement — it depends on jurisdiction, contractual retention
 * obligations, and legal holds that override both — and Phase 24 (compliance
 * and privacy) owns that judgement. This phase's job is to identify candidates
 * and to make the act of removing one a decision someone takes deliberately.
 *
 * ## The tension this seam sits on
 *
 * Append-only tamper evidence and legally-compelled deletion pull in opposite
 * directions. A hash chain's value is that nothing has been removed; GDPR
 * erasure requires that something be removed. There is no implementation that
 * satisfies both silently, which is why `AuditLogRepository` has no `delete`
 * method at all: the first erasure has to arrive as a new, reviewed port with
 * its own guarantees, not as a method that was quietly always available.
 *
 * The expected shape of that resolution, for continuity with Phase 24: erasure
 * removes *content* while leaving an anchored digest of the removed record in
 * place, and the chain is extended with an explicit erasure entry rather than
 * rewritten. Whether that satisfies a given regulator's erasure request is
 * Phase 24's question, not this one.
 */
export interface RetentionPolicy {
  /** Identifies the policy in a review's output. Name it as a rule, not a number: `eu-account-activity-7y`. */
  readonly name: string;

  /**
   * The instant at or before which an entry is past retention.
   *
   * `now` is a parameter rather than a clock read: a policy that consults the
   * wall clock internally cannot be tested against a pinned date, and the
   * boundary behaviour that matters — an entry exactly at the window edge — is
   * exactly what a test has to be able to fix in place.
   *
   * A policy that must nominate nothing (a legal hold, for instance) returns
   * the earliest possible date. Phase 24 will give that a name and a record of
   * its own; here it is what the shape already permits.
   */
  cutoffDate(now: Date): Date;
}

/** One year of milliseconds, and the same ambiguity that makes `365` worth stating. */
const DAYS_PER_YEAR = 365;
const MS_PER_DAY = 86_400_000;

/** A retention window expressed in whole days. */
export interface RetentionWindow {
  readonly days: number;
}

/**
 * The one policy shape this phase needs: keep entries for N days.
 *
 * A class rather than a bare function because the *identity* of the policy has
 * to travel with its decision. A review that reports "records older than
 * 2024-03-01 are candidates" without saying which rule produced that date is
 * not actionable — the operator cannot tell whether the seven-year financial
 * rule or the ninety-day support-log rule was applied.
 */
export class AgeRetentionPolicy implements RetentionPolicy {
  readonly name: string;
  readonly window: RetentionWindow;

  constructor(name: string, window: RetentionWindow) {
    if (!Number.isInteger(window.days) || window.days < 1) {
      throw new Error(`Retention window for "${name}" must be a whole number of days >= 1.`);
    }

    this.name = name;
    this.window = window;
  }

  /** A window of `years` calendar years, rounded to whole days. */
  static yearly(name: string, years: number): AgeRetentionPolicy {
    return new AgeRetentionPolicy(name, { days: years * DAYS_PER_YEAR });
  }

  cutoffDate(now: Date): Date {
    return new Date(now.getTime() - this.window.days * MS_PER_DAY);
  }
}

/**
 * The default window for a deployment with no policy configured: seven years.
 *
 * Not a safe default so much as a *conservative* one — it is the length common
 * to financial-record obligations, and erring the other way (short) destroys
 * evidence an operator may still be legally required to hold. The correct value
 * is always the deployment's, and configuring it is an operator task.
 */
export const DEFAULT_RETENTION_WINDOW_DAYS = 7 * DAYS_PER_YEAR;

/** The policy used when a caller supplies none. */
export const DEFAULT_RETENTION_POLICY: RetentionPolicy = new AgeRetentionPolicy("default-7y", {
  days: DEFAULT_RETENTION_WINDOW_DAYS,
});
