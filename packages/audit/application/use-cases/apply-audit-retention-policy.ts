import type { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";
import type { AuditLogRepository } from "../ports/audit-log-repository.js";
import { DEFAULT_RETENTION_POLICY, type RetentionPolicy } from "../ports/retention-policy.js";

export interface ApplyRetentionPolicyCommand {
  /** Pin the evaluation instant; defaults to now. Tests pin it. */
  readonly now?: Date | undefined;
  /** Resume from a previous review's `nextCursor`. */
  readonly cursor?: number | undefined;
  /** Entries examined per run. */
  readonly limit?: number | undefined;
  /** Restrict the review to one tenant. */
  readonly organizationId?: string | undefined;
}

/** An entry the policy says is past retention — and nothing has been done about it. */
export interface RetentionCandidate {
  readonly entry: AuditLogEntry;
  /** How old the entry was at evaluation, in whole days. */
  readonly ageDays: number;
}

/**
 * What a retention run produced.
 *
 * `disposition` is a literal field rather than implied by the absence of
 * deletion, and it is here so that a caller logging this result has something
 * to assert on. A review whose output reads like an action report is how an
 * identify-only job gets mistaken for an erasing one.
 */
export interface RetentionReview {
  readonly policy: string;
  readonly evaluatedAt: Date;
  readonly cutoff: Date;
  readonly candidates: readonly RetentionCandidate[];
  /** Sequence of the last entry examined, for resuming. */
  readonly evaluatedThroughSequence: number | undefined;
  readonly nextCursor: number | undefined;
  readonly hasMore: boolean;
  readonly disposition: "identified_only";
}

const MS_PER_DAY = 86_400_000;

/**
 * Identifies audit entries that have outlived the configured retention window.
 *
 * ## This job does not delete anything
 *
 * That restriction is the deliverable, not a stub waiting to be finished. The
 * decision that a record may be erased is a compliance judgement — retention
 * obligations, legal holds, and jurisdiction all override a plain age rule —
 * and Phase 24 owns it. What belongs to this phase is the *seam*: a query that
 * finds the candidates, a shape that reports them, and an interface that a
 * future erasure step consumes rather than reinvents.
 *
 * Keeping identification separate also makes it safe to run today. An operator
 * can schedule this against production now and start seeing their retention
 * backlog, which is the only way to learn that a policy was wrong before the
 * policy is what destroys the evidence.
 *
 * ## Why candidates are reported rather than archived in passing
 *
 * Moving or compressing old entries would rewrite where the chain's content
 * lives while leaving its hashes behind, and a verification run would then
 * report `content_altered` on records nobody altered. Archival has to be
 * designed together with verification and with anchoring — see
 * `docs/security/audit-log-integrity.md` — not bolted onto a query.
 *
 * ## Reading the pagination
 *
 * Entries are walked in sequence order with a keyset cursor, the same way
 * `QueryAuditEvents` does it. A retention run over a log with millions of
 * entries is a long job, and a long job that cannot be resumed is a long job
 * that gets run manually.
 */
export class ApplyAuditRetentionPolicy {
  constructor(
    private readonly repository: AuditLogRepository,
    private readonly policy: RetentionPolicy = DEFAULT_RETENTION_POLICY,
  ) {}

  async execute(command: ApplyRetentionPolicyCommand = {}): Promise<RetentionReview> {
    const now = command.now ?? new Date();
    const cutoff = this.policy.cutoffDate(now);
    const limit = command.limit ?? 200;
    const cursor = command.cursor ?? 0;

    // `toDate` is the retention boundary itself: this is a scan for age, and
    // the repository filter is what keeps it off the recent half of the log.
    const entries = await this.repository.findWithFilters({
      filters: {
        toDate: cutoff,
        organizationId: command.organizationId,
      },
      fromSequence: cursor + 1,
      // One extra, to know whether there is more without a second query.
      limit: limit + 1,
    });

    const hasMore = entries.length > limit;
    const examined = hasMore ? entries.slice(0, limit) : entries;

    const candidates = examined.map((entry) => ({
      entry,
      ageDays: Math.floor((now.getTime() - entry.occurredAt.getTime()) / MS_PER_DAY),
    }));

    return {
      policy: this.policy.name,
      evaluatedAt: now,
      cutoff,
      candidates,
      evaluatedThroughSequence: examined.at(-1)?.sequence,
      nextCursor:
        hasMore && examined.length > 0 ? examined[examined.length - 1]!.sequence : undefined,
      hasMore,
      disposition: "identified_only",
    };
  }
}
