import type { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";
import type { AuditLogRepository } from "../ports/audit-log-repository.js";

export interface QueryAuditEventsFilters {
  readonly actorId?: string | undefined;
  readonly subjectId?: string | undefined;
  readonly organizationId?: string | undefined;
  readonly action?: string | undefined;
  readonly fromDate?: Date | undefined;
  readonly toDate?: Date | undefined;
}

export interface QueryAuditEventsCommand {
  readonly filters?: QueryAuditEventsFilters;
  readonly cursor?: number | undefined;
  readonly limit?: number;
}

export interface QueryAuditEventsResult {
  readonly entries: readonly AuditLogEntry[];
  readonly nextCursor: number | undefined;
  readonly hasMore: boolean;
}

/**
 * Queries the audit log with filtering and cursor-based pagination.
 *
 * ## Keyset (cursor-based) pagination
 *
 * Uses `sequence` as the cursor rather than offset-based pagination. An offset
 * of 1000 forces the database to read and skip 1000 rows even when none of
 * them are returned, and the cost grows linearly with depth. A keyset cursor
 * says "everything after sequence N," which is a range scan on the indexed
 * column — constant cost regardless of how far into the log the query reaches.
 *
 * The trade is that you cannot jump to an arbitrary page, only continue from
 * where you left off. That is an acceptable restriction for an audit log: the
 * typical access pattern is "show me what happened," and walking forward
 * through a result set is exactly that.
 */
export class QueryAuditEvents {
  constructor(private readonly repository: AuditLogRepository) {}

  async execute(command: QueryAuditEventsCommand): Promise<QueryAuditEventsResult> {
    const limit = command.limit ?? 50;
    const cursor = command.cursor ?? 0;

    // Fetch one extra to determine if there are more results
    const entries = await this.repository.findWithFilters({
      filters: command.filters ?? {},
      fromSequence: cursor + 1,
      limit: limit + 1,
    });

    const hasMore = entries.length > limit;
    const resultEntries = hasMore ? entries.slice(0, limit) : entries;
    const nextCursor =
      hasMore && resultEntries.length > 0
        ? resultEntries[resultEntries.length - 1]!.sequence
        : undefined;

    return {
      entries: resultEntries,
      nextCursor,
      hasMore,
    };
  }
}
