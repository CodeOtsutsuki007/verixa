import { Result } from "@verixa/shared-kernel";

import type { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";
import type { AuditReader } from "../../domain/policies/audit-access-policy.js";
import { type AuditReadError, authorizeAndRecordAuditRead } from "../audit-read-access.js";
import type { AuditEventReader } from "../ports/audit-event-reader.js";

import type { RecordAuditEvent } from "./record-audit-event.js";

/** The largest page a single query may return. */
export const MAX_AUDIT_QUERY_PAGE_SIZE = 100;
const DEFAULT_PAGE_SIZE = 50;

export interface QueryAuditEventsCommand {
  /** The authenticated caller, built by the interface layer — see {@link AuditReader}. */
  readonly reader: AuditReader;
  /** Whose audit log to read. Must be the reader's own organization. */
  readonly organizationId: string;
  readonly actorId?: string | undefined;
  readonly subjectId?: string | undefined;
  readonly from?: Date | undefined;
  readonly to?: Date | undefined;
  /** Keyset cursor: the last `sequence` of the previous page. */
  readonly afterSequence?: number | undefined;
  /** Clamped to `1..`{@link MAX_AUDIT_QUERY_PAGE_SIZE}. */
  readonly limit?: number | undefined;
}

/**
 * Reads one page of an organization's audit log, on behalf of someone allowed
 * to read it, and leaves a record that they did.
 *
 * ## Who audits the auditors
 *
 * An audit log is the most concentrated record of who did what in the system,
 * which makes it one of the most sensitive things in it. If reading it were
 * unprivileged, or privileged but unobserved, the log would become the easiest
 * way to learn what an organization's users do — and nobody would know it had
 * been used that way. So every read requires `audit:query` within the
 * requested organization, and every read is itself appended to the audit log
 * before any entry is returned. Compliance regimes (SOC 2's CC7 monitoring
 * criteria, among others) expect exactly this.
 *
 * ## Why the page size is capped
 *
 * `audit:query` is granted more widely than `audit:export`. Without a cap, a
 * query with `limit: 10_000_000` is an export by another name, reached with
 * the weaker permission. The cap keeps the two permissions meaning different
 * things.
 */
export class QueryAuditEvents {
  constructor(
    private readonly events: AuditEventReader,
    private readonly recordAuditEvent: RecordAuditEvent,
  ) {}

  async execute(
    command: QueryAuditEventsCommand,
  ): Promise<Result<readonly AuditLogEntry[], AuditReadError>> {
    const criteria = {
      organizationId: command.organizationId,
      actorId: command.actorId,
      subjectId: command.subjectId,
      from: command.from,
      to: command.to,
    };

    const access = await authorizeAndRecordAuditRead(
      this.recordAuditEvent,
      command.reader,
      "query",
      criteria,
    );
    if (Result.isErr(access)) return access;

    const limit = Math.min(
      Math.max(Math.trunc(command.limit ?? DEFAULT_PAGE_SIZE), 1),
      MAX_AUDIT_QUERY_PAGE_SIZE,
    );

    return Result.ok(
      await this.events.query(criteria, { afterSequence: command.afterSequence, limit }),
    );
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
