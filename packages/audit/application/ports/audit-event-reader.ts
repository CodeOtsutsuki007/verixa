import type { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";

/**
 * What a read of the audit log is scoped to.
 *
 * `organizationId` is required, and it is set by the query/export use cases
 * from the *authorized* organization — never passed through from a caller.
 * An adapter therefore never sees an unscoped read, and "forgot to add the
 * tenant filter" is not a bug an implementation of this port can have.
 */
export interface AuditEventCriteria {
  readonly organizationId: string;
  readonly actorId?: string | undefined;
  readonly subjectId?: string | undefined;
  /** Inclusive lower bound on `occurredAt`. */
  readonly from?: Date | undefined;
  /** Inclusive upper bound on `occurredAt`. */
  readonly to?: Date | undefined;
}

/** A keyset page: entries with `sequence` greater than `afterSequence`. */
export interface AuditEventPage {
  readonly afterSequence?: number | undefined;
  readonly limit: number;
}

/**
 * The read side of the audit log, as the query and export use cases need it.
 *
 * Separate from `AuditLogRepository` because the two serve different masters:
 * that port exists to append and to walk the whole chain for verification,
 * and must stay unscoped to do so; this one exists to answer an
 * organization's questions about its own history, and must never be unscoped.
 * Putting both on one interface would give every caller of the second a
 * method that silently ignores tenancy.
 *
 * Deliberately minimal. Filter semantics, index-backed keyset pagination and
 * a memory-bounded streaming adapter are Issues 187–189's to build; this is
 * the seam their adapters plug into, and they are free to widen it.
 */
export interface AuditEventReader {
  /** Matching entries in ascending `sequence` order, at most `page.limit`. */
  query(criteria: AuditEventCriteria, page: AuditEventPage): Promise<readonly AuditLogEntry[]>;

  /**
   * Every matching entry in ascending `sequence` order, yielded incrementally
   * so an export of years of history never has to fit in memory at once.
   */
  stream(criteria: AuditEventCriteria): AsyncIterable<AuditLogEntry>;
}
