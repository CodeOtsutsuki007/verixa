import type { Result } from "@verixa/shared-kernel";

import type { AuditEvent, AuditEventId } from "../../domain/entities/audit-event.js";
import type { AuditAction } from "../../domain/value-objects/audit-action.js";

/**
 * Query filters for searching audit events.
 */
export interface AuditEventFilters {
  /** Filter by actor who initiated the actions */
  readonly actorId?: string;
  /** Filter by action type */
  readonly action?: AuditAction;
  /** Filter by resource type */
  readonly resourceType?: string;
  /** Filter by specific resource ID */
  readonly resourceId?: string;
  /** Filter by organization (required for tenant isolation) */
  readonly organizationId: string;
  /** Filter by timestamp range (inclusive) */
  readonly timestampFrom?: Date;
  readonly timestampTo?: Date;
}

/**
 * Pagination parameters for query results.
 */
export interface PaginationParams {
  /** Cursor for keyset pagination (opaque string from previous result) */
  readonly cursor?: string;
  /** Maximum number of results to return */
  readonly limit: number;
}

/**
 * Paginated query result.
 */
export interface PaginatedAuditEvents {
  /** The events matching the query */
  readonly events: readonly AuditEvent[];
  /** Cursor for fetching the next page, undefined if this is the last page */
  readonly nextCursor?: string;
  /** Total count of events matching the filter (optional, may be expensive to compute) */
  readonly totalCount?: number;
}

/**
 * Repository port for audit events.
 *
 * ## Append-only by design
 *
 * This interface deliberately excludes any `update()` or `delete()` methods.
 * Audit events are immutable facts — once an action has occurred and been
 * recorded, that record cannot change. This is not merely convention; it is
 * enforced at three layers:
 *
 * 1. **Domain model**: `AuditEvent` has no setters
 * 2. **Repository port** (here): No mutation methods in the interface
 * 3. **Database**: UPDATE/DELETE grants revoked for the application role
 *
 * Making mutation unrepresentable in the type system (layer 2) is what
 * prevents a well-intentioned developer from adding an "edit audit log" feature
 * that would undermine the entire purpose of the audit trail. The signature
 * `append(event): Promise<Result<void>>` is the complete write API.
 *
 * ## Why append returns Result
 *
 * Even though appending to an audit log should always succeed in normal
 * operation, there are failure modes that must be handled:
 * - Database unavailable
 * - Disk full
 * - Constraint violation (e.g., duplicate ID, which should be impossible but
 *   is a database-level check)
 *
 * These are *exceptional* in the true sense — they should never happen in
 * production, but when they do, the caller needs to know. Unlike a use case
 * failure (invalid input, business rule violation), an audit append failure
 * is usually logged and the operation continues, because failing the operation
 * that *caused* the audit event (e.g., blocking a successful login because the
 * audit log is down) is worse than having a gap in the audit trail.
 *
 * See `RecordAuditEvent` use case for how append failures are handled.
 *
 * ## Query methods and tenant isolation
 *
 * Every query method requires `organizationId` in its filters. This is
 * non-negotiable: audit events from one organization must never be visible to
 * another without explicit permission escalation. The port enforces this at
 * the type level by making `organizationId` a required field in
 * `AuditEventFilters`.
 *
 * Implementations must enforce this at the database level as well (Row-Level
 * Security or equivalent), but the port's signature is the first line of
 * defense — it makes writing a cross-tenant query require actively working
 * around the type system.
 *
 * ## No count-only queries
 *
 * There is no separate `count()` method. If a caller needs a count, they
 * request it via the `totalCount` field in pagination parameters. This is
 * deliberate: counting audit events is expensive (potentially a full table
 * scan, depending on filters), and making it a side effect of an actual query
 * rather than a standalone operation discourages writing "how many events do
 * we have?" dashboards that scan the entire log on every page load.
 *
 * Implementations may return `undefined` for `totalCount` if computing it
 * would be prohibitively expensive for the given filter set.
 */
export interface AuditEventRepository {
  /**
   * Appends a new audit event to the log.
   *
   * This is the sole write operation. No update, delete, or bulk operations
   * exist — events are append-only.
   *
   * @param event - The event to append
   * @returns Success if the event was persisted, or an error describing why it failed
   */
  append(event: AuditEvent): Promise<Result<void, AppendAuditEventError>>;

  /**
   * Finds an audit event by its ID.
   *
   * Used for lookups when an event ID is directly referenced (e.g., from
   * another system's logs, or when confirming an anchoring reference).
   *
   * @param id - The event ID to look up
   * @param organizationId - The organization the event must belong to (tenant isolation)
   * @returns The event if found and belongs to the specified organization, undefined otherwise
   */
  findById(id: AuditEventId, organizationId: string): Promise<AuditEvent | undefined>;

  /**
   * Queries audit events matching the given filters.
   *
   * Results are ordered by timestamp descending (most recent first) within each
   * page. Pagination is cursor-based (keyset pagination) rather than
   * offset-based, to remain stable under concurrent inserts — an offset-based
   * page 2 would shift if new events arrived between fetching page 1 and page 2.
   *
   * @param filters - Query filters (organizationId is required)
   * @param pagination - Pagination parameters
   * @returns Paginated result set
   */
  query(filters: AuditEventFilters, pagination: PaginationParams): Promise<PaginatedAuditEvents>;

  /**
   * Retrieves a range of events for a given organization in sequence order.
   *
   * Used primarily for chain verification and anchoring — operations that need
   * to walk the event sequence in order. Unlike `query()`, this is ordered by
   * ID/insertion order (ascending), not timestamp.
   *
   * @param organizationId - The organization whose events to retrieve
   * @param fromId - Start from this event ID (inclusive), or from the beginning if undefined
   * @param limit - Maximum number of events to return
   * @returns Events in sequence order
   */
  getSequenceRange(
    organizationId: string,
    fromId?: AuditEventId,
    limit?: number,
  ): Promise<readonly AuditEvent[]>;
}

/**
 * Errors that can occur when appending an audit event.
 */
export type AppendAuditEventError =
  | { readonly type: "database_unavailable"; readonly message: string }
  | { readonly type: "constraint_violation"; readonly message: string }
  | { readonly type: "unknown"; readonly message: string };

/**
 * Creates a database unavailable error.
 */
export function databaseUnavailableError(message: string): AppendAuditEventError {
  return { type: "database_unavailable", message };
}

/**
 * Creates a constraint violation error.
 */
export function constraintViolationError(message: string): AppendAuditEventError {
  return { type: "constraint_violation", message };
}

/**
 * Creates an unknown error.
 */
export function unknownAppendError(message: string): AppendAuditEventError {
  return { type: "unknown", message };
}
