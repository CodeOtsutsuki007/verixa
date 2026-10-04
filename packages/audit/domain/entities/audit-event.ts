import { createId, type Id } from "@verixa/shared-kernel";

import type { AuditAction } from "../value-objects/audit-action.js";
import { isAuditAction } from "../value-objects/audit-action.js";
import { validateAuditMetadata } from "../value-objects/audit-metadata-schemas.js";

export type AuditEventId = Id<"AuditEventId">;

/**
 * Resource type identifier.
 *
 * Describes what kind of entity the audit event pertains to. Combined with
 * `resourceId`, this forms a complete reference to the affected resource.
 *
 * Examples: `user`, `organization`, `session`, `verification_request`, `role`
 */
export type ResourceType = string;

/**
 * Organization identifier for tenant scoping.
 *
 * Every audit event is scoped to an organization, ensuring audit logs are
 * tenant-isolated and cross-organization queries are impossible without
 * explicit permission escalation.
 *
 * For system-level events that don't belong to any specific organization,
 * this may be a sentinel value (e.g., a well-known system org ID).
 */
export type OrganizationId = string;

interface AuditEventProps {
  readonly id: AuditEventId;
  readonly actorId: string | undefined;
  readonly action: AuditAction;
  readonly resourceType: ResourceType;
  readonly resourceId: string;
  readonly timestamp: Date;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly organizationId: OrganizationId;
}

/**
 * An immutable record of a security-relevant action.
 *
 * ## Why audit events are immutable
 *
 * An audit log is a ledger, not a mutable table. Once an event has occurred
 * and been recorded, the record of that occurrence cannot change — any
 * alteration would undermine the entire purpose of the audit trail, which is
 * to provide a trustworthy account of what actually happened.
 *
 * This immutability is enforced at three layers:
 * 1. **Domain model**: No setter methods exist; properties are readonly
 * 2. **Repository port**: No update/delete operations in the interface
 * 3. **Database**: UPDATE/DELETE grants revoked for the application role
 *
 * The three layers are complementary. The domain model makes accidental
 * mutation hard; the repository port makes intentional mutation unrepresentable
 * in the application layer; the database grants make bypassing both layers
 * require direct DBA intervention.
 *
 * ## Nullable actorId for system actions
 *
 * Most audit events have a human or service account actor — someone initiated
 * the action. But some events are purely system-driven: a session expiring, a
 * scheduled job running, an automated check completing. These have no
 * meaningful actor, and forcing a synthetic "system" actor ID would just add
 * noise to queries. `actorId` is therefore nullable, with `undefined`
 * explicitly meaning "this was a system action with no initiating actor."
 *
 * ## Metadata as structured JSON
 *
 * Each action has context-specific details beyond the common fields. Rather
 * than adding nullable fields for every possible detail (and ending up with a
 * table of 90% NULLs), action-specific data goes in `metadata` as validated
 * JSON. Each action type has a Zod schema defining its metadata shape,
 * ensuring metadata is queryable and consistent, not an opaque blob.
 *
 * See `audit-metadata-schemas.ts` for the schema registry and validation.
 *
 * ## organizationId for tenant scoping
 *
 * Multi-tenancy in audit logs is not optional. Every query, export, and
 * analysis must be scoped to the tenant performing it — letting one
 * organization see another's audit trail would be a catastrophic isolation
 * failure. `organizationId` is therefore a first-class field on every event,
 * and the repository enforces it on every query path.
 *
 * ## No delete or update
 *
 * There is deliberately no way to modify an `AuditEvent` after construction.
 * Corrections, if ever needed, are handled by appending a *new* event that
 * describes the correction, not by editing the original. This preserves the
 * full history, including mistakes, which is exactly what an audit log is for.
 */
export class AuditEvent {
  readonly id: AuditEventId;
  readonly actorId: string | undefined;
  readonly action: AuditAction;
  readonly resourceType: ResourceType;
  readonly resourceId: string;
  readonly timestamp: Date;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly organizationId: OrganizationId;

  private constructor(props: AuditEventProps) {
    this.id = props.id;
    this.actorId = props.actorId;
    this.action = props.action;
    this.resourceType = props.resourceType;
    this.resourceId = props.resourceId;
    this.timestamp = props.timestamp;
    this.metadata = Object.freeze({ ...props.metadata });
    this.organizationId = props.organizationId;
  }

  /**
   * Creates a new audit event with validation.
   *
   * @param params - Event parameters
   * @param params.actorId - The actor who initiated the action, or undefined for system actions
   * @param params.action - The action that occurred (must be a valid AuditAction)
   * @param params.resourceType - The type of resource affected
   * @param params.resourceId - The ID of the affected resource
   * @param params.organizationId - The organization this event belongs to
   * @param params.metadata - Action-specific metadata (validated against action's schema)
   * @param params.timestamp - When the event occurred (defaults to now)
   *
   * @throws {Error} If the action is not a valid AuditAction
   * @throws {ZodError} If metadata validation fails for the action's schema
   */
  static create(params: {
    actorId?: string | undefined;
    action: string;
    resourceType: ResourceType;
    resourceId: string;
    organizationId: OrganizationId;
    metadata?: Record<string, unknown>;
    timestamp?: Date;
  }): AuditEvent {
    // Validate action is in the known set
    if (!isAuditAction(params.action)) {
      throw new Error(
        `Invalid audit action: "${params.action}". Action must be registered in AuditAction type.`,
      );
    }

    // Validate and normalize metadata according to action's schema
    const validatedMetadata = validateAuditMetadata(params.action, params.metadata ?? {});

    return new AuditEvent({
      id: createId<"AuditEventId">(),
      actorId: params.actorId,
      action: params.action,
      resourceType: params.resourceType,
      resourceId: params.resourceId,
      timestamp: params.timestamp ?? new Date(),
      metadata: validatedMetadata,
      organizationId: params.organizationId,
    });
  }

  /**
   * Reconstitutes an audit event from trusted storage.
   *
   * Use this when loading events from the database. Unlike `create()`, this
   * skips validation — the assumption is that stored data has already been
   * validated on the way in and can be trusted on the way out.
   *
   * **Do not** use this with untrusted input (API requests, imports). Those
   * must go through `create()`.
   */
  static reconstitute(props: AuditEventProps): AuditEvent {
    return new AuditEvent(props);
  }

  /**
   * Creates a copy with the metadata field replaced.
   *
   * This is **not** for editing existing events (audit events are immutable).
   * It's a utility for tests and data migrations where you need to construct
   * an event shape with specific metadata without going through the validation
   * path.
   *
   * Production code should never call this.
   */
  withMetadata(metadata: Record<string, unknown>): AuditEvent {
    return new AuditEvent({
      id: this.id,
      actorId: this.actorId,
      action: this.action,
      resourceType: this.resourceType,
      resourceId: this.resourceId,
      timestamp: this.timestamp,
      metadata: Object.freeze({ ...metadata }),
      organizationId: this.organizationId,
    });
  }
}
