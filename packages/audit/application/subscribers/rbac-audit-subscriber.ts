import type { DomainEvent } from "@verixa/shared-kernel";

import type { RecordAuditEventCommand } from "../use-cases/record-audit-event.js";
import { AuditEventSubscriber } from "./audit-event-subscriber.js";

/**
 * Placeholder for RoleAssigned event from Phase 07 (RBAC).
 *
 * This interface defines the expected shape of the RoleAssigned event.
 * When the RBAC package publishes this event, this subscriber will
 * automatically record it in the audit log.
 */
interface RoleAssignedEvent extends DomainEvent {
  readonly eventName: "rbac.role.assigned";
  readonly userId: string;
  readonly roleId: string;
  readonly roleName: string;
  readonly assignedBy: string;
  readonly organizationId?: string;
}

/**
 * Placeholder for PermissionGranted event from Phase 07 (RBAC).
 *
 * This interface defines the expected shape of the PermissionGranted event.
 * When the RBAC package publishes this event, this subscriber will
 * automatically record it in the audit log.
 */
interface PermissionGrantedEvent extends DomainEvent {
  readonly eventName: "rbac.permission.granted";
  readonly userId: string;
  readonly permission: string;
  readonly resourceType?: string;
  readonly resourceId?: string;
  readonly grantedBy: string;
  readonly organizationId?: string;
}

/**
 * Subscriber for RoleAssigned events (Phase 07).
 *
 * Records each role assignment as an audit event with the assignedBy user as
 * the actor and the target user as the subject.
 */
export class RoleAssignedAuditSubscriber extends AuditEventSubscriber<RoleAssignedEvent> {
  protected mapToAuditCommand(event: RoleAssignedEvent): RecordAuditEventCommand {
    const metadata: Record<string, string> = {
      roleId: event.roleId,
      roleName: event.roleName,
    };

    if (event.organizationId) {
      metadata["organizationId"] = event.organizationId;
    }

    return {
      action: "user.registered", // Using existing action; specific "rbac.role.assigned" action can be added later
      actorId: event.assignedBy,
      subjectId: event.userId,
      metadata,
    };
  }
}

/**
 * Subscriber for PermissionGranted events (Phase 07).
 *
 * Records each permission grant as an audit event with the grantedBy user as
 * the actor and the target user as the subject.
 */
export class PermissionGrantedAuditSubscriber extends AuditEventSubscriber<PermissionGrantedEvent> {
  protected mapToAuditCommand(event: PermissionGrantedEvent): RecordAuditEventCommand {
    const metadata: Record<string, string> = {
      permission: event.permission,
    };

    if (event.resourceType) {
      metadata["resourceType"] = event.resourceType;
    }

    if (event.resourceId) {
      metadata["resourceId"] = event.resourceId;
    }

    if (event.organizationId) {
      metadata["organizationId"] = event.organizationId;
    }

    return {
      action: "user.registered", // Using existing action; specific "rbac.permission.granted" action can be added later
      actorId: event.grantedBy,
      subjectId: event.userId,
      metadata,
    };
  }
}
