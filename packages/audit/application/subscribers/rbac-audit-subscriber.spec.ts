import { describe, expect, it } from "vitest";

import { InMemoryAuditLogRepository } from "../../infrastructure/testing/in-memory-audit-repositories.js";
import { RecordAuditEvent } from "../use-cases/record-audit-event.js";

import {
  PermissionGrantedAuditSubscriber,
  type PermissionGrantedEvent,
  RoleAssignedAuditSubscriber,
  type RoleAssignedEvent,
} from "./rbac-audit-subscriber.js";

function harness(): {
  repository: InMemoryAuditLogRepository;
  roleAssigned: RoleAssignedAuditSubscriber;
  permissionGranted: PermissionGrantedAuditSubscriber;
} {
  const repository = new InMemoryAuditLogRepository();
  const recordEvent = new RecordAuditEvent(repository);
  return {
    repository,
    roleAssigned: new RoleAssignedAuditSubscriber(recordEvent),
    permissionGranted: new PermissionGrantedAuditSubscriber(recordEvent),
  };
}

const occurredAt = new Date("2026-01-01T09:00:00.000Z");

function roleAssigned(
  organization: { organizationId: string } | undefined = undefined,
): RoleAssignedEvent {
  return {
    eventName: "rbac.role.assigned",
    aggregateId: "role-1",
    occurredAt,
    userId: "user-7",
    roleId: "role-editor",
    roleName: "editor",
    assignedBy: "admin-1",
    ...organization,
  };
}

function permissionGranted(
  resource:
    | { readonly resourceType: string; readonly resourceId: string }
    | { readonly organizationId: string }
    | undefined = undefined,
): PermissionGrantedEvent {
  return {
    eventName: "rbac.permission.granted",
    aggregateId: "permission-1",
    occurredAt,
    userId: "user-7",
    permission: "document:write",
    grantedBy: "admin-1",
    ...resource,
  };
}

describe("RoleAssignedAuditSubscriber", () => {
  it("separates the admin who acted from the user the role was given to", async () => {
    const { repository, roleAssigned: subscriber } = harness();

    await subscriber.handle(roleAssigned());

    const entry = await repository.findLatest();
    expect(entry?.actorId).toBe("admin-1");
    expect(entry?.subjectId).toBe("user-7");
    expect(entry?.metadata).toEqual({ roleId: "role-editor", roleName: "editor" });
  });

  it("records the organization when the grant is tenant-scoped", async () => {
    const { repository, roleAssigned: subscriber } = harness();

    await subscriber.handle(roleAssigned({ organizationId: "org-a" }));

    const entry = await repository.findLatest();
    expect(entry?.metadata).toEqual({
      roleId: "role-editor",
      roleName: "editor",
      organizationId: "org-a",
    });
  });
});

describe("PermissionGrantedAuditSubscriber", () => {
  it("records the permission and who granted it", async () => {
    const { repository, permissionGranted: subscriber } = harness();

    await subscriber.handle(permissionGranted());

    const entry = await repository.findLatest();
    expect(entry?.actorId).toBe("admin-1");
    expect(entry?.subjectId).toBe("user-7");
    expect(entry?.metadata).toEqual({ permission: "document:write" });
  });

  it("names the resource the permission applies to when there is one", async () => {
    const { repository, permissionGranted: subscriber } = harness();

    await subscriber.handle(permissionGranted({ resourceType: "document", resourceId: "doc-9" }));

    const entry = await repository.findLatest();
    expect(entry?.metadata).toEqual({
      permission: "document:write",
      resourceType: "document",
      resourceId: "doc-9",
    });
  });

  it("keeps the tenant the grant is scoped to, since that is the query auditors run", async () => {
    const { repository, permissionGranted: subscriber } = harness();

    await subscriber.handle(permissionGranted({ organizationId: "org-a" }));

    const entry = await repository.findLatest();
    expect(entry?.metadata).toEqual({
      permission: "document:write",
      organizationId: "org-a",
    });
  });
});

describe("RBAC subscribers sharing one log", () => {
  it("chains a grant after an assignment instead of restarting the sequence", async () => {
    const { repository, roleAssigned: assignment, permissionGranted: grant } = harness();

    await assignment.handle(roleAssigned());
    await grant.handle(permissionGranted());

    const entries = repository.all();
    expect(entries[1]?.previousHash).toBe(entries[0]?.hash);
    expect(entries.map((entry) => entry.sequence)).toEqual([1, 2]);
  });
});
