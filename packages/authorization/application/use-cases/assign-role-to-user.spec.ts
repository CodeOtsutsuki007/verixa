import { asId, Result } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { Role } from "../../domain/entities/role.js";
import { InMemoryRoleRepository } from "../../infrastructure/fakes/in-memory-role-repository.js";
import { InMemoryUserRoleAssignmentRepository } from "../../infrastructure/fakes/in-memory-user-role-assignment-repository.js";

import { AssignRoleToUser } from "./assign-role-to-user.js";

describe("AssignRoleToUser", () => {
  let roleRepo: InMemoryRoleRepository;
  let assignmentRepo: InMemoryUserRoleAssignmentRepository;
  let assignRoleToUser: AssignRoleToUser;

  const actorId = asId<"UserId">("user_admin");
  const targetUserId = asId<"UserId">("user_target");
  const orgId = asId<"OrgId">("org_cyberdyne");

  let globalAdminRole: Role;
  let scopedEditorRole: Role;

  beforeEach(async () => {
    roleRepo = new InMemoryRoleRepository();
    assignmentRepo = new InMemoryUserRoleAssignmentRepository();
    assignRoleToUser = new AssignRoleToUser(assignmentRepo, roleRepo);

    // Seed test roles
    const adminRes = Role.create({
      name: "global-admin",
      permissions: ["users:read", "users:write"],
    });
    if (Result.isOk(adminRes)) {
      globalAdminRole = adminRes.value;
      await roleRepo.save(globalAdminRole);
    }

    const editorRes = Role.create({
      name: "editor",
      orgId,
      permissions: ["content:write"],
    });
    if (Result.isOk(editorRes)) {
      scopedEditorRole = editorRes.value;
      await roleRepo.save(scopedEditorRole);
    }
  });

  it("successfully assigns a global role to a user system-wide", async () => {
    const result = await assignRoleToUser.execute({
      userId: targetUserId,
      roleId: globalAdminRole.id,
      orgId: null,
      assignedBy: actorId,
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isOk(result)) {
      expect(result.value.userId).toBe(targetUserId);
      expect(result.value.roleId).toBe(globalAdminRole.id);
      expect(result.value.orgId).toBeNull();
      expect(result.value.assignedBy).toBe(actorId);

      const persisted = await assignmentRepo.findById(result.value.id);
      expect(persisted).toBeDefined();
    }
  });

  it("successfully assigns an organization-scoped role to a user", async () => {
    const result = await assignRoleToUser.execute({
      userId: targetUserId,
      roleId: scopedEditorRole.id,
      orgId,
      assignedBy: actorId,
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isOk(result)) {
      expect(result.value.userId).toBe(targetUserId);
      expect(result.value.roleId).toBe(scopedEditorRole.id);
      expect(result.value.orgId).toBe(orgId);

      const assignments = await assignmentRepo.findByUserAndOrg(targetUserId, orgId);
      expect(assignments).toHaveLength(1);
      expect(assignments[0]?.roleId).toBe(scopedEditorRole.id);
    }
  });

  it("allows setting an expiration date on role assignment", async () => {
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60); // 1 hour later
    const result = await assignRoleToUser.execute({
      userId: targetUserId,
      roleId: scopedEditorRole.id,
      orgId,
      assignedBy: actorId,
      expiresAt,
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isOk(result)) {
      expect(result.value.expiresAt?.getTime()).toBe(expiresAt.getTime());
    }
  });

  it("returns existing assignment idempotently when already assigned and active", async () => {
    const first = await assignRoleToUser.execute({
      userId: targetUserId,
      roleId: scopedEditorRole.id,
      orgId,
      assignedBy: actorId,
    });
    expect(Result.isOk(first)).toBe(true);

    const second = await assignRoleToUser.execute({
      userId: targetUserId,
      roleId: scopedEditorRole.id,
      orgId,
      assignedBy: actorId,
    });
    expect(Result.isOk(second)).toBe(true);

    if (Result.isOk(first) && Result.isOk(second)) {
      expect(second.value.id).toBe(first.value.id);
    }

    const all = await assignmentRepo.findByUserAndOrg(targetUserId, orgId);
    expect(all).toHaveLength(1);
  });

  it("fails if target role does not exist", async () => {
    const missingRoleId = asId<"RoleId">("role_non_existent");
    const result = await assignRoleToUser.execute({
      userId: targetUserId,
      roleId: missingRoleId,
      orgId,
      assignedBy: actorId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.code).toBe("NOT_FOUND");
      expect(result.error.message).toContain('Role with ID "role_non_existent" was not found');
    }
  });

  it("fails if attempting to assign an organization-scoped role to another organization", async () => {
    const anotherOrgId = asId<"OrgId">("org_other");
    const result = await assignRoleToUser.execute({
      userId: targetUserId,
      roleId: scopedEditorRole.id,
      orgId: anotherOrgId,
      assignedBy: actorId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.code).toBe("VALIDATION_ERROR");
      expect(result.error.message).toContain("cannot be assigned to scope");
    }
  });

  it("fails if attempting to assign an organization-scoped role globally", async () => {
    const result = await assignRoleToUser.execute({
      userId: targetUserId,
      roleId: scopedEditorRole.id,
      orgId: null,
      assignedBy: actorId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.code).toBe("VALIDATION_ERROR");
      expect(result.error.message).toContain("cannot be assigned to scope");
    }
  });

  it("fails when validation invariants are violated (e.g. invalid expiry)", async () => {
    const pastExpiresAt = new Date(Date.now() - 1000 * 60 * 60); // 1 hour ago
    const result = await assignRoleToUser.execute({
      userId: targetUserId,
      roleId: globalAdminRole.id,
      orgId: null,
      assignedBy: actorId,
      expiresAt: pastExpiresAt,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.code).toBe("VALIDATION_ERROR");
    }
  });
});
