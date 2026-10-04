import { asId, Result } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { UserRoleAssignment } from "../../domain/entities/user-role-assignment.js";
import { InMemoryUserRoleAssignmentRepository } from "../../infrastructure/fakes/in-memory-user-role-assignment-repository.js";

import { RevokeRoleFromUser } from "./revoke-role-from-user.js";

describe("RevokeRoleFromUser", () => {
  let assignmentRepo: InMemoryUserRoleAssignmentRepository;
  let revokeRoleFromUser: RevokeRoleFromUser;

  const targetUserId = asId<"UserId">("user_target");
  const roleId = asId<"RoleId">("role_admin");
  const orgId = asId<"OrgId">("org_cyberdyne");
  const assignedBy = asId<"UserId">("user_admin");

  let seededAssignment: UserRoleAssignment;

  beforeEach(async () => {
    assignmentRepo = new InMemoryUserRoleAssignmentRepository();
    revokeRoleFromUser = new RevokeRoleFromUser(assignmentRepo);

    const assignmentRes = UserRoleAssignment.create({
      userId: targetUserId,
      roleId,
      orgId,
      assignedBy,
    });
    if (Result.isOk(assignmentRes)) {
      seededAssignment = assignmentRes.value;
      await assignmentRepo.save(seededAssignment);
    }
  });

  it("successfully revokes an assignment by assignmentId", async () => {
    const result = await revokeRoleFromUser.execute({
      assignmentId: seededAssignment.id,
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isOk(result)) {
      expect(result.value.id).toBe(seededAssignment.id);
    }

    const fetched = await assignmentRepo.findById(seededAssignment.id);
    expect(fetched).toBeUndefined();
  });

  it("successfully revokes an assignment by (userId, roleId, orgId) tuple", async () => {
    const result = await revokeRoleFromUser.execute({
      userId: targetUserId,
      roleId,
      orgId,
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isOk(result)) {
      expect(result.value.id).toBe(seededAssignment.id);
    }

    const remaining = await assignmentRepo.findByUserAndOrg(targetUserId, orgId);
    expect(remaining).toHaveLength(0);
  });

  it("returns NotFoundError when revoking non-existent assignmentId", async () => {
    const nonExistentId = asId<"UserRoleAssignmentId">("non_existent_id");
    const result = await revokeRoleFromUser.execute({
      assignmentId: nonExistentId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.code).toBe("NOT_FOUND");
    }
  });

  it("returns NotFoundError when revoking by tuple for non-existent role assignment", async () => {
    const anotherRoleId = asId<"RoleId">("role_other");
    const result = await revokeRoleFromUser.execute({
      userId: targetUserId,
      roleId: anotherRoleId,
      orgId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.code).toBe("NOT_FOUND");
    }
  });

  it("returns ValidationError when no valid identifier is provided", async () => {
    const result = await revokeRoleFromUser.execute({});

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.code).toBe("VALIDATION_ERROR");
    }
  });
});
