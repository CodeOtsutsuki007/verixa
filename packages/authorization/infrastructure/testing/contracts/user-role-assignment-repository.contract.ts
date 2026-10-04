import { asId, Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { UserRoleAssignmentRepository } from "../../../application/ports/user-role-assignment-repository.js";
import {
  type OrgId,
  type RoleId,
  type UserId,
  UserRoleAssignment,
} from "../../../domain/entities/user-role-assignment.js";

const USER_1 = asId<"UserId">("11111111-1111-4111-8111-111111111111");
const USER_2 = asId<"UserId">("22222222-2222-4222-8222-222222222222");
const ADMIN = asId<"UserId">("33333333-3333-4333-8333-333333333333");
const ROLE_A = asId<"RoleId">("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
const ROLE_B = asId<"RoleId">("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
const ORG_X = asId<"OrganizationId">("xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx");
const ORG_Y = asId<"OrganizationId">("yyyyyyyy-yyyy-4yyy-8yyy-yyyyyyyyyyyy");

function makeAssignment(params: {
  userId: UserId;
  roleId: RoleId;
  orgId: OrgId | null;
  assignedAt?: Date;
  expiresAt?: Date;
}): UserRoleAssignment {
  const result = UserRoleAssignment.create({
    userId: params.userId,
    roleId: params.roleId,
    orgId: params.orgId,
    assignedBy: ADMIN,
    ...(params.assignedAt !== undefined ? { assignedAt: params.assignedAt } : {}),
    ...(params.expiresAt !== undefined ? { expiresAt: params.expiresAt } : {}),
  });
  if (!Result.isOk(result)) {
    throw new Error("contract test fixture setup failed");
  }
  return result.value;
}

/**
 * Behavioral contract every `UserRoleAssignmentRepository` implementation must satisfy.
 * Follows the Issue 031 contract-testing pattern.
 */
export function userRoleAssignmentRepositoryContract(
  createRepository: () => UserRoleAssignmentRepository,
): void {
  describe("UserRoleAssignmentRepository contract", () => {
    it("returns undefined for an assignment that was never saved", async () => {
      const repository = createRepository();
      const unsavedId = asId<"UserRoleAssignmentId">("00000000-0000-0000-0000-000000000001");

      await expect(repository.findById(unsavedId)).resolves.toBeUndefined();
    });

    it("finds a saved assignment by id", async () => {
      const repository = createRepository();
      const assignment = makeAssignment({
        userId: USER_1,
        roleId: ROLE_A,
        orgId: ORG_X,
      });

      await repository.save(assignment);

      const found = await repository.findById(assignment.id);
      expect(found).toBeDefined();
      expect(found?.id).toBe(assignment.id);
      expect(found?.userId).toBe(USER_1);
      expect(found?.roleId).toBe(ROLE_A);
      expect(found?.orgId).toBe(ORG_X);
      expect(found?.assignedBy).toBe(ADMIN);
    });

    it("findByUser returns all assignments for a user across multiple scopes", async () => {
      const repository = createRepository();
      const a1 = makeAssignment({ userId: USER_1, roleId: ROLE_A, orgId: ORG_X });
      const a2 = makeAssignment({ userId: USER_1, roleId: ROLE_B, orgId: ORG_Y });
      const a3 = makeAssignment({ userId: USER_1, roleId: ROLE_A, orgId: null }); // global
      const otherUser = makeAssignment({ userId: USER_2, roleId: ROLE_A, orgId: ORG_X });

      await repository.save(a1);
      await repository.save(a2);
      await repository.save(a3);
      await repository.save(otherUser);

      const results = await repository.findByUser(USER_1);
      expect(results).toHaveLength(3);
      const ids = results.map((r) => r.id);
      expect(ids).toContain(a1.id);
      expect(ids).toContain(a2.id);
      expect(ids).toContain(a3.id);
      expect(ids).not.toContain(otherUser.id);
    });

    it("findByUserAndOrg finds assignments scoped to a specific org", async () => {
      const repository = createRepository();
      const scopedX = makeAssignment({ userId: USER_1, roleId: ROLE_A, orgId: ORG_X });
      const scopedY = makeAssignment({ userId: USER_1, roleId: ROLE_A, orgId: ORG_Y });
      const global = makeAssignment({ userId: USER_1, roleId: ROLE_B, orgId: null });

      await repository.save(scopedX);
      await repository.save(scopedY);
      await repository.save(global);

      const results = await repository.findByUserAndOrg(USER_1, ORG_X);
      expect(results).toHaveLength(1);
      expect(results[0]?.id).toBe(scopedX.id);
    });

    it("findByUserAndOrg finds global assignments when orgId is null", async () => {
      const repository = createRepository();
      const scoped = makeAssignment({ userId: USER_1, roleId: ROLE_A, orgId: ORG_X });
      const global = makeAssignment({ userId: USER_1, roleId: ROLE_B, orgId: null });

      await repository.save(scoped);
      await repository.save(global);

      const results = await repository.findByUserAndOrg(USER_1, null);
      expect(results).toHaveLength(1);
      expect(results[0]?.id).toBe(global.id);
    });

    it("findByUserAndOrg excludes expired assignments by default (acceptance criteria)", async () => {
      const repository = createRepository();
      const pastAssigned = new Date("2026-01-01T00:00:00.000Z");
      const pastExpiry = new Date("2026-01-02T00:00:00.000Z");
      const referenceNow = new Date("2026-01-03T00:00:00.000Z");

      const active = makeAssignment({
        userId: USER_1,
        roleId: ROLE_A,
        orgId: ORG_X,
        assignedAt: pastAssigned,
      });

      const expired = makeAssignment({
        userId: USER_1,
        roleId: ROLE_B,
        orgId: ORG_X,
        assignedAt: pastAssigned,
        expiresAt: pastExpiry,
      });

      await repository.save(active);
      await repository.save(expired);

      // Default: expired assignments are excluded
      const results = await repository.findByUserAndOrg(USER_1, ORG_X, { now: referenceNow });
      expect(results).toHaveLength(1);
      expect(results[0]?.id).toBe(active.id);
    });

    it("findByUserAndOrg includes expired assignments when includeExpired is true (acceptance criteria)", async () => {
      const repository = createRepository();
      const pastAssigned = new Date("2026-01-01T00:00:00.000Z");
      const pastExpiry = new Date("2026-01-02T00:00:00.000Z");
      const referenceNow = new Date("2026-01-03T00:00:00.000Z");

      const active = makeAssignment({
        userId: USER_1,
        roleId: ROLE_A,
        orgId: ORG_X,
        assignedAt: pastAssigned,
      });

      const expired = makeAssignment({
        userId: USER_1,
        roleId: ROLE_B,
        orgId: ORG_X,
        assignedAt: pastAssigned,
        expiresAt: pastExpiry,
      });

      await repository.save(active);
      await repository.save(expired);

      // Explicit opt-in to include expired
      const results = await repository.findByUserAndOrg(USER_1, ORG_X, {
        includeExpired: true,
        now: referenceNow,
      });
      expect(results).toHaveLength(2);
      const ids = results.map((r) => r.id);
      expect(ids).toContain(active.id);
      expect(ids).toContain(expired.id);
    });

    it("findByUser excludes expired assignments by default and includes with option", async () => {
      const repository = createRepository();
      const pastAssigned = new Date("2026-01-01T00:00:00.000Z");
      const pastExpiry = new Date("2026-01-02T00:00:00.000Z");
      const referenceNow = new Date("2026-01-03T00:00:00.000Z");

      const active = makeAssignment({
        userId: USER_1,
        roleId: ROLE_A,
        orgId: null,
        assignedAt: pastAssigned,
      });

      const expired = makeAssignment({
        userId: USER_1,
        roleId: ROLE_B,
        orgId: ORG_X,
        assignedAt: pastAssigned,
        expiresAt: pastExpiry,
      });

      await repository.save(active);
      await repository.save(expired);

      const defaultResults = await repository.findByUser(USER_1, { now: referenceNow });
      expect(defaultResults).toHaveLength(1);
      expect(defaultResults[0]?.id).toBe(active.id);

      const allResults = await repository.findByUser(USER_1, {
        includeExpired: true,
        now: referenceNow,
      });
      expect(allResults).toHaveLength(2);
    });

    it("save is an idempotent upsert", async () => {
      const repository = createRepository();
      const assignment = makeAssignment({
        userId: USER_1,
        roleId: ROLE_A,
        orgId: ORG_X,
      });

      await repository.save(assignment);
      await repository.save(assignment);

      const results = await repository.findByUser(USER_1);
      expect(results).toHaveLength(1);
      expect(results[0]?.id).toBe(assignment.id);
    });

    it("revoke removes an existing assignment", async () => {
      const repository = createRepository();
      const assignment = makeAssignment({
        userId: USER_1,
        roleId: ROLE_A,
        orgId: ORG_X,
      });

      await repository.save(assignment);
      expect(await repository.findById(assignment.id)).toBeDefined();

      await repository.revoke(assignment.id);
      expect(await repository.findById(assignment.id)).toBeUndefined();

      const results = await repository.findByUser(USER_1);
      expect(results).toHaveLength(0);
    });

    it("revoke is an idempotent no-op for a non-existent assignment id", async () => {
      const repository = createRepository();
      const nonExistentId = asId<"UserRoleAssignmentId">("00000000-0000-0000-0000-000000000000");

      await expect(repository.revoke(nonExistentId)).resolves.toBeUndefined();
    });
  });
}
