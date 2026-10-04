import { asId, Result } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { Role } from "../../domain/entities/role.js";
import { UserRoleAssignment } from "../../domain/entities/user-role-assignment.js";
import { Permission } from "../../domain/value-objects/permission.js";
import { InMemoryRoleRepository } from "../../infrastructure/fakes/in-memory-role-repository.js";
import { InMemoryUserRoleAssignmentRepository } from "../../infrastructure/fakes/in-memory-user-role-assignment-repository.js";

import { PermissionChecker } from "./permission-checker.js";

describe("PermissionChecker", () => {
  let roleRepo: InMemoryRoleRepository;
  let assignmentRepo: InMemoryUserRoleAssignmentRepository;
  let checker: PermissionChecker;

  const adminUser = asId<"UserId">("user_admin");
  const regularUser = asId<"UserId">("user_regular");
  const unassignedUser = asId<"UserId">("user_unassigned");

  const orgAlpha = asId<"OrgId">("org_alpha");
  const orgBeta = asId<"OrgId">("org_beta");

  let readerRole: Role;
  let writerRole: Role;
  let superAdminRole: Role;

  beforeEach(async () => {
    roleRepo = new InMemoryRoleRepository();
    assignmentRepo = new InMemoryUserRoleAssignmentRepository();
    checker = new PermissionChecker(assignmentRepo, roleRepo);

    // Create test roles
    const readerRes = Role.create({
      name: "reader",
      orgId: orgAlpha,
      permissions: ["documents:read", "comments:read"],
    });
    if (Result.isOk(readerRes)) {
      readerRole = readerRes.value;
      await roleRepo.save(readerRole);
    }

    const writerRes = Role.create({
      name: "writer",
      orgId: orgAlpha,
      permissions: ["documents:write", "comments:write"],
    });
    if (Result.isOk(writerRes)) {
      writerRole = writerRes.value;
      await roleRepo.save(writerRole);
    }

    const superAdminRes = Role.create({
      name: "super-admin",
      isSystemRole: true,
      permissions: ["admin:*", "admin:access"],
    });
    if (Result.isOk(superAdminRes)) {
      superAdminRole = superAdminRes.value;
      await roleRepo.save(superAdminRole);
    }
  });

  describe("deny-by-default & unassigned users", () => {
    it("returns false for any permission check when user has no role assignments", async () => {
      const hasRead = await checker.hasPermission(unassignedUser, orgAlpha, "documents:read");
      const hasAny = await checker.hasAnyPermission(unassignedUser, orgAlpha, [
        "documents:read",
        "comments:read",
      ]);
      const hasAll = await checker.hasAllPermissions(unassignedUser, orgAlpha, ["documents:read"]);
      const effective = await checker.resolveEffectivePermissions(unassignedUser, orgAlpha);

      expect(hasRead).toBe(false);
      expect(hasAny).toBe(false);
      expect(hasAll).toBe(false);
      expect(effective.size).toBe(0);
    });

    it("evaluates hasAllPermissions as true when empty permissions iterable is passed", async () => {
      const hasAllEmpty = await checker.hasAllPermissions(unassignedUser, orgAlpha, []);
      expect(hasAllEmpty).toBe(true);
    });

    it("evaluates hasAnyPermission as false when empty permissions iterable is passed", async () => {
      const hasAnyEmpty = await checker.hasAnyPermission(unassignedUser, orgAlpha, []);
      expect(hasAnyEmpty).toBe(false);
    });
  });

  describe("single-role permission checks", () => {
    beforeEach(async () => {
      const assignmentRes = UserRoleAssignment.create({
        userId: regularUser,
        roleId: readerRole.id,
        orgId: orgAlpha,
        assignedBy: adminUser,
      });
      if (Result.isOk(assignmentRes)) {
        await assignmentRepo.save(assignmentRes.value);
      }
    });

    it("returns true for permissions granted by the assigned role", async () => {
      expect(await checker.hasPermission(regularUser, orgAlpha, "documents:read")).toBe(true);
      expect(
        await checker.hasPermission(regularUser, orgAlpha, Permission.from("comments:read")),
      ).toBe(true);
    });

    it("returns false for permissions not granted by the role", async () => {
      expect(await checker.hasPermission(regularUser, orgAlpha, "documents:write")).toBe(false);
      expect(await checker.hasPermission(regularUser, orgAlpha, "users:delete")).toBe(false);
    });

    it("correctly evaluates hasAnyPermission", async () => {
      expect(
        await checker.hasAnyPermission(regularUser, orgAlpha, [
          "documents:write",
          "documents:read",
        ]),
      ).toBe(true);
      expect(
        await checker.hasAnyPermission(regularUser, orgAlpha, ["documents:write", "users:delete"]),
      ).toBe(false);
    });

    it("correctly evaluates hasAllPermissions", async () => {
      expect(
        await checker.hasAllPermissions(regularUser, orgAlpha, ["documents:read", "comments:read"]),
      ).toBe(true);
      expect(
        await checker.hasAllPermissions(regularUser, orgAlpha, [
          "documents:read",
          "documents:write",
        ]),
      ).toBe(false);
    });
  });

  describe("multi-role union & overlapping permissions", () => {
    beforeEach(async () => {
      // Assign both reader and writer roles in orgAlpha
      const assignReader = UserRoleAssignment.create({
        userId: regularUser,
        roleId: readerRole.id,
        orgId: orgAlpha,
        assignedBy: adminUser,
      });
      const assignWriter = UserRoleAssignment.create({
        userId: regularUser,
        roleId: writerRole.id,
        orgId: orgAlpha,
        assignedBy: adminUser,
      });

      if (Result.isOk(assignReader) && Result.isOk(assignWriter)) {
        await assignmentRepo.save(assignReader.value);
        await assignmentRepo.save(assignWriter.value);
      }
    });

    it("unions permissions across all active assigned roles", async () => {
      const effective = await checker.resolveEffectivePermissions(regularUser, orgAlpha);
      expect(effective.size).toBe(4);

      expect(await checker.hasPermission(regularUser, orgAlpha, "documents:read")).toBe(true);
      expect(await checker.hasPermission(regularUser, orgAlpha, "documents:write")).toBe(true);
      expect(await checker.hasPermission(regularUser, orgAlpha, "comments:read")).toBe(true);
      expect(await checker.hasPermission(regularUser, orgAlpha, "comments:write")).toBe(true);

      expect(
        await checker.hasAllPermissions(regularUser, orgAlpha, [
          "documents:read",
          "documents:write",
          "comments:read",
          "comments:write",
        ]),
      ).toBe(true);
    });
  });

  describe("temporal evaluation & expired assignment exclusion", () => {
    it("excludes expired role assignments from permission resolution", async () => {
      const baseTime = new Date("2026-09-27T10:00:00Z");
      const expiredTime = new Date("2026-09-27T11:00:00Z");
      const evalTime = new Date("2026-09-27T12:00:00Z");

      const timedAssignment = UserRoleAssignment.create({
        userId: regularUser,
        roleId: writerRole.id,
        orgId: orgAlpha,
        assignedBy: adminUser,
        assignedAt: baseTime,
        expiresAt: expiredTime,
      });

      expect(Result.isOk(timedAssignment)).toBe(true);
      if (Result.isOk(timedAssignment)) {
        await assignmentRepo.save(timedAssignment.value);
      }

      // At 10:30 (before expiry), permission should be active
      const beforeExpiry = new Date("2026-09-27T10:30:00Z");
      expect(
        await checker.hasPermission(regularUser, orgAlpha, "documents:write", {
          now: beforeExpiry,
        }),
      ).toBe(true);

      // At 12:00 (after expiry), permission should be denied
      expect(
        await checker.hasPermission(regularUser, orgAlpha, "documents:write", {
          now: evalTime,
        }),
      ).toBe(false);

      const effectiveAfter = await checker.resolveEffectivePermissions(regularUser, orgAlpha, {
        now: evalTime,
      });
      expect(effectiveAfter.size).toBe(0);
    });
  });

  describe("multi-tenant scoping & global roles", () => {
    it("does not grant permissions in Org Beta for a role scoped to Org Alpha", async () => {
      const assignReader = UserRoleAssignment.create({
        userId: regularUser,
        roleId: readerRole.id,
        orgId: orgAlpha,
        assignedBy: adminUser,
      });
      if (Result.isOk(assignReader)) {
        await assignmentRepo.save(assignReader.value);
      }

      expect(await checker.hasPermission(regularUser, orgAlpha, "documents:read")).toBe(true);
      expect(await checker.hasPermission(regularUser, orgBeta, "documents:read")).toBe(false);
    });

    it("grants permissions globally across all organizations when assigned a global role", async () => {
      const assignGlobal = UserRoleAssignment.create({
        userId: adminUser,
        roleId: superAdminRole.id,
        orgId: null,
        assignedBy: adminUser,
      });
      if (Result.isOk(assignGlobal)) {
        await assignmentRepo.save(assignGlobal.value);
      }

      // Check global scope
      expect(await checker.hasPermission(adminUser, null, "admin:access")).toBe(true);
      // Check orgAlpha scope
      expect(await checker.hasPermission(adminUser, orgAlpha, "admin:access")).toBe(true);
      // Check orgBeta scope
      expect(await checker.hasPermission(adminUser, orgBeta, "admin:access")).toBe(true);
      // Wildcard match on action: admin:* matches admin:delete
      expect(await checker.hasPermission(adminUser, orgAlpha, "admin:delete")).toBe(true);
    });
  });
});
