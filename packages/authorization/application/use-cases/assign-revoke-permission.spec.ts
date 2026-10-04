import { asId, Result } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { Role } from "../../domain/entities/role.js";
import { Permission } from "../../domain/value-objects/permission.js";
import { InMemoryPermissionRepository } from "../../infrastructure/fakes/in-memory-permission-repository.js";
import { InMemoryRoleRepository } from "../../infrastructure/fakes/in-memory-role-repository.js";

import { AssignPermissionToRole } from "./assign-permission-to-role.js";
import { RevokePermissionFromRole } from "./revoke-permission-from-role.js";

describe("AssignPermissionToRole & RevokePermissionFromRole", () => {
  let roleRepository: InMemoryRoleRepository;
  let permissionRepository: InMemoryPermissionRepository;
  let assignPermission: AssignPermissionToRole;
  let revokePermission: RevokePermissionFromRole;

  beforeEach(async () => {
    roleRepository = new InMemoryRoleRepository();
    permissionRepository = new InMemoryPermissionRepository();

    await permissionRepository.save(Permission.from("users:read"));
    await permissionRepository.save(Permission.from("users:write"));
    await permissionRepository.save(Permission.from("billing:read"));

    assignPermission = new AssignPermissionToRole(roleRepository, permissionRepository);
    revokePermission = new RevokePermissionFromRole(roleRepository);
  });

  describe("AssignPermissionToRole", () => {
    it("grants a registered catalog permission to an existing role", async () => {
      const roleResult = Role.create({ name: "viewer" });
      if (!Result.isOk(roleResult)) throw new Error("setup failed");
      const role = roleResult.value;
      await roleRepository.save(role);

      const result = await assignPermission.execute({
        roleId: role.id,
        permission: "users:read",
      });

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.hasPermission("users:read")).toBe(true);
      }

      const updated = await roleRepository.findById(role.id);
      expect(updated?.hasPermission("users:read")).toBe(true);
    });

    it("rejects an unregistered permission not present in the catalog", async () => {
      const roleResult = Role.create({ name: "viewer" });
      if (!Result.isOk(roleResult)) throw new Error("setup failed");
      const role = roleResult.value;
      await roleRepository.save(role);

      const result = await assignPermission.execute({
        roleId: role.id,
        permission: "secret:hack",
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.code).toBe("VALIDATION_ERROR");
        expect(result.error.message).toContain("not registered in the system catalog");
      }
    });

    it("rejects when the role does not exist", async () => {
      const nonExistentId = asId<"RoleId">("role_missing");
      const result = await assignPermission.execute({
        roleId: nonExistentId,
        permission: "users:read",
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.code).toBe("NOT_FOUND");
      }
    });

    it("rejects granting the global wildcard *:* to a non-system role", async () => {
      await permissionRepository.save(Permission.from("*:*"));
      const roleResult = Role.create({ name: "regular-manager" });
      if (!Result.isOk(roleResult)) throw new Error("setup failed");
      const role = roleResult.value;
      await roleRepository.save(role);

      const result = await assignPermission.execute({
        roleId: role.id,
        permission: "*:*",
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.code).toBe("VALIDATION_ERROR");
        expect(result.error.message).toContain("Global wildcard");
      }
    });

    it("allows granting the global wildcard *:* to a system role", async () => {
      await permissionRepository.save(Permission.from("*:*"));
      const sysRoleResult = Role.createSystemRole({ name: "super-admin" });
      if (!Result.isOk(sysRoleResult)) throw new Error("setup failed");
      const sysRole = sysRoleResult.value;
      await roleRepository.save(sysRole);

      const result = await assignPermission.execute({
        roleId: sysRole.id,
        permission: "*:*",
      });

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.hasPermission("*:*")).toBe(true);
      }
    });

    it("rejects an invalid permission format", async () => {
      const roleResult = Role.create({ name: "viewer" });
      if (!Result.isOk(roleResult)) throw new Error("setup failed");
      const role = roleResult.value;
      await roleRepository.save(role);

      const result = await assignPermission.execute({
        roleId: role.id,
        permission: "invalidpermissionformat",
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.code).toBe("VALIDATION_ERROR");
      }
    });
  });

  describe("RevokePermissionFromRole", () => {
    it("revokes an existing permission from a non-system role", async () => {
      const roleResult = Role.create({
        name: "editor",
        permissions: ["users:read", "users:write"],
      });
      if (!Result.isOk(roleResult)) throw new Error("setup failed");
      const role = roleResult.value;
      await roleRepository.save(role);

      const result = await revokePermission.execute({
        roleId: role.id,
        permission: "users:write",
      });

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.hasPermission("users:write")).toBe(false);
        expect(result.value.hasPermission("users:read")).toBe(true);
      }

      const updated = await roleRepository.findById(role.id);
      expect(updated?.hasPermission("users:write")).toBe(false);
    });

    it("rejects revoking permissions from a protected system role", async () => {
      const roleResult = Role.createSystemRole({
        name: "super-admin",
        permissions: ["users:read"],
      });
      if (!Result.isOk(roleResult)) throw new Error("setup failed");
      const role = roleResult.value;
      await roleRepository.save(role);

      const result = await revokePermission.execute({
        roleId: role.id,
        permission: "users:read",
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.code).toBe("SYSTEM_ROLE_IMMUTABLE");
        expect(result.error.httpStatusHint).toBe(403);
      }
    });

    it("rejects when the role does not exist", async () => {
      const nonExistentId = asId<"RoleId">("role_missing");
      const result = await revokePermission.execute({
        roleId: nonExistentId,
        permission: "users:read",
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.code).toBe("NOT_FOUND");
      }
    });
  });
});
