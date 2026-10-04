import { asId, Result, ValidationError } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { SystemRoleImmutableError } from "../errors/system-role-immutable-error.js";
import { Permission } from "../value-objects/permission.js";

import { Role } from "./role.js";

function unwrap<T, E extends Error>(result: Result<T, E>): T {
  if (Result.isErr(result)) {
    throw result.error;
  }
  return result.value;
}

describe("Role aggregate", () => {
  describe("creation & reconstitution", () => {
    it("creates a standard role with valid parameters", () => {
      const result = Role.create({
        name: "accountant",
        description: "Access to invoices and financial ledgers",
        permissions: ["invoices:read", "invoices:write"],
      });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;

      const role = result.value;
      expect(role.name).toBe("accountant");
      expect(role.description).toBe("Access to invoices and financial ledgers");
      expect(role.isSystemRole).toBe(false);
      expect(role.orgId).toBeNull();
      expect(role.isGlobal()).toBe(true);
      expect(role.isScoped()).toBe(false);
      expect(role.permissions.size).toBe(2);
      expect(role.hasPermission("invoices:read")).toBe(true);
      expect(role.hasPermission("invoices:write")).toBe(true);
      expect(role.hasPermission("users:read")).toBe(false);
    });

    it("creates an organization-scoped role via createScoped", () => {
      const orgId = asId<"OrgId">("org_456");
      const result = Role.createScoped({
        name: "custom-reviewer",
        orgId,
        permissions: ["content:review"],
      });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;

      const role = result.value;
      expect(role.name).toBe("custom-reviewer");
      expect(role.orgId).toBe("org_456");
      expect(role.isGlobal()).toBe(false);
      expect(role.isScoped()).toBe(true);
    });

    it("creates a protected system role via createSystemRole", () => {
      const result = Role.createSystemRole({
        name: "super-admin",
        description: "Full break-glass system administration",
        permissions: ["users:*", "roles:*"],
      });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;

      const role = result.value;
      expect(role.name).toBe("super-admin");
      expect(role.isSystemRole).toBe(true);
      expect(role.orgId).toBeNull();
      expect(role.isGlobal()).toBe(true);
      expect(role.isScoped()).toBe(false);
      expect(role.hasPermission("users:delete")).toBe(true);
      expect(role.hasPermission("roles:manage")).toBe(true);
    });

    it("rejects creation with empty or whitespace name", () => {
      const emptyResult = Role.create({ name: "" });
      expect(Result.isErr(emptyResult)).toBe(true);
      if (!Result.isErr(emptyResult)) return;
      expect(emptyResult.error).toBeInstanceOf(ValidationError);

      const whitespaceResult = Role.create({ name: "   " });
      expect(Result.isErr(whitespaceResult)).toBe(true);
    });

    it("reconstitutes a role from trusted persistence data", () => {
      const now = new Date();
      const role = Role.reconstitute({
        // @ts-expect-error test branded id string
        id: "role_123",
        name: "moderator",
        description: "Content moderator",
        isSystemRole: false,
        permissions: new Set(["content:review", "content:delete"]),
        createdAt: now,
        updatedAt: now,
      });

      expect(role.id).toBe("role_123");
      expect(role.name).toBe("moderator");
      expect(role.isSystemRole).toBe(false);
      expect(role.permissions.has("content:review")).toBe(true);
    });
  });

  describe("standard role mutations", () => {
    it("grants and revokes permissions on standard roles", () => {
      const role = unwrap(Role.create({ name: "editor" }));

      expect(role.hasPermission("articles:write")).toBe(false);

      role.grant("articles:write");
      expect(role.hasPermission("articles:write")).toBe(true);

      const permObj = Permission.from("articles:publish");
      role.grant(permObj);
      expect(role.hasPermission(permObj)).toBe(true);
      expect(role.permissions.size).toBe(2);

      role.revoke("articles:write");
      expect(role.hasPermission("articles:write")).toBe(false);
      expect(role.permissions.size).toBe(1);

      role.revoke(permObj);
      expect(role.hasPermission(permObj)).toBe(false);
      expect(role.permissions.size).toBe(0);
    });

    it("renames standard roles successfully", () => {
      const role = unwrap(Role.create({ name: "viewer" }));
      role.rename("auditor");
      expect(role.name).toBe("auditor");
    });

    it("rejects renaming standard role to empty string", () => {
      const role = unwrap(Role.create({ name: "viewer" }));
      expect(() => role.rename("")).toThrow(ValidationError);
      expect(() => role.rename("   ")).toThrow(ValidationError);
    });

    it("updates description on standard roles", () => {
      const role = unwrap(Role.create({ name: "viewer" }));
      role.updateDescription("Updated read-only access description");
      expect(role.description).toBe("Updated read-only access description");
    });

    it("protects internal permissions set against direct mutation", () => {
      const role = unwrap(
        Role.create({
          name: "viewer",
          permissions: ["users:read"],
        }),
      );

      const exposed = role.permissions as Set<string>;
      exposed.add("hack:evil");

      expect(role.hasPermission("hack:evil")).toBe(false);
      expect(role.permissions.has("hack:evil")).toBe(false);
    });
  });

  describe("system-role protection invariants (Issue 123)", () => {
    it("throws SystemRoleImmutableError when revoking any permission from a system role", () => {
      const role = unwrap(
        Role.createSystemRole({
          name: "super-admin",
          permissions: ["users:*", "roles:*", "system:breakglass"],
        }),
      );

      expect(() => role.revoke("users:*")).toThrow(SystemRoleImmutableError);
      expect(() => role.revoke(Permission.from("roles:*"))).toThrow(SystemRoleImmutableError);

      // Verify the invariant: permissions must remain intact
      expect(role.hasPermission("users:*")).toBe(true);
      expect(role.hasPermission("roles:*")).toBe(true);
    });

    it("produces a structured SystemRoleImmutableError with status 403 and attemptedAction", () => {
      const role = unwrap(
        Role.createSystemRole({
          name: "super-admin",
          permissions: ["system:recover"],
        }),
      );

      let caughtError: unknown;
      try {
        role.revoke("system:recover");
      } catch (err) {
        caughtError = err;
      }

      expect(caughtError).toBeInstanceOf(SystemRoleImmutableError);
      const err = caughtError as SystemRoleImmutableError;
      expect(err.code).toBe("SYSTEM_ROLE_IMMUTABLE");
      expect(err.httpStatusHint).toBe(403);
      expect(err.roleName).toBe("super-admin");
      expect(err.attemptedAction).toBe("revoke");
      expect(err.message).toContain('Cannot revoke permissions from system role "super-admin"');
      expect(err.toJSON().attemptedAction).toBe("revoke");
    });

    it("throws SystemRoleImmutableError when attempting to rename a system role", () => {
      const role = unwrap(
        Role.createSystemRole({
          name: "super-admin",
        }),
      );

      expect(() => role.rename("regular-admin")).toThrow(SystemRoleImmutableError);

      let caughtError: unknown;
      try {
        role.rename("something-else");
      } catch (err) {
        caughtError = err;
      }

      expect(caughtError).toBeInstanceOf(SystemRoleImmutableError);
      const err = caughtError as SystemRoleImmutableError;
      expect(err.code).toBe("SYSTEM_ROLE_IMMUTABLE");
      expect(err.httpStatusHint).toBe(403);
      expect(err.attemptedAction).toBe("rename");
      expect(err.message).toContain('Cannot rename system role "super-admin"');
      expect(role.name).toBe("super-admin");
    });

    it("allows granting additional permissions to a system role", () => {
      const role = unwrap(
        Role.createSystemRole({
          name: "super-admin",
          permissions: ["users:*"],
        }),
      );

      expect(role.hasPermission("billing:manage")).toBe(false);

      // Granting additional permissions is explicitly allowed on system roles
      role.grant("billing:manage");
      expect(role.hasPermission("billing:manage")).toBe(true);
    });

    it("allows updating description on a system role", () => {
      const role = unwrap(
        Role.createSystemRole({
          name: "super-admin",
          description: "Initial description",
        }),
      );

      role.updateDescription("Updated system role description");
      expect(role.description).toBe("Updated system role description");
      expect(role.updatedAt).toBeInstanceOf(Date);
    });

    it("supports delete attemptedAction in SystemRoleImmutableError", () => {
      const err = new SystemRoleImmutableError("role_1", "super-admin", "delete");
      expect(err.attemptedAction).toBe("delete");
      expect(err.message).toContain("Cannot delete system role");
    });
  });
});
