import { asId, Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { RoleRepository } from "../../../application/ports/role-repository.js";
import { type OrgId, Role } from "../../../domain/entities/role.js";
import { SystemRoleImmutableError } from "../../../domain/errors/system-role-immutable-error.js";

function makeRole(name: string, orgId?: OrgId | null): Role {
  const result = Role.create({
    name,
    description: `Description for ${name}`,
    orgId: orgId ?? null,
    permissions: ["items:read"],
  });
  if (!Result.isOk(result)) {
    throw new Error("contract test fixture setup failed");
  }
  return result.value;
}

function makeSystemRole(name: string): Role {
  const result = Role.createSystemRole({
    name,
    description: `System role for ${name}`,
    permissions: ["system:*"],
  });
  if (!Result.isOk(result)) {
    throw new Error("contract test fixture setup failed");
  }
  return result.value;
}

/**
 * Behavioral contract every `RoleRepository` implementation must satisfy.
 * Run against `InMemoryRoleRepository` and future database adapters.
 * Following the Issue 031 contract-test pattern.
 */
export function roleRepositoryContract(createRepository: () => RoleRepository): void {
  describe("RoleRepository contract", () => {
    it("returns undefined for a role that was never saved", async () => {
      const repository = createRepository();
      const unsavedId = asId<"RoleId">("00000000-0000-0000-0000-000000000001");

      await expect(repository.findById(unsavedId)).resolves.toBeUndefined();
    });

    it("finds a saved role by id", async () => {
      const repository = createRepository();
      const role = makeRole("analyst");

      await repository.save(role);

      const found = await repository.findById(role.id);
      expect(found).toBeDefined();
      expect(found?.id).toBe(role.id);
      expect(found?.name).toBe("analyst");
      expect(found?.description).toBe(role.description);
      expect(found?.isSystemRole).toBe(false);
      expect(found?.permissions.has("items:read")).toBe(true);
    });

    it("finds a saved global role by name", async () => {
      const repository = createRepository();
      const role = makeRole("global-viewer", null);

      await repository.save(role);

      const found = await repository.findByName("global-viewer");
      expect(found).toBeDefined();
      expect(found?.id).toBe(role.id);
      expect(found?.name).toBe("global-viewer");
      expect(found?.orgId).toBeNull();
    });

    it("finds a saved organization-scoped role by name and orgId", async () => {
      const repository = createRepository();
      const orgId = asId<"OrgId">("11111111-1111-1111-1111-111111111111");
      const role = makeRole("billing-manager", orgId);

      await repository.save(role);

      const found = await repository.findByName("billing-manager", orgId);
      expect(found).toBeDefined();
      expect(found?.id).toBe(role.id);
      expect(found?.orgId).toBe(orgId);
    });

    it("distinguishes same role name in different organizations", async () => {
      const repository = createRepository();
      const org1 = asId<"OrgId">("11111111-1111-1111-1111-111111111111");
      const org2 = asId<"OrgId">("22222222-2222-2222-2222-222222222222");

      const role1 = makeRole("editor", org1);
      const role2 = makeRole("editor", org2);

      await repository.save(role1);
      await repository.save(role2);

      const found1 = await repository.findByName("editor", org1);
      const found2 = await repository.findByName("editor", org2);

      expect(found1?.id).toBe(role1.id);
      expect(found2?.id).toBe(role2.id);
      expect(found1?.id).not.toBe(found2?.id);
    });

    it("findByName returns undefined when role exists in another org but not the queried org", async () => {
      const repository = createRepository();
      const org1 = asId<"OrgId">("11111111-1111-1111-1111-111111111111");
      const org2 = asId<"OrgId">("22222222-2222-2222-2222-222222222222");

      const role = makeRole("reviewer", org1);
      await repository.save(role);

      await expect(repository.findByName("reviewer", org2)).resolves.toBeUndefined();
    });

    it("findByName returns undefined when querying global scope for an org-scoped role", async () => {
      const repository = createRepository();
      const org = asId<"OrgId">("11111111-1111-1111-1111-111111111111");
      const role = makeRole("scoped-only", org);

      await repository.save(role);

      await expect(repository.findByName("scoped-only")).resolves.toBeUndefined();
      await expect(repository.findByName("scoped-only", null)).resolves.toBeUndefined();
    });

    it("findAllForOrg returns all roles belonging to that organization", async () => {
      const repository = createRepository();
      const targetOrg = asId<"OrgId">("11111111-1111-1111-1111-111111111111");
      const otherOrg = asId<"OrgId">("22222222-2222-2222-2222-222222222222");

      const role1 = makeRole("org1-admin", targetOrg);
      const role2 = makeRole("org1-member", targetOrg);
      const otherRole = makeRole("other-role", otherOrg);
      const globalRole = makeRole("global-role", null);

      await repository.save(role1);
      await repository.save(role2);
      await repository.save(otherRole);
      await repository.save(globalRole);

      const orgRoles = await repository.findAllForOrg(targetOrg);
      expect(orgRoles).toHaveLength(2);
      const roleIds = orgRoles.map((r) => r.id);
      expect(roleIds).toContain(role1.id);
      expect(roleIds).toContain(role2.id);
      expect(roleIds).not.toContain(otherRole.id);
      expect(roleIds).not.toContain(globalRole.id);
    });

    it("findAllForOrg returns an empty array when organization has no roles", async () => {
      const repository = createRepository();
      const emptyOrg = asId<"OrgId">("99999999-9999-9999-9999-999999999999");

      const result = await repository.findAllForOrg(emptyOrg);
      expect(result).toEqual([]);
    });

    it("save is an idempotent upsert", async () => {
      const repository = createRepository();
      const role = makeRole("operator");

      await repository.save(role);

      // Mutate the aggregate
      role.grant("items:create");
      role.updateDescription("Updated operator description");
      await repository.save(role);

      const found = await repository.findById(role.id);
      expect(found).toBeDefined();
      expect(found?.description).toBe("Updated operator description");
      expect(found?.hasPermission("items:create")).toBe(true);
      expect(found?.permissions.size).toBe(2);
    });

    it("deletes an existing custom role", async () => {
      const repository = createRepository();
      const role = makeRole("temporary-guest");

      await repository.save(role);
      expect(await repository.findById(role.id)).toBeDefined();

      await repository.delete(role.id);
      expect(await repository.findById(role.id)).toBeUndefined();
    });

    it("delete is an idempotent no-op for a non-existent role id", async () => {
      const repository = createRepository();
      const nonExistentId = asId<"RoleId">("00000000-0000-0000-0000-000000000000");

      await expect(repository.delete(nonExistentId)).resolves.toBeUndefined();
    });

    it("throws SystemRoleImmutableError when attempting to delete a system role", async () => {
      const repository = createRepository();
      const systemRole = makeSystemRole("super-admin");

      await repository.save(systemRole);

      await expect(repository.delete(systemRole.id)).rejects.toThrow(SystemRoleImmutableError);

      // Verify invariant: system role must still exist in persistence after rejection
      const stillThere = await repository.findById(systemRole.id);
      expect(stillThere).toBeDefined();
      expect(stillThere?.id).toBe(systemRole.id);
    });
  });
}
