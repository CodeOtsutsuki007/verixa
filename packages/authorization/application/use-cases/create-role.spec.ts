import { asId, Result } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { Permission } from "../../domain/value-objects/permission.js";
import { InMemoryRoleRepository } from "../../infrastructure/fakes/in-memory-role-repository.js";

import { CreateRole } from "./create-role.js";

describe("CreateRole", () => {
  let roleRepository: InMemoryRoleRepository;
  let createRole: CreateRole;

  beforeEach(() => {
    roleRepository = new InMemoryRoleRepository();
    createRole = new CreateRole(roleRepository);
  });

  it("creates a global role successfully and persists it", async () => {
    const result = await createRole.execute({
      name: "billing-manager",
      description: "Manages subscriptions and invoices",
      permissions: ["billing:read", "billing:write"],
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isOk(result)) {
      expect(result.value.name).toBe("billing-manager");
      expect(result.value.description).toBe("Manages subscriptions and invoices");
      expect(result.value.isGlobal()).toBe(true);
      expect(result.value.hasPermission("billing:read")).toBe(true);
      expect(result.value.hasPermission("billing:write")).toBe(true);

      const persisted = await roleRepository.findById(result.value.id);
      expect(persisted).toBeDefined();
      expect(persisted?.id).toBe(result.value.id);
    }
  });

  it("creates an organization-scoped role successfully", async () => {
    const orgId = asId<"OrgId">("org_123");
    const result = await createRole.execute({
      name: "viewer",
      orgId,
      permissions: [Permission.from("docs:read")],
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isOk(result)) {
      expect(result.value.name).toBe("viewer");
      expect(result.value.orgId).toBe(orgId);
      expect(result.value.isScoped()).toBe(true);
      expect(result.value.hasPermission("docs:read")).toBe(true);

      const persisted = await roleRepository.findByName("viewer", orgId);
      expect(persisted?.id).toBe(result.value.id);
    }
  });

  it("allows identical role names across different organizations", async () => {
    const org1 = asId<"OrgId">("org_1");
    const org2 = asId<"OrgId">("org_2");

    const res1 = await createRole.execute({ name: "editor", orgId: org1 });
    const res2 = await createRole.execute({ name: "editor", orgId: org2 });

    expect(Result.isOk(res1)).toBe(true);
    expect(Result.isOk(res2)).toBe(true);
  });

  it("rejects duplicate role name in the same organization", async () => {
    const orgId = asId<"OrgId">("org_abc");

    const first = await createRole.execute({ name: "admin", orgId });
    expect(Result.isOk(first)).toBe(true);

    const duplicate = await createRole.execute({ name: "admin", orgId });
    expect(Result.isErr(duplicate)).toBe(true);
    if (Result.isErr(duplicate)) {
      expect(duplicate.error.code).toBe("CONFLICT");
      expect(duplicate.error.message).toContain("already exists in organization");
    }
  });

  it("rejects duplicate global role name", async () => {
    const first = await createRole.execute({ name: "global-auditor" });
    expect(Result.isOk(first)).toBe(true);

    const duplicate = await createRole.execute({ name: "global-auditor" });
    expect(Result.isErr(duplicate)).toBe(true);
    if (Result.isErr(duplicate)) {
      expect(duplicate.error.code).toBe("CONFLICT");
      expect(duplicate.error.message).toContain("already exists globally");
    }
  });

  it("rejects creating a non-system role with the global wildcard *:*", async () => {
    const result = await createRole.execute({
      name: "super-user",
      permissions: ["*:*"],
      isSystemRole: false,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.code).toBe("VALIDATION_ERROR");
      expect(result.error.message).toContain("Global wildcard");
    }
  });

  it("allows creating a system role with the global wildcard *:*", async () => {
    const result = await createRole.execute({
      name: "super-admin",
      permissions: ["*:*"],
      isSystemRole: true,
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isOk(result)) {
      expect(result.value.isSystemRole).toBe(true);
      expect(result.value.hasPermission("*:*")).toBe(true);
    }
  });

  it("rejects invalid role parameters without writing to repository", async () => {
    const result = await createRole.execute({ name: "" });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.code).toBe("VALIDATION_ERROR");
    }
  });
});
