import { Result } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { InMemoryPermissionRepository } from "../../infrastructure/fakes/in-memory-permission-repository.js";

import { DefinePermission } from "./define-permission.js";

describe("DefinePermission", () => {
  let permissionRepository: InMemoryPermissionRepository;
  let definePermission: DefinePermission;

  beforeEach(() => {
    permissionRepository = new InMemoryPermissionRepository();
    definePermission = new DefinePermission(permissionRepository);
  });

  it("registers a valid permission and persists it in the catalog", async () => {
    const result = await definePermission.execute({ key: "users:read" });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isOk(result)) {
      expect(result.value.key).toBe("users:read");
      expect(result.value.resource).toBe("users");
      expect(result.value.action).toBe("read");

      const persisted = await permissionRepository.findByKey("users:read");
      expect(persisted).toBeDefined();
      expect(persisted?.key).toBe("users:read");
    }
  });

  it("is idempotent when registering duplicate permission keys", async () => {
    const first = await definePermission.execute({ key: "roles:write" });
    expect(Result.isOk(first)).toBe(true);

    const duplicate = await definePermission.execute({ key: "roles:write" });
    expect(Result.isOk(duplicate)).toBe(true);

    if (Result.isOk(duplicate)) {
      expect(duplicate.value.key).toBe("roles:write");
    }

    const all = await permissionRepository.findAll();
    expect(all).toHaveLength(1);
  });

  it("handles case-insensitive duplicate registrations idempotently", async () => {
    const first = await definePermission.execute({ key: "audit:EXPORT" });
    expect(Result.isOk(first)).toBe(true);

    const duplicate = await definePermission.execute({ key: "AUDIT:export" });
    expect(Result.isOk(duplicate)).toBe(true);

    const all = await permissionRepository.findAll();
    expect(all).toHaveLength(1);
    expect(all[0]?.key).toBe("audit:export");
  });

  it("rejects an invalid permission key format without writing to catalog", async () => {
    const result = await definePermission.execute({ key: "invalid-key-no-colon" });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.code).toBe("VALIDATION_ERROR");
    }

    const all = await permissionRepository.findAll();
    expect(all).toHaveLength(0);
  });

  it("rejects an empty permission key string", async () => {
    const result = await definePermission.execute({ key: "   " });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.code).toBe("VALIDATION_ERROR");
    }
  });
});
