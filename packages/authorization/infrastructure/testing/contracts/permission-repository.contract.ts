import { ConflictError } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { PermissionRepository } from "../../../application/ports/permission-repository.js";
import { Permission } from "../../../domain/value-objects/permission.js";

/**
 * Behavioral contract every `PermissionRepository` implementation must satisfy.
 * Follows the Issue 031 contract-testing pattern.
 */
export function permissionRepositoryContract(createRepository: () => PermissionRepository): void {
  describe("PermissionRepository contract", () => {
    it("returns undefined for a permission that was never registered", async () => {
      const repository = createRepository();

      await expect(repository.findByKey("nonexistent:action")).resolves.toBeUndefined();
    });

    it("finds a registered permission by exact key", async () => {
      const repository = createRepository();
      const perm = Permission.from("users:read");

      await repository.save(perm);

      const found = await repository.findByKey("users:read");
      expect(found).toBeDefined();
      expect(found?.value).toBe("users:read");
      expect(found?.resource).toBe("users");
      expect(found?.action).toBe("read");
      expect(found?.key).toBe("users:read");
    });

    it("finds a registered permission using case-insensitive and trimmed key", async () => {
      const repository = createRepository();
      const perm = Permission.from("roles:write");

      await repository.save(perm);

      const found = await repository.findByKey("  ROLES:WRITE  ");
      expect(found).toBeDefined();
      expect(found?.value).toBe("roles:write");
    });

    it("rejects duplicate findByKey registration with ConflictError", async () => {
      const repository = createRepository();
      const perm1 = Permission.from("audit:export");
      const perm2 = Permission.from("  AUDIT:EXPORT  ");

      await repository.save(perm1);

      await expect(repository.save(perm2)).rejects.toThrow(ConflictError);

      // Verify catalog remains consistent with exactly 1 entry
      const all = await repository.findAll();
      expect(all).toHaveLength(1);
      expect(all[0]?.value).toBe("audit:export");
    });

    it("returns all registered permissions from findAll", async () => {
      const repository = createRepository();
      const p1 = Permission.from("users:read");
      const p2 = Permission.from("users:write");
      const p3 = Permission.from("orgs:*");

      await repository.save(p1);
      await repository.save(p2);
      await repository.save(p3);

      const all = await repository.findAll();
      expect(all).toHaveLength(3);
      const keys = all.map((p) => p.value);
      expect(keys).toContain("users:read");
      expect(keys).toContain("users:write");
      expect(keys).toContain("orgs:*");
    });

    it("returns an empty array from findAll when catalog is empty", async () => {
      const repository = createRepository();

      const all = await repository.findAll();
      expect(all).toEqual([]);
    });
  });
}
