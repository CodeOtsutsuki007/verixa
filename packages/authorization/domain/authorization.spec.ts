import { describe, expect, it } from "vitest";

import { AuthorizationError, Permission, Role } from "./authorization.js";

describe("authorization domain", () => {
  it("accepts permission keys and rejects malformed keys", () => {
    expect(new Permission("users:read", "Read users").key).toBe("users:read");
    expect(() => new Permission("users", "invalid")).toThrow(AuthorizationError);
  });

  it("matches exact, resource wildcard, and global wildcard permissions", () => {
    const role = new Role({
      id: "role",
      name: "viewer",
      description: "",
      isSystemRole: false,
      organizationId: null,
      permissions: ["users:*"],
    });
    expect(role.hasPermission("users:read")).toBe(true);
    expect(role.hasPermission("orgs:read")).toBe(false);
    expect(new Role({ ...role.record, permissions: ["*:*"] }).hasPermission("anything:write")).toBe(
      true,
    );
  });
});
