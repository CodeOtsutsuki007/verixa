import { describe, expect, it } from "vitest";

import { Permission } from "../value-objects/permission.js";

import { PermissionMatcher } from "./permission-matcher.js";

describe("PermissionMatcher", () => {
  describe("exact matching", () => {
    it("matches identical permission strings and objects", () => {
      expect(PermissionMatcher.matches("users:read", "users:read")).toBe(true);
      expect(PermissionMatcher.matches("audit:export", "audit:export")).toBe(true);

      const p1 = Permission.from("roles:write");
      const p2 = Permission.from("roles:write");
      expect(PermissionMatcher.matches(p1, p2)).toBe(true);
    });

    it("does not match different resources or actions without wildcards", () => {
      expect(PermissionMatcher.matches("users:read", "users:write")).toBe(false);
      expect(PermissionMatcher.matches("users:read", "orgs:read")).toBe(false);
      expect(PermissionMatcher.matches("audit:export", "audit:import")).toBe(false);
    });
  });

  describe("action wildcard matching (resource:*)", () => {
    it("matches any action within the same resource", () => {
      expect(PermissionMatcher.matches("users:*", "users:read")).toBe(true);
      expect(PermissionMatcher.matches("users:*", "users:write")).toBe(true);
      expect(PermissionMatcher.matches("users:*", "users:delete")).toBe(true);
      expect(PermissionMatcher.matches("users:*", "users:custom_action")).toBe(true);
    });

    it("does not match different resources", () => {
      expect(PermissionMatcher.matches("users:*", "orgs:read")).toBe(false);
      expect(PermissionMatcher.matches("users:*", "user_profile:read")).toBe(false);
      expect(PermissionMatcher.matches("documents:*", "folders:list")).toBe(false);
    });

    it("is directional: specific grant does not satisfy wildcard requirement", () => {
      expect(PermissionMatcher.matches("users:read", "users:*")).toBe(false);
    });
  });

  describe("resource wildcard matching (*:action)", () => {
    it("matches the same action across different resources", () => {
      expect(PermissionMatcher.matches("*:read", "users:read")).toBe(true);
      expect(PermissionMatcher.matches("*:read", "orgs:read")).toBe(true);
      expect(PermissionMatcher.matches("*:read", "audit:read")).toBe(true);
    });

    it("does not match different actions", () => {
      expect(PermissionMatcher.matches("*:read", "users:write")).toBe(false);
      expect(PermissionMatcher.matches("*:read", "orgs:delete")).toBe(false);
    });
  });

  describe("global wildcard matching (*:*)", () => {
    it("matches any permission across any resource and action", () => {
      expect(PermissionMatcher.matches("*:*", "users:read")).toBe(true);
      expect(PermissionMatcher.matches("*:*", "orgs:delete")).toBe(true);
      expect(PermissionMatcher.matches("*:*", "billing:invoices:export")).toBe(false); // malformed/invalid
      expect(PermissionMatcher.matches("*:*", "system:reboot")).toBe(true);
      expect(PermissionMatcher.matches("*:*", "*:*")).toBe(true);
    });

    it("correctly identifies global wildcard permissions", () => {
      expect(PermissionMatcher.isGlobalWildcard("*:*")).toBe(true);
      expect(PermissionMatcher.isGlobalWildcard(Permission.from("*:*"))).toBe(true);
      expect(PermissionMatcher.isGlobalWildcard("users:*")).toBe(false);
      expect(PermissionMatcher.isGlobalWildcard("*:read")).toBe(false);
      expect(PermissionMatcher.isGlobalWildcard("users:read")).toBe(false);
    });
  });

  describe("property-style randomized test matrix", () => {
    const resources = ["users", "orgs", "billing", "audit", "secrets", "roles"];
    const actions = ["read", "write", "delete", "export", "manage", "list"];

    it("generates pairwise checks and asserts strict consistency invariants", () => {
      for (const r1 of resources) {
        for (const a1 of actions) {
          const exact = `${r1}:${a1}`;
          const actionWildcard = `${r1}:*`;
          const resourceWildcard = `*:${a1}`;
          const globalWildcard = "*:*";

          for (const r2 of resources) {
            for (const a2 of actions) {
              const target = `${r2}:${a2}`;

              // Invariant 1: Exact matches if and only if r1==r2 and a1==a2
              const exactExpected = r1 === r2 && a1 === a2;
              expect(PermissionMatcher.matches(exact, target)).toBe(exactExpected);

              // Invariant 2: Action wildcard matches if and only if r1==r2
              const actionExpected = r1 === r2;
              expect(PermissionMatcher.matches(actionWildcard, target)).toBe(actionExpected);

              // Invariant 3: Resource wildcard matches if and only if a1==a2
              const resourceExpected = a1 === a2;
              expect(PermissionMatcher.matches(resourceWildcard, target)).toBe(resourceExpected);

              // Invariant 4: Global wildcard unconditionally matches
              expect(PermissionMatcher.matches(globalWildcard, target)).toBe(true);
            }
          }
        }
      }
    });
  });
});
