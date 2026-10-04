import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { Condition } from "../value-objects/condition.js";
import { Rule } from "../value-objects/rule.js";

import { Policy } from "./policy.js";

function aRule(): Rule {
  return Rule.create({ effect: "PERMIT", condition: Condition.always() });
}

describe("Policy", () => {
  describe("create", () => {
    it("creates a version-1 policy given a name, target, and at least one rule", () => {
      const result = Policy.create({
        name: "document-owners-may-read",
        target: { resourceType: "document", actions: ["read"] },
        rules: [aRule()],
      });

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.version).toBe(1);
        expect(result.value.name).toBe("document-owners-may-read");
        expect(result.value.rules).toHaveLength(1);
        expect(result.value.id).toBeDefined();
      }
    });

    it("rejects an empty name", () => {
      const result = Policy.create({
        name: "  ",
        target: { resourceType: "document", actions: ["read"] },
        rules: [aRule()],
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.fieldErrors.name).toContain("required");
      }
    });

    it("rejects a policy with no rules", () => {
      const result = Policy.create({
        name: "empty-policy",
        target: { resourceType: "document", actions: ["read"] },
        rules: [],
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.fieldErrors.rules).toContain("at_least_one_rule_required");
      }
    });

    it("rejects a target with no actions", () => {
      const result = Policy.create({
        name: "no-actions",
        target: { resourceType: "document", actions: [] },
        rules: [aRule()],
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.fieldErrors.target).toContain("at_least_one_action_required");
      }
    });

    it("accumulates every field error at once", () => {
      const result = Policy.create({
        name: "",
        target: { resourceType: "document", actions: [] },
        rules: [],
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(Object.keys(result.error.fieldErrors).sort()).toEqual(["name", "rules", "target"]);
      }
    });
  });

  describe("reconstitute", () => {
    it("rebuilds a policy from trusted data without re-validating", () => {
      const created = Policy.create({
        name: "reconstituted",
        target: { resourceType: "document", actions: ["read"] },
        rules: [aRule()],
      });
      if (Result.isErr(created)) {
        throw created.error;
      }

      const reloaded = Policy.reconstitute(created.value);
      expect(reloaded.id).toBe(created.value.id);
      expect(reloaded.version).toBe(created.value.version);
    });
  });

  describe("publishNewVersion", () => {
    it("returns a new instance with version incremented, leaving the original untouched", () => {
      const created = Policy.create({
        name: "versioned",
        target: { resourceType: "document", actions: ["read"] },
        rules: [aRule()],
      });
      if (Result.isErr(created)) {
        throw created.error;
      }
      const original = created.value;

      const nextRule = Rule.create({ effect: "DENY", condition: Condition.always() });
      const published = original.publishNewVersion([nextRule]);

      expect(Result.isOk(published)).toBe(true);
      if (Result.isOk(published)) {
        expect(published.value.version).toBe(2);
        expect(published.value.id).toBe(original.id);
        expect(published.value.name).toBe(original.name);
        expect(original.version).toBe(1);
        expect(original.rules[0]?.equals(aRule())).toBe(true);
      }
    });

    it("rejects publishing a new version with no rules", () => {
      const created = Policy.create({
        name: "versioned",
        target: { resourceType: "document", actions: ["read"] },
        rules: [aRule()],
      });
      if (Result.isErr(created)) {
        throw created.error;
      }

      const published = created.value.publishNewVersion([]);
      expect(Result.isErr(published)).toBe(true);
    });
  });
});
