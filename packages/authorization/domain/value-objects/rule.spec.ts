import { describe, expect, it } from "vitest";

import { Condition } from "./condition.js";
import { Rule } from "./rule.js";

describe("Rule", () => {
  it("creates a rule from an effect and a real condition", () => {
    const rule = Rule.create({
      effect: "PERMIT",
      condition: Condition.comparison("resource.ownerId", "eq", "subject.id"),
    });

    expect(rule.effect).toBe("PERMIT");
    expect(rule.condition.kind).toBe("comparison");
  });

  it("creates a rule using the explicit 'always' marker instead of a real condition", () => {
    const rule = Rule.create({ effect: "DENY", condition: Condition.always() });

    expect(rule.effect).toBe("DENY");
    expect(rule.condition.kind).toBe("always");
  });

  it("carries an optional human-readable description", () => {
    const rule = Rule.create({
      effect: "PERMIT",
      condition: Condition.always(),
      description: "owners may always read their own resource",
    });

    expect(rule.description).toBe("owners may always read their own resource");
  });

  describe("equals", () => {
    it("treats rules with the same effect and condition as equal", () => {
      const a = Rule.create({ effect: "PERMIT", condition: Condition.comparison("a", "eq", 1) });
      const b = Rule.create({ effect: "PERMIT", condition: Condition.comparison("a", "eq", 1) });
      expect(a.equals(b)).toBe(true);
    });

    it("ignores description when comparing equality", () => {
      const a = Rule.create({
        effect: "PERMIT",
        condition: Condition.always(),
        description: "one",
      });
      const b = Rule.create({
        effect: "PERMIT",
        condition: Condition.always(),
        description: "two",
      });
      expect(a.equals(b)).toBe(true);
    });

    it("treats rules with different effects as unequal", () => {
      const a = Rule.create({ effect: "PERMIT", condition: Condition.always() });
      const b = Rule.create({ effect: "DENY", condition: Condition.always() });
      expect(a.equals(b)).toBe(false);
    });

    it("treats rules with different conditions as unequal", () => {
      const a = Rule.create({ effect: "PERMIT", condition: Condition.comparison("a", "eq", 1) });
      const b = Rule.create({ effect: "PERMIT", condition: Condition.comparison("a", "eq", 2) });
      expect(a.equals(b)).toBe(false);
    });
  });
});
