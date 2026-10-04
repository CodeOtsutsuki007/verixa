import { describe, expect, it, vi } from "vitest";

import { AttributeContext } from "../value-objects/attribute-context.js";
import { Condition, type Condition as ConditionType } from "../value-objects/condition.js";
import { Rule } from "../value-objects/rule.js";

import { evaluateCondition, evaluateRule } from "./policy-evaluation-engine.js";

describe("evaluateCondition", () => {
  it("matches 'always' unconditionally", () => {
    expect(evaluateCondition(Condition.always(), AttributeContext.create({}))).toBe(true);
  });

  describe("comparison operators", () => {
    const context = AttributeContext.create({
      subject: { role: "admin", clearance: 3 },
      resource: {
        ownerId: "user-1",
        tags: ["a", "b"],
        availableFrom: new Date("2026-01-01T00:00:00Z"),
      },
    });

    it("eq matches equal primitives", () => {
      expect(
        evaluateCondition(Condition.comparison("resource.ownerId", "eq", "user-1"), context),
      ).toBe(true);
      expect(
        evaluateCondition(Condition.comparison("resource.ownerId", "eq", "user-2"), context),
      ).toBe(false);
    });

    it("neq is the negation of eq", () => {
      expect(
        evaluateCondition(Condition.comparison("resource.ownerId", "neq", "user-2"), context),
      ).toBe(true);
    });

    it("lt/lte/gt/gte compare numbers", () => {
      expect(evaluateCondition(Condition.comparison("subject.clearance", "gte", 3), context)).toBe(
        true,
      );
      expect(evaluateCondition(Condition.comparison("subject.clearance", "gt", 3), context)).toBe(
        false,
      );
      expect(evaluateCondition(Condition.comparison("subject.clearance", "lt", 3), context)).toBe(
        false,
      );
      expect(evaluateCondition(Condition.comparison("subject.clearance", "lte", 3), context)).toBe(
        true,
      );
    });

    it("lt/lte/gt/gte compare Date attributes against a numeric timestamp", () => {
      const before = new Date("2025-12-31T00:00:00Z").getTime();
      expect(
        evaluateCondition(Condition.comparison("resource.availableFrom", "gt", before), context),
      ).toBe(true);
    });

    it("in checks membership of the attribute in the literal array", () => {
      expect(
        evaluateCondition(Condition.comparison("subject.role", "in", ["admin", "owner"]), context),
      ).toBe(true);
      expect(
        evaluateCondition(Condition.comparison("subject.role", "in", ["owner"]), context),
      ).toBe(false);
    });

    it("contains checks membership of the literal in the attribute array", () => {
      expect(
        evaluateCondition(Condition.comparison("resource.tags", "contains", "a"), context),
      ).toBe(true);
      expect(
        evaluateCondition(Condition.comparison("resource.tags", "contains", "c"), context),
      ).toBe(false);
    });

    it("type mismatches evaluate to false rather than coercing", () => {
      expect(evaluateCondition(Condition.comparison("subject.role", "gt", 1), context)).toBe(false);
      expect(
        evaluateCondition(Condition.comparison("subject.clearance", "in", ["3"]), context),
      ).toBe(false);
      expect(
        evaluateCondition(Condition.comparison("resource.tags", "eq", ["a", "b"]), context),
      ).toBe(false);
    });

    it("evaluates to false against an attribute that is not present in the context", () => {
      expect(evaluateCondition(Condition.comparison("resource.missing", "eq", "x"), context)).toBe(
        false,
      );
    });
  });

  describe("short-circuiting", () => {
    it("AND does not evaluate later operands once an earlier one is false", () => {
      const secondOperand = vi.fn(() => false);
      const spyCondition: ConditionType = {
        kind: "comparison",
        get attribute() {
          secondOperand();
          return "subject.role";
        },
        operator: "eq",
        value: "admin",
      };

      const tree = Condition.and([
        Condition.comparison("subject.role", "eq", "guest"),
        spyCondition,
      ]);
      const context = AttributeContext.create({ subject: { role: "admin" } });

      expect(evaluateCondition(tree, context)).toBe(false);
      expect(secondOperand).not.toHaveBeenCalled();
    });

    it("OR does not evaluate later operands once an earlier one is true", () => {
      const secondOperand = vi.fn(() => false);
      const spyCondition: ConditionType = {
        kind: "comparison",
        get attribute() {
          secondOperand();
          return "subject.role";
        },
        operator: "eq",
        value: "admin",
      };

      const tree = Condition.or([
        Condition.comparison("subject.role", "eq", "admin"),
        spyCondition,
      ]);
      const context = AttributeContext.create({ subject: { role: "admin" } });

      expect(evaluateCondition(tree, context)).toBe(true);
      expect(secondOperand).not.toHaveBeenCalled();
    });
  });

  describe("deep nesting", () => {
    it("evaluates arbitrarily nested AND/OR/NOT correctly", () => {
      const context = AttributeContext.create({
        subject: { role: "guest" },
        resource: { ownerId: "user-1", locked: true },
      });

      const tree = Condition.and([
        Condition.or([
          Condition.comparison("subject.role", "eq", "admin"),
          Condition.comparison("resource.ownerId", "eq", "user-1"),
        ]),
        Condition.not(Condition.comparison("resource.locked", "eq", true)),
      ]);

      expect(evaluateCondition(tree, context)).toBe(false);
    });
  });
});

describe("evaluateRule", () => {
  it("delegates to evaluateCondition without consulting the rule's effect", () => {
    const context = AttributeContext.create({ subject: { role: "admin" } });
    const rule = Rule.create({
      effect: "DENY",
      condition: Condition.comparison("subject.role", "eq", "admin"),
    });

    expect(evaluateRule(rule, context)).toBe(true);
  });
});
