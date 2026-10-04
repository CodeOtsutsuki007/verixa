import { describe, expect, it } from "vitest";

import { Condition } from "./condition.js";

describe("Condition", () => {
  describe("always", () => {
    it("produces an unconditional leaf", () => {
      expect(Condition.always()).toEqual({ kind: "always" });
    });
  });

  describe("comparison", () => {
    it("carries the attribute path, operator, and literal value", () => {
      const condition = Condition.comparison("resource.ownerId", "eq", "user-1");
      expect(condition).toEqual({
        kind: "comparison",
        attribute: "resource.ownerId",
        operator: "eq",
        value: "user-1",
      });
    });

    it("accepts array literals for set operators", () => {
      const condition = Condition.comparison("resource.tags", "in", ["a", "b"]);
      expect(condition.value).toEqual(["a", "b"]);
    });
  });

  describe("arbitrary nesting", () => {
    it("supports AND/OR/NOT nested to arbitrary depth", () => {
      const tree = Condition.and([
        Condition.or([
          Condition.comparison("subject.role", "eq", "admin"),
          Condition.not(Condition.comparison("resource.locked", "eq", true)),
        ]),
        Condition.comparison("action", "eq", "read"),
      ]);

      expect(tree.kind).toBe("and");
      expect(tree.operands).toHaveLength(2);
      expect(tree.operands[0]?.kind).toBe("or");
    });

    it("throws when AND is given no operands", () => {
      expect(() => Condition.and([])).toThrow();
    });

    it("throws when OR is given no operands", () => {
      expect(() => Condition.or([])).toThrow();
    });
  });

  describe("equals", () => {
    it("treats identical trees as equal regardless of object identity", () => {
      const a = Condition.and([
        Condition.comparison("subject.role", "eq", "admin"),
        Condition.comparison("action", "eq", "read"),
      ]);
      const b = Condition.and([
        Condition.comparison("subject.role", "eq", "admin"),
        Condition.comparison("action", "eq", "read"),
      ]);

      expect(Condition.equals(a, b)).toBe(true);
    });

    it("treats different operand order as unequal", () => {
      const a = Condition.and([
        Condition.comparison("subject.role", "eq", "admin"),
        Condition.comparison("action", "eq", "read"),
      ]);
      const b = Condition.and([
        Condition.comparison("action", "eq", "read"),
        Condition.comparison("subject.role", "eq", "admin"),
      ]);

      expect(Condition.equals(a, b)).toBe(false);
    });

    it("treats different node kinds as unequal", () => {
      const a = Condition.always();
      const b = Condition.comparison("action", "eq", "read");
      expect(Condition.equals(a, b)).toBe(false);
    });

    it("treats different comparison operators as unequal", () => {
      const a = Condition.comparison("resource.count", "lt", 5);
      const b = Condition.comparison("resource.count", "lte", 5);
      expect(Condition.equals(a, b)).toBe(false);
    });

    it("treats different array literal values as unequal", () => {
      const a = Condition.comparison("resource.tags", "in", ["a", "b"]);
      const b = Condition.comparison("resource.tags", "in", ["a", "c"]);
      expect(Condition.equals(a, b)).toBe(false);
    });

    it("treats a scalar value compared against an array value as unequal", () => {
      const a = Condition.comparison("resource.tags", "in", ["a"]);
      const b = Condition.comparison("resource.tags", "in", "a");
      expect(Condition.equals(a, b)).toBe(false);
    });

    it("compares NOT nodes by their operand", () => {
      const a = Condition.not(Condition.comparison("resource.locked", "eq", true));
      const b = Condition.not(Condition.comparison("resource.locked", "eq", true));
      const c = Condition.not(Condition.comparison("resource.locked", "eq", false));

      expect(Condition.equals(a, b)).toBe(true);
      expect(Condition.equals(a, c)).toBe(false);
    });

    it("treats operand-count mismatches within AND/OR as unequal", () => {
      const a = Condition.and([Condition.always(), Condition.always()]);
      const b = Condition.and([Condition.always()]);
      expect(Condition.equals(a, b)).toBe(false);
    });
  });
});
