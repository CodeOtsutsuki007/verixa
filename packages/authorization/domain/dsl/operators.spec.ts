import { describe, expect, it } from "vitest";

import { between, evaluateOperator } from "./operators.js";

describe("policy DSL operators", () => {
  it("performs strict equality without coercing values", () => {
    expect(evaluateOperator("==", "5", 5)).toEqual({ ok: true, value: false });
    expect(evaluateOperator("!=", "5", 5)).toEqual({ ok: true, value: true });
    expect(evaluateOperator("==", true, true)).toEqual({ ok: true, value: true });
  });

  it.each([
    ["<", 2, 3, true],
    ["<=", 3, 3, true],
    [">", 4, 3, true],
    [">=", 3, 3, true],
    ["<", "a", "b", true],
  ] as const)("compares %s values", (operator, left, right, expected) => {
    expect(evaluateOperator(operator, left, right)).toEqual({ ok: true, value: expected });
  });

  it("returns an explicit mismatch for ordering incompatible types", () => {
    expect(evaluateOperator("<", "5", 6)).toEqual({ ok: false, reason: "type_mismatch" });
  });

  it("supports membership and string/array containment", () => {
    expect(evaluateOperator("in", "read", ["read", "write"])).toEqual({ ok: true, value: true });
    expect(evaluateOperator("contains", "document", "doc")).toEqual({ ok: true, value: true });
    expect(evaluateOperator("contains", ["reader", "admin"], "admin")).toEqual({ ok: true, value: true });
    expect(evaluateOperator("in", "read", "read,write")).toEqual({ ok: false, reason: "type_mismatch" });
  });

  it("matches regular expressions and reports malformed patterns", () => {
    expect(evaluateOperator("matches", "alice@example.com", "^[^@]+@example\\.com$")).toEqual({
      ok: true,
      value: true,
    });
    expect(evaluateOperator("matches", "abc", "[")).toEqual({ ok: false, reason: "invalid_pattern" });
  });

  it("makes missing values fail closed, even for inequality", () => {
    expect(evaluateOperator("==", undefined, "admin")).toEqual({ ok: true, value: false });
    expect(evaluateOperator("!=", undefined, "admin")).toEqual({ ok: true, value: false });
  });

  it("evaluates inclusive date and number ranges", () => {
    const start = new Date("2026-09-30T10:00:00.000Z");
    const end = new Date("2026-09-30T12:00:00.000Z");
    expect(between(end, start, end)).toEqual({ ok: true, value: true });
    expect(between(5, 1, 5)).toEqual({ ok: true, value: true });
    expect(between(6, 1, 5)).toEqual({ ok: true, value: false });
    expect(between("5", 1, 5)).toEqual({ ok: false, reason: "type_mismatch" });
  });
});
