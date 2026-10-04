import type { AttributeValue } from "../value-objects/attribute-context.js";

export type ComparisonOperator =
  "==" | "!=" | "<" | "<=" | ">" | ">=" | "in" | "contains" | "matches";

export type OperatorResult =
  | { readonly ok: true; readonly value: boolean }
  | { readonly ok: false; readonly reason: "type_mismatch" | "invalid_pattern" | "invalid_date" };

/**
 * Evaluate a typed DSL operator. No implicit coercion is performed: values of
 * different types never become equal, and operators used with incompatible
 * types return a mismatch rather than relying on JavaScript's coercion rules.
 */
export function evaluateOperator(
  operator: ComparisonOperator,
  left: AttributeValue | undefined,
  right: AttributeValue | undefined,
): OperatorResult {
  if (left === undefined || right === undefined) return success(false);

  switch (operator) {
    case "==":
      return success(sameTypedValue(left, right));
    case "!=":
      return success(!sameTypedValue(left, right));
    case "<":
    case "<=":
    case ">":
    case ">=":
      return compare(operator, left, right);
    case "in":
      if (!Array.isArray(right)) return mismatch();
      return success(
        (right as readonly AttributeValue[]).some((candidate) => sameTypedValue(left, candidate)),
      );
    case "contains":
      if (typeof left === "string" && typeof right === "string") {
        return success(left.includes(right));
      }
      if (Array.isArray(left))
        return success(
          (left as readonly AttributeValue[]).some((candidate) => sameTypedValue(candidate, right)),
        );
      return mismatch();
    case "matches":
      if (typeof left !== "string" || typeof right !== "string") return mismatch();
      try {
        return success(new RegExp(right, "u").test(left));
      } catch {
        return { ok: false, reason: "invalid_pattern" };
      }
  }
}

/** Inclusive range helper, useful for explicit environment.now time windows. */
export function between(
  value: AttributeValue | undefined,
  start: AttributeValue | undefined,
  end: AttributeValue | undefined,
): OperatorResult {
  if (value === undefined || start === undefined || end === undefined) return success(false);
  if (value instanceof Date && start instanceof Date && end instanceof Date) {
    if (![value, start, end].every((date) => !Number.isNaN(date.getTime()))) {
      return { ok: false, reason: "invalid_date" };
    }
    return success(start.getTime() <= value.getTime() && value.getTime() <= end.getTime());
  }
  if ([value, start, end].every((entry) => typeof entry === "number" && Number.isFinite(entry))) {
    return success((start as number) <= (value as number) && (value as number) <= (end as number));
  }
  return mismatch();
}

function compare(
  operator: "<" | "<=" | ">" | ">=",
  left: AttributeValue,
  right: AttributeValue,
): OperatorResult {
  if (typeof left === "number" && typeof right === "number") {
    if (!Number.isFinite(left) || !Number.isFinite(right)) return mismatch();
    switch (operator) {
      case "<":
        return success(left < right);
      case "<=":
        return success(left <= right);
      case ">":
        return success(left > right);
      case ">=":
        return success(left >= right);
    }
  }
  if (typeof left === "string" && typeof right === "string") {
    const order = left < right ? -1 : left > right ? 1 : 0;
    switch (operator) {
      case "<":
        return success(order < 0);
      case "<=":
        return success(order <= 0);
      case ">":
        return success(order > 0);
      case ">=":
        return success(order >= 0);
    }
  }
  if (left instanceof Date && right instanceof Date) {
    if (Number.isNaN(left.getTime()) || Number.isNaN(right.getTime())) {
      return { ok: false, reason: "invalid_date" };
    }
    return compare(operator, left.getTime(), right.getTime());
  }
  return mismatch();
}

function sameTypedValue(left: AttributeValue, right: AttributeValue): boolean {
  if (typeof left !== typeof right) return false;
  if (left instanceof Date && right instanceof Date) return left.getTime() === right.getTime();
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) && Array.isArray(right) && JSON.stringify(left) === JSON.stringify(right)
    );
  }
  if (typeof left === "object" && left !== null && typeof right === "object" && right !== null) {
    return JSON.stringify(left) === JSON.stringify(right);
  }
  return left === right;
}

function success(value: boolean): OperatorResult {
  return { ok: true, value };
}

function mismatch(): OperatorResult {
  return { ok: false, reason: "type_mismatch" };
}
