import type { AttributeContext, AttributeValue } from "../value-objects/attribute-context.js";
import type { ComparisonCondition, Condition } from "../value-objects/condition.js";
import type { Rule } from "../value-objects/rule.js";

function isOrderable(value: AttributeValue): value is number | Date {
  return typeof value === "number" || value instanceof Date;
}

function orderableValueOf(value: number | Date): number {
  return value instanceof Date ? value.getTime() : value;
}

/**
 * Evaluates one leaf comparison against a resolved attribute value.
 *
 * Type-mismatch behavior is deliberately explicit rather than coercive, per
 * Issue 147's rationale (which this minimal implementation anticipates
 * without yet building the full standalone operator library): comparing a
 * number to a string never silently succeeds via implicit coercion, it
 * simply evaluates to `false`. This keeps a policy author's mistake (or a
 * resolver returning the wrong shape) a visible "this rule didn't match"
 * rather than a surprising type-juggled result.
 */
function evaluateComparison(condition: ComparisonCondition, context: AttributeContext): boolean {
  const actual = context.resolve(condition.attribute);
  if (actual === undefined) {
    return false;
  }

  switch (condition.operator) {
    case "eq":
      if (Array.isArray(actual) || Array.isArray(condition.value)) {
        return false;
      }
      if (actual instanceof Date) {
        return (
          typeof condition.value === "string" && actual.getTime() === Date.parse(condition.value)
        );
      }
      return actual === condition.value;
    case "neq":
      return !evaluateComparison({ ...condition, operator: "eq" }, context);
    case "lt":
    case "lte":
    case "gt":
    case "gte": {
      if (!isOrderable(actual) || typeof condition.value !== "number") {
        return false;
      }
      const actualValue = orderableValueOf(actual);
      switch (condition.operator) {
        case "lt":
          return actualValue < condition.value;
        case "lte":
          return actualValue <= condition.value;
        case "gt":
          return actualValue > condition.value;
        case "gte":
          return actualValue >= condition.value;
      }
      break;
    }
    case "in": {
      if (!Array.isArray(condition.value) || Array.isArray(actual) || actual instanceof Date) {
        return false;
      }
      return (condition.value as readonly (string | number)[]).includes(actual as string | number);
    }
    case "contains": {
      if (!Array.isArray(actual) || Array.isArray(condition.value)) {
        return false;
      }
      return (actual as readonly (string | number)[]).includes(condition.value as string | number);
    }
  }
}

/**
 * Pure function walking a {@link Condition} tree against an
 * {@link AttributeContext}. No I/O, no repository calls, no side effects —
 * which is what makes exhaustive branch-coverage testing of authorization
 * logic tractable (see Issue 146's educational note).
 *
 * `AND`/`OR` short-circuit via `Array.prototype.every`/`.some`: a `false`
 * branch inside an `AND` (or a `true` one inside an `OR`) stops evaluation
 * of the remaining operands rather than evaluating every one regardless.
 * Evaluating against a missing attribute resolves to `false` rather than
 * throwing, matching {@link AttributeContext.resolve}'s own contract.
 */
export function evaluateCondition(condition: Condition, context: AttributeContext): boolean {
  switch (condition.kind) {
    case "always":
      return true;
    case "comparison":
      return evaluateComparison(condition, context);
    case "and":
      return condition.operands.every((operand) => evaluateCondition(operand, context));
    case "or":
      return condition.operands.some((operand) => evaluateCondition(operand, context));
    case "not":
      return !evaluateCondition(condition.operand, context);
  }
}

/**
 * Evaluates whether `rule`'s condition matches `context`. Does not consult
 * `rule.effect` — deriving a `PERMIT`/`DENY`/`NOT_APPLICABLE` outcome from a
 * match/no-match result is `combining-algorithms.ts`'s job (Issue 148), kept
 * separate so this evaluator stays a pure boolean predicate.
 */
export function evaluateRule(rule: Rule, context: AttributeContext): boolean {
  return evaluateCondition(rule.condition, context);
}
