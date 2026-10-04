import type { AttributeContext } from "../value-objects/attribute-context.js";
import type { Rule } from "../value-objects/rule.js";

import { evaluateRule } from "./policy-evaluation-engine.js";

/**
 * The outcome one rule contributes once its condition has been checked
 * against a context — a third state beyond {@link import("../value-objects/effect.js").Effect}'s
 * `PERMIT`/`DENY`, for the rule that simply didn't match.
 */
export type RuleOutcome = "PERMIT" | "DENY" | "NOT_APPLICABLE";

/** Evaluates every rule's condition and maps each to its {@link RuleOutcome}: the rule's effect if it matched, `NOT_APPLICABLE` otherwise. */
export function deriveRuleOutcomes(
  rules: readonly Rule[],
  context: AttributeContext,
): readonly RuleOutcome[] {
  return rules.map((rule) => (evaluateRule(rule, context) ? rule.effect : "NOT_APPLICABLE"));
}

/**
 * A named strategy for reducing several rules' outcomes to one final
 * decision — lifted directly from XACML's combining-algorithm vocabulary
 * (Issue 148's educational note), so contributors can bring prior ABAC
 * knowledge to these names rather than Verixa inventing its own.
 */
export type CombiningAlgorithm = (outcomes: readonly RuleOutcome[]) => RuleOutcome;

/**
 * Any `DENY` wins, regardless of how many `PERMIT`s also matched. This is
 * the system default (see `authorization-service.ts` and
 * `docs/security/authorization-model.md`): favoring safety means a single
 * applicable deny rule should never be overridable by a more permissive one
 * elsewhere in the same policy set.
 */
export const denyOverrides: CombiningAlgorithm = (outcomes) => {
  if (outcomes.includes("DENY")) {
    return "DENY";
  }
  if (outcomes.includes("PERMIT")) {
    return "PERMIT";
  }
  return "NOT_APPLICABLE";
};

/** Any `PERMIT` wins over a `DENY` — the inverse precedence of {@link denyOverrides}, for policy sets designed to be permissive-by-default. */
export const permitOverrides: CombiningAlgorithm = (outcomes) => {
  if (outcomes.includes("PERMIT")) {
    return "PERMIT";
  }
  if (outcomes.includes("DENY")) {
    return "DENY";
  }
  return "NOT_APPLICABLE";
};

/**
 * The first rule with an applicable outcome (not `NOT_APPLICABLE`) wins;
 * everything after it is ignored regardless of effect. Requires rule order
 * within a policy to be meaningful, unlike the other two algorithms.
 */
export const firstApplicable: CombiningAlgorithm = (outcomes) => {
  return outcomes.find((outcome) => outcome !== "NOT_APPLICABLE") ?? "NOT_APPLICABLE";
};
