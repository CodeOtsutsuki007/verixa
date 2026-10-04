import type { AttributeContext } from "../../domain/attribute-context.js";
import type { PolicyEffect } from "../../domain/authorization-decision.js";

/**
 * The evaluation engine as the simulator needs it: Issue 146's evaluator plus
 * Issue 148's combining step, with the per-rule detail a dry run has to report.
 *
 * This is deliberately *not* {@link PolicyDecisionPoint}. That port answers "what
 * did the system decide", which is the question production asks and the simulator
 * cannot act on: a mismatch in a dry run is only actionable if the author can see
 * which rule produced it and whether the combining algorithm overrode it. Same
 * evaluation, a wider result.
 *
 * It is also narrower in the other direction: nothing here is request-shaped (no
 * subject id, no resource id, no tenant), so a simulation runs against fixtures
 * with no database, no session and no HTTP request behind them — which is the
 * entire point of the tool.
 */

/**
 * The policy under test.
 *
 * Both halves of the issue's "a policy (DSL text or stored id)" are represented,
 * and the distinction is load-bearing rather than cosmetic: a `draft` is
 * evaluated as given and never persisted, which is what lets an author iterate
 * on un-published text; a `stored` reference asks the engine for the policy a
 * real request would be evaluated against, which is what makes the tool useful
 * for answering "why does production deny this" after the fact.
 *
 * A discriminated union rather than two nullable strings, so "caller forgot to
 * say which" is not a representable input.
 */
export type PolicySource =
  | { readonly kind: "stored"; readonly ref: string }
  | { readonly kind: "draft"; readonly label: string; readonly dsl: string };

/** One rule's contribution to a run. */
export interface SimulatedRuleOutcome {
  readonly ruleId: string;
  /** What this rule alone concluded. `NOT_APPLICABLE` means its condition did not match. */
  readonly effect: PolicyEffect;
  /**
   * Whether this rule's effect is the one the combining step reported. A `PERMIT`
   * rule that was overridden by a `DENY` is not decisive, and saying so is what
   * turns "expected PERMIT, got DENY" into an explanation.
   */
  readonly decisive: boolean;
}

/** Everything one fixture's evaluation produced. */
export interface PolicySimulationRun {
  /** Human-readable identity of the policy that ran — a stored ref, or a draft's label. */
  readonly policyLabel: string;
  readonly combinedEffect: PolicyEffect;
  /** Named so a report can say which strategy produced the effect (Issue 148). */
  readonly combiningAlgorithm: string;
  readonly matchedPolicyIds: readonly string[];
  readonly rules: readonly SimulatedRuleOutcome[];
}

/** Port implemented by the policy engine that compiles and evaluates the DSL. */
export interface PolicySimulationEngine {
  /**
   * Evaluates `policy` against `context`, without persisting anything.
   *
   * Contracts an implementation must honour:
   *
   * - **Read-only.** A dry run must not publish, version-bump or cache a policy
   *   as a side effect of being asked what it would decide. A simulator that can
   *   change the thing it is inspecting is a liability in CI.
   * - **Every rule is reported, not just the matching ones.** The `rules` array
   *   covers the whole applicable rule set, with `NOT_APPLICABLE` for rules whose
   *   conditions did not match; a simulator that only sees winners cannot explain
   *   a result.
   * - **The combining step is named.** `combiningAlgorithm` is the strategy that
   *   reduced the rules to `combinedEffect`, so a report can attribute an
   *   override to `deny-overrides` rather than to a mystery.
   * - **Unresolved attributes deny; missing is not an error.** A fixture may leave
   *   an axis empty, and a rule whose operands are missing simply does not match.
   * - **An unreachable policy store throws.** That is an infrastructure failure,
   *   not a simulation result, and the caller reports it as such rather than as a
   *   mismatch — see `PolicySimulateCommand`'s exit codes.
   */
  simulate(policy: PolicySource, context: AttributeContext): Promise<PolicySimulationRun>;
}
