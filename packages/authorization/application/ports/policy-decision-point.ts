import type { AuthorizationRequest } from "../../domain/attribute-context.js";
import type { PolicyEffect } from "../../domain/authorization-decision.js";

/**
 * The attribute-based half of an authorization question: Issue 148's combined
 * policy decision for one request.
 *
 * The port deliberately returns three values rather than a boolean. "No policy
 * targets this action" is not the same fact as "a policy denied it" — the
 * composition service needs the difference to decide whether an RBAC grant
 * stands, and the simulator needs it to explain a dry run.
 */

/** What the policy engine concluded, without losing which policies produced it. */
export interface PolicyEvaluation {
  readonly effect: PolicyEffect;
  /** Stable explanation, for logs, the audit trail, and dry-run reports. */
  readonly reason: string;
  /** Policies that matched the request and contributed to the effect. */
  readonly matchedPolicyIds: readonly string[];
}

/** Port implemented by the policy engine that compiles and evaluates the DSL. */
export interface PolicyDecisionPoint {
  /**
   * Evaluates every applicable policy for the request and returns the combined
   * effect.
   *
   * Contracts an implementation must honour:
   *
   * - **`deny-overrides` is the combining strategy.** A single explicit `DENY`
   *   outranks any number of `PERMIT` rules (threat E-2). An implementation may
   *   not select another strategy per call.
   * - **`NOT_APPLICABLE` means "no policy targets this".** It is returned only
   *   when the applicable set is empty, never to mean "evaluation failed".
   * - **Unresolved attributes deny, they do not throw.** A condition whose
   *   operands are missing evaluates to `false`, so the affected rule does not
   *   match; attribute provider failure must not surface as `NOT_APPLICABLE`.
   * - **Only repository unavailability throws.** A store that cannot be reached
   *   is an infrastructure failure the caller converts into an explicit `DENY`
   *   with reason "Policy repository unavailable" — never a permit.
   */
  evaluate(request: AuthorizationRequest): Promise<PolicyEvaluation>;
}
