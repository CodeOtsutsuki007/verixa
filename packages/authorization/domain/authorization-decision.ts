/**
 * The decision model returned by every authorization path, plus the precedence
 * contract that composes them.
 *
 * Two rules from `docs/security/threat-model-abac.md` are executable here
 * rather than only described there. Threat E-1 (RBAC/ABAC precedence bugs) is
 * the reason the precedence strategy below is a named, resolved value instead
 * of an if-order inside the service; threat E-2 (over-grant by combining) is
 * the reason `deny-overrides` is the default. A change to either has to be a
 * deliberate edit to this file, reviewed as a security change.
 */

/** The two terminal outcomes a decision can have. There is no "abstain" at this layer. */
export type AuthorizationEffect = "PERMIT" | "DENY";

/**
 * What a policy evaluation can conclude. `NOT_APPLICABLE` is the third value
 * the composition service needs: "no policy targets this request" is a
 * different fact from "a policy denied it", and only the difference lets an
 * RBAC grant stand unrefined.
 */
export type PolicyEffect = "PERMIT" | "DENY" | "NOT_APPLICABLE";

/** Which layer produced the decision that is being returned. */
export type AuthorizationDecisionSource = "rbac" | "abac" | "composition" | "fail-closed";

/** A decision, with enough context to answer "why" without re-running the evaluation. */
export interface AuthorizationDecision {
  readonly effect: AuthorizationEffect;
  /** Layer that produced the returned effect. */
  readonly source: AuthorizationDecisionSource;
  /** Stable, human-readable explanation — safe to log, not safe to return to end users as-is. */
  readonly reason: string;
  /** Every policy that contributed to the decision, so an audit trail can reference them. */
  readonly matchedPolicyIds: readonly string[];
}

/**
 * The composition contract between the RBAC layer (Phase 07) and the ABAC
 * layer (Issue 148).
 *
 * Issue 152 asks for a *documented, configurable* precedence order. Both halves
 * matter, and they pull in opposite directions: a deployment should be able to
 * state the order it runs under, but the two rules below are the ones that stop
 * a coarse role grant from silently outranking a fine-grained policy denial.
 * The resolution is that the order is configuration — resolved once, carried as
 * a value, and asserted in tests — while {@link assertAuthorizationPrecedenceIsSafe}
 * refuses any configuration that weakens it, so a typo or an optimistic local
 * edit fails loudly instead of shipping an over-grant.
 *
 * - An explicit ABAC `DENY` always overrides an RBAC `PERMIT`: an attribute
 *   policy is the only place that can express "not this time" for a role that
 *   would otherwise be allowed (working hours, clearance, tenant boundaries).
 *   Threat E-1 is exactly this rule failing, and it is rated the highest-risk
 *   failure of the phase.
 * - An ABAC `PERMIT` never overrides an RBAC `DENY`, and an ABAC
 *   `NOT_APPLICABLE` never upgrades to a permit. Role denials stay final, and
 *   "no policy matched" is a denial, not an approval.
 */
export interface AuthorizationPrecedence {
  /** When false, a role grant short-circuits the policy engine and an applicable `DENY` policy becomes unreachable. Mandated `true`. */
  readonly abacDenyOverridesRbacPermit: boolean;
  /** When true, an attribute policy can talk a revoked permission back into existence. Mandated `false`. */
  readonly abacPermitOverridesRbacDeny: boolean;
  /** Effect of "neither layer granted" — denial by absence of authority. Mandated `DENY`. */
  readonly defaultEffectWhenNoPolicyMatches: AuthorizationEffect;
}

/** The precedence order Verixa runs under, and the only one a boot will accept. */
export const AUTHORIZATION_PRECEDENCE: AuthorizationPrecedence = {
  abacDenyOverridesRbacPermit: true,
  abacPermitOverridesRbacDeny: false,
  defaultEffectWhenNoPolicyMatches: "DENY",
};

/** Raised when a configuration asks for a precedence order that is not safe to run. */
export class UnsafeAuthorizationPrecedenceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsafeAuthorizationPrecedenceError";
  }
}

/**
 * Rejects a precedence order that would weaken the composition contract.
 *
 * Called by the service at construction time, so a bad configuration stops the
 * process at boot rather than granting access wrongly at request time. The
 * rejected alternative that motivated this: making the order fully free-form,
 * including an `rbac-first` mode that consults policies only when no role
 * matched. It is one indexed lookup cheaper and it reads like the issue's own
 * summary sentence, but it makes every policy denial unreachable for subjects
 * who hold a role — the policy layer could then only add authority, never
 * withhold it. That is threat E-1 with a configuration flag on it.
 */
export function assertAuthorizationPrecedenceIsSafe(
  precedence: AuthorizationPrecedence,
): AuthorizationPrecedence {
  if (!precedence.abacDenyOverridesRbacPermit) {
    throw new UnsafeAuthorizationPrecedenceError(
      "Unsafe authorization precedence: abacDenyOverridesRbacPermit must be true — a role grant may not outrank an explicit policy denial (threat E-1).",
    );
  }

  if (precedence.abacPermitOverridesRbacDeny) {
    throw new UnsafeAuthorizationPrecedenceError(
      "Unsafe authorization precedence: abacPermitOverridesRbacDeny must be false — an attribute policy may not overrule a role denial.",
    );
  }

  if (precedence.defaultEffectWhenNoPolicyMatches !== "DENY") {
    throw new UnsafeAuthorizationPrecedenceError(
      "Unsafe authorization precedence: defaultEffectWhenNoPolicyMatches must be DENY — permit-by-default grants every request no role and no policy mentions (threat E-2).",
    );
  }

  return precedence;
}

/**
 * Resolves the deployment's precedence order, defaulting to
 * {@link AUTHORIZATION_PRECEDENCE} and validating whatever it is given.
 */
export function resolveAuthorizationPrecedence(
  overrides?: Partial<AuthorizationPrecedence>,
): AuthorizationPrecedence {
  return assertAuthorizationPrecedenceIsSafe({ ...AUTHORIZATION_PRECEDENCE, ...overrides });
}

/**
 * The reason strings returned by the composition service and the simulator.
 * They are contract: tests assert on them and the audit trail records them, so
 * they change only deliberately.
 */
export const AUTHORIZATION_REASONS = {
  rbacGrant: "RBAC grant",
  rbacDeny: "RBAC denial",
  abacDeny: "ABAC policy denial",
  abacPermit: "ABAC policy permit",
  noApplicablePolicy: "No applicable policy",
  rbacUnavailable: "Role permission store unavailable",
  policyRepositoryUnavailable: "Policy repository unavailable",
  invalidRequest: "Invalid authorization request",
} as const;
