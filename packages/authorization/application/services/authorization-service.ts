import type { PolicyId } from "../../domain/entities/policy.js";
import {
  deriveRuleOutcomes,
  denyOverrides,
  type CombiningAlgorithm,
  type RuleOutcome,
} from "../../domain/services/combining-algorithms.js";
import type { AttributeContext } from "../../domain/value-objects/attribute-context.js";
import type { PolicyRepository } from "../ports/policy-repository.js";
import type { RbacAuthorizationPort, RbacDecision } from "../ports/rbac-authorization.js";

export interface AuthorizeParams {
  readonly subjectId: string;
  readonly action: string;
  readonly resourceType: string;
  readonly context: AttributeContext;
}

/** `PERMIT`/`DENY` only: this is the *final* decision, after RBAC and ABAC have been composed, so "no opinion" is never a valid outcome here. */
export type AuthorizationEffect = "PERMIT" | "DENY";

export interface AuthorizationResult {
  readonly effect: AuthorizationEffect;
  readonly rbacDecision: RbacDecision;
  readonly abacDecision: RuleOutcome;
  readonly matchedPolicyIds: readonly PolicyId[];
}

/**
 * Composes Phase 07's RBAC grant check with ABAC policy evaluation into one
 * decision — the central architectural piece of Phase 08 (Issue 152).
 *
 * ## Precedence order
 *
 * ```
 * 1. An applicable DENY policy always wins, regardless of the RBAC result.
 * 2. Otherwise, a definitive RBAC decision (PERMIT or DENY) passes through
 *    unchanged — this is what "RBAC-only decisions work unchanged from
 *    Phase 07 behavior" means once RBAC actually has an opinion.
 * 3. Otherwise (RBAC has no opinion), an applicable PERMIT policy grants.
 * 4. Otherwise, deny. Fail-closed: silent over-grant from two systems each
 *    assuming the other would catch it is exactly the risk this composition
 *    layer exists to avoid (see `docs/security/authorization-model.md`).
 * ```
 *
 * Full truth table (`✔` = this outcome, tested in
 * `authorization-service.spec.ts`):
 *
 * | RBAC           | ABAC           | Result  | Why                          |
 * |----------------|----------------|---------|------------------------------|
 * | PERMIT         | PERMIT         | PERMIT  | rule 2                       |
 * | PERMIT         | DENY           | DENY    | rule 1 — explicit override   |
 * | DENY           | PERMIT         | DENY    | rule 2 — RBAC deny wins      |
 * | DENY           | DENY           | DENY    | rule 1 and rule 2 agree      |
 * | NOT_APPLICABLE | PERMIT         | PERMIT  | rule 3                       |
 * | NOT_APPLICABLE | DENY           | DENY    | rule 1                       |
 * | NOT_APPLICABLE | NOT_APPLICABLE | DENY    | rule 4 — fail-closed default |
 * | PERMIT         | NOT_APPLICABLE | PERMIT  | rule 2 — Phase 07 unchanged  |
 * | DENY           | NOT_APPLICABLE | DENY    | rule 2 — Phase 07 unchanged  |
 *
 * ABAC's own multi-policy/multi-rule outcomes are reduced first, via
 * `combiningAlgorithm` (default: {@link denyOverrides} — see that
 * function's own doc comment for why deny-overrides is the system default).
 */
export class AuthorizationService {
  constructor(
    private readonly rbac: RbacAuthorizationPort,
    private readonly policyRepository: PolicyRepository,
    private readonly combiningAlgorithm: CombiningAlgorithm = denyOverrides,
  ) {}

  async authorize(params: AuthorizeParams): Promise<AuthorizationResult> {
    const rbacDecision = await this.rbac.checkGrant({
      subjectId: params.subjectId,
      action: params.action,
      resourceType: params.resourceType,
    });

    const applicablePolicies = await this.policyRepository.findApplicableTo(
      params.resourceType,
      params.action,
    );

    const matchedPolicyIds: PolicyId[] = [];
    const allOutcomes: RuleOutcome[] = [];
    for (const policy of applicablePolicies) {
      const outcomes = deriveRuleOutcomes(policy.rules, params.context);
      if (outcomes.some((outcome) => outcome !== "NOT_APPLICABLE")) {
        matchedPolicyIds.push(policy.id);
      }
      allOutcomes.push(...outcomes);
    }
    const abacDecision = this.combiningAlgorithm(allOutcomes);

    const effect = AuthorizationService.compose(rbacDecision, abacDecision);

    return { effect, rbacDecision, abacDecision, matchedPolicyIds };
  }

  private static compose(
    rbacDecision: RbacDecision,
    abacDecision: RuleOutcome,
  ): AuthorizationEffect {
    if (abacDecision === "DENY") {
      return "DENY";
    }
    if (rbacDecision !== "NOT_APPLICABLE") {
      return rbacDecision;
    }
    if (abacDecision === "PERMIT") {
      return "PERMIT";
    }
    return "DENY";
  }
}
