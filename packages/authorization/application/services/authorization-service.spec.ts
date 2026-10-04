import { describe, expect, it } from "vitest";

import {
  AUTHORIZATION_PRECEDENCE,
  AUTHORIZATION_REASONS,
  UnsafeAuthorizationPrecedenceError,
  assertAuthorizationPrecedenceIsSafe,
  resolveAuthorizationPrecedence,
} from "../../domain/authorization-decision.js";
import {
  emptyAttributeContext,
  type AuthorizationRequest,
} from "../../domain/attribute-context.js";
import type { PolicyDecisionPoint, PolicyEvaluation } from "../ports/policy-decision-point.js";
import type { RoleDecision, RolePermissionGate } from "../ports/role-permission-gate.js";
import { AuthorizationService } from "./authorization-service.js";

const REQUEST: AuthorizationRequest = {
  subject: { subjectId: "user-1", tenantId: "tenant-1" },
  action: "document:read",
  resource: { resourceType: "document", resourceId: "doc-1" },
  context: emptyAttributeContext(),
};

/**
 * Records every role check it receives so a test can assert that the ABAC
 * layer was *not* consulted when the role layer already settled the question.
 */
class RecordingRolePermissionGate implements RolePermissionGate {
  readonly requests: unknown[] = [];

  constructor(private readonly outcome: RoleDecision | Error) {}

  async check(request: unknown): Promise<RoleDecision> {
    this.requests.push(request);
    if (this.outcome instanceof Error) {
      throw this.outcome;
    }
    return this.outcome;
  }
}

/** Records the request each evaluation saw, so context defaults can be asserted. */
class RecordingPolicyDecisionPoint implements PolicyDecisionPoint {
  readonly requests: AuthorizationRequest[] = [];

  constructor(private readonly outcome: PolicyEvaluation | Error) {}

  async evaluate(request: AuthorizationRequest): Promise<PolicyEvaluation> {
    this.requests.push(request);
    if (this.outcome instanceof Error) {
      throw this.outcome;
    }
    return this.outcome;
  }
}

function roleDecision(kind: RoleDecision["kind"]): RoleDecision {
  return { kind, reason: `stub ${kind}`, roles: ["editor"], permissions: ["document:read"] };
}

function evaluation(effect: PolicyEvaluation["effect"]): PolicyEvaluation {
  return { effect, reason: `stub ${effect}`, matchedPolicyIds: ["policy-1"] };
}

describe("AuthorizationService", () => {
  describe("RBAC x ABAC precedence matrix (deny-overrides, the default)", () => {
    it("denies when a role is granted but an explicit policy denies", async () => {
      const gate = new RecordingRolePermissionGate(roleDecision("grant"));
      const pdp = new RecordingPolicyDecisionPoint(evaluation("DENY"));
      const service = new AuthorizationService(gate, pdp);

      const decision = await service.authorize(REQUEST);

      expect(decision).toEqual({
        effect: "DENY",
        source: "composition",
        reason: AUTHORIZATION_REASONS.abacDeny,
        matchedPolicyIds: ["policy-1"],
      });
      // The rule the threat model fixes is asserted, not assumed: an ABAC denial
      // is reachable for a subject who holds the role.
      expect(AUTHORIZATION_PRECEDENCE.abacDenyOverridesRbacPermit).toBe(true);
      expect(gate.requests).toHaveLength(1);
      expect(pdp.requests).toHaveLength(1);
    });

    it("permits when a role is granted and a policy also permits", async () => {
      const service = new AuthorizationService(
        new RecordingRolePermissionGate(roleDecision("grant")),
        new RecordingPolicyDecisionPoint(evaluation("PERMIT")),
      );

      const decision = await service.authorize(REQUEST);

      expect(decision).toEqual({
        effect: "PERMIT",
        source: "composition",
        reason: AUTHORIZATION_REASONS.rbacGrant,
        matchedPolicyIds: ["policy-1"],
      });
    });

    it("keeps Phase 07 behaviour when the role grant is unrefined by any policy", async () => {
      const service = new AuthorizationService(
        new RecordingRolePermissionGate(roleDecision("grant")),
        new RecordingPolicyDecisionPoint(evaluation("NOT_APPLICABLE")),
      );

      const decision = await service.authorize(REQUEST);

      expect(decision).toEqual({
        effect: "PERMIT",
        source: "rbac",
        reason: AUTHORIZATION_REASONS.rbacGrant,
        matchedPolicyIds: [],
      });
    });

    it("treats a role denial as final and never consults the policy engine", async () => {
      const gate = new RecordingRolePermissionGate(roleDecision("deny"));
      const pdp = new RecordingPolicyDecisionPoint(evaluation("PERMIT"));
      const service = new AuthorizationService(gate, pdp);

      const decision = await service.authorize(REQUEST);

      expect(decision.effect).toBe("DENY");
      expect(decision.source).toBe("rbac");
      expect(decision.reason).toBe(AUTHORIZATION_REASONS.rbacDeny);
      expect(pdp.requests).toHaveLength(0);
    });

    it("denies when no role matches and a policy denies", async () => {
      const service = new AuthorizationService(
        new RecordingRolePermissionGate(roleDecision("no-match")),
        new RecordingPolicyDecisionPoint(evaluation("DENY")),
      );

      const decision = await service.authorize(REQUEST);

      expect(decision).toEqual({
        effect: "DENY",
        source: "abac",
        reason: AUTHORIZATION_REASONS.abacDeny,
        matchedPolicyIds: ["policy-1"],
      });
    });

    it("permits when no role matches and a policy permits", async () => {
      const service = new AuthorizationService(
        new RecordingRolePermissionGate(roleDecision("no-match")),
        new RecordingPolicyDecisionPoint(evaluation("PERMIT")),
      );

      const decision = await service.authorize(REQUEST);

      expect(decision).toEqual({
        effect: "PERMIT",
        source: "abac",
        reason: AUTHORIZATION_REASONS.abacPermit,
        matchedPolicyIds: ["policy-1"],
      });
    });

    it("default-denies when no role matches and no policy applies", async () => {
      const service = new AuthorizationService(
        new RecordingRolePermissionGate(roleDecision("no-match")),
        new RecordingPolicyDecisionPoint(evaluation("NOT_APPLICABLE")),
      );

      const decision = await service.authorize(REQUEST);

      expect(decision).toEqual({
        effect: AUTHORIZATION_PRECEDENCE.defaultEffectWhenNoPolicyMatches,
        source: "composition",
        reason: AUTHORIZATION_REASONS.noApplicablePolicy,
        matchedPolicyIds: [],
      });
    });
  });

  describe("precedence configuration", () => {
    it("defaults to the order the threat model mandates", () => {
      const service = new AuthorizationService(
        new RecordingRolePermissionGate(roleDecision("no-match")),
        new RecordingPolicyDecisionPoint(evaluation("NOT_APPLICABLE")),
      );

      expect(service.precedenceOrder).toEqual(AUTHORIZATION_PRECEDENCE);
      expect(AUTHORIZATION_PRECEDENCE.abacDenyOverridesRbacPermit).toBe(true);
      expect(AUTHORIZATION_PRECEDENCE.abacPermitOverridesRbacDeny).toBe(false);
      expect(AUTHORIZATION_PRECEDENCE.defaultEffectWhenNoPolicyMatches).toBe("DENY");
    });

    it("accepts a configuration that restates the mandated order", () => {
      expect(resolveAuthorizationPrecedence({ abacDenyOverridesRbacPermit: true })).toEqual(
        AUTHORIZATION_PRECEDENCE,
      );
    });

    it("refuses a configuration that would let a role grant outrank a policy denial", () => {
      // The `rbac-first` shortcut, expressed as configuration: cheap, and it
      // silently disables every policy denial for role holders. It must not boot.
      expect(() =>
        resolveAuthorizationPrecedence({ abacDenyOverridesRbacPermit: false }),
      ).toThrowError(UnsafeAuthorizationPrecedenceError);

      expect(() =>
        assertAuthorizationPrecedenceIsSafe({
          ...AUTHORIZATION_PRECEDENCE,
          abacDenyOverridesRbacPermit: false,
        }),
      ).toThrowError("abacDenyOverridesRbacPermit must be true");
    });

    it("refuses a configuration that would let a policy rescue a role denial", () => {
      expect(() =>
        assertAuthorizationPrecedenceIsSafe({
          ...AUTHORIZATION_PRECEDENCE,
          abacPermitOverridesRbacDeny: true,
        }),
      ).toThrowError("abacPermitOverridesRbacDeny must be false");
    });

    it("refuses permit-by-default when nothing applies", () => {
      expect(() =>
        assertAuthorizationPrecedenceIsSafe({
          ...AUTHORIZATION_PRECEDENCE,
          defaultEffectWhenNoPolicyMatches: "PERMIT",
        }),
      ).toThrowError("defaultEffectWhenNoPolicyMatches must be DENY");
    });

    it("stops an unsafe service from being constructed at all", () => {
      expect(
        () =>
          new AuthorizationService(
            new RecordingRolePermissionGate(roleDecision("grant")),
            new RecordingPolicyDecisionPoint(evaluation("DENY")),
            { abacDenyOverridesRbacPermit: false },
          ),
      ).toThrowError(UnsafeAuthorizationPrecedenceError);
    });

    it("carries the resolved order on the service, so the composition root can log it", () => {
      const service = new AuthorizationService(
        new RecordingRolePermissionGate(roleDecision("grant")),
        new RecordingPolicyDecisionPoint(evaluation("DENY")),
      );

      expect(service.precedenceOrder).toEqual(AUTHORIZATION_PRECEDENCE);
    });
  });

  describe("fail-closed dependency handling", () => {
    it("denies when the role store is unavailable", async () => {
      const pdp = new RecordingPolicyDecisionPoint(evaluation("PERMIT"));
      const service = new AuthorizationService(
        new RecordingRolePermissionGate(new Error("permission store down")),
        pdp,
      );

      const decision = await service.authorize(REQUEST);

      expect(decision.effect).toBe("DENY");
      expect(decision.source).toBe("fail-closed");
      expect(decision.reason).toBe(AUTHORIZATION_REASONS.rbacUnavailable);
      expect(pdp.requests).toHaveLength(0);
    });

    it("denies with the documented reason when the policy repository is unavailable", async () => {
      const service = new AuthorizationService(
        new RecordingRolePermissionGate(roleDecision("grant")),
        new RecordingPolicyDecisionPoint(new Error("policy table unreachable")),
      );

      const decision = await service.authorize(REQUEST);

      expect(decision.effect).toBe("DENY");
      expect(decision.source).toBe("fail-closed");
      expect(decision.reason).toBe(AUTHORIZATION_REASONS.policyRepositoryUnavailable);
    });

    it("denies even when the role layer would have granted, if evaluation throws", async () => {
      const service = new AuthorizationService(
        new RecordingRolePermissionGate(roleDecision("grant")),
        new RecordingPolicyDecisionPoint(new Error("attribute provider timeout")),
      );

      const decision = await service.authorize(REQUEST);

      expect(decision.effect).toBe("DENY");
    });
  });

  describe("malformed requests", () => {
    const cases: ReadonlyArray<readonly [string, AuthorizationRequest, string]> = [
      [
        "empty subjectId",
        {
          ...REQUEST,
          subject: { subjectId: "  ", tenantId: "tenant-1" },
        },
        "subjectId is empty",
      ],
      [
        "empty tenantId",
        {
          ...REQUEST,
          subject: { subjectId: "user-1", tenantId: "" },
        },
        "tenantId is empty",
      ],
      ["empty action", { ...REQUEST, action: " " }, "action is empty"],
      [
        "empty resourceType",
        {
          ...REQUEST,
          resource: { resourceType: "" },
        },
        "resourceType is empty",
      ],
    ];

    it.each(cases)("denies %s before touching either layer", async (_name, request, detail) => {
      const gate = new RecordingRolePermissionGate(roleDecision("grant"));
      const pdp = new RecordingPolicyDecisionPoint(evaluation("PERMIT"));
      const service = new AuthorizationService(gate, pdp);

      const decision = await service.authorize(request);

      expect(decision.effect).toBe("DENY");
      expect(decision.source).toBe("fail-closed");
      expect(decision.reason).toBe(`${AUTHORIZATION_REASONS.invalidRequest}: ${detail}`);
      expect(gate.requests).toHaveLength(0);
      expect(pdp.requests).toHaveLength(0);
    });
  });

  it("passes an empty attribute context to the engine when the caller supplies none", async () => {
    const pdp = new RecordingPolicyDecisionPoint(evaluation("NOT_APPLICABLE"));
    const service = new AuthorizationService(
      new RecordingRolePermissionGate(roleDecision("no-match")),
      pdp,
    );

    await service.authorize({
      subject: REQUEST.subject,
      action: REQUEST.action,
      resource: REQUEST.resource,
    });

    expect(pdp.requests).toHaveLength(1);
    expect(pdp.requests[0]?.context).toEqual(emptyAttributeContext());
  });

  it("forwards the caller's attribute bags to the engine unchanged", async () => {
    const pdp = new RecordingPolicyDecisionPoint(evaluation("PERMIT"));
    const service = new AuthorizationService(
      new RecordingRolePermissionGate(roleDecision("no-match")),
      pdp,
    );

    await service.authorize({
      ...REQUEST,
      context: {
        subject: { clearance: "secret" },
        resource: { ownerId: "user-1" },
        action: { name: "document:read" },
        environment: { hour: 9 },
      },
    });

    expect(pdp.requests[0]?.context?.subject).toEqual({ clearance: "secret" });
    expect(pdp.requests[0]?.context?.environment).toEqual({ hour: 9 });
  });
});
