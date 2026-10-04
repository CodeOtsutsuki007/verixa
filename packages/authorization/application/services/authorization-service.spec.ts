import { describe, expect, it } from "vitest";

import { Policy } from "../../domain/entities/policy.js";
import { AttributeContext } from "../../domain/value-objects/attribute-context.js";
import { Condition } from "../../domain/value-objects/condition.js";
import { Rule } from "../../domain/value-objects/rule.js";
import { InMemoryPolicyRepository } from "../../infrastructure/fakes/in-memory-policy-repository.js";
import type { PolicyRepository } from "../ports/policy-repository.js";
import type { RbacAuthorizationPort, RbacDecision } from "../ports/rbac-authorization.js";
import { NoRbacGrants } from "../ports/rbac-authorization.js";

import { AuthorizationService } from "./authorization-service.js";

function stubRbac(decision: RbacDecision): RbacAuthorizationPort {
  return { checkGrant: () => Promise.resolve(decision) };
}

async function repositoryWith(effect: "PERMIT" | "DENY" | undefined): Promise<PolicyRepository> {
  const repository = new InMemoryPolicyRepository();
  if (effect !== undefined) {
    const created = Policy.create({
      name: "test-policy",
      target: { resourceType: "document", actions: ["read"] },
      rules: [Rule.create({ effect, condition: Condition.always() })],
    });
    if (created.kind === "err") {
      throw created.error;
    }
    await repository.save(created.value);
  }
  return repository;
}

const context = AttributeContext.create({});
const params = { subjectId: "user-1", action: "read", resourceType: "document", context };

describe("AuthorizationService.authorize", () => {
  it("RBAC PERMIT + ABAC PERMIT -> PERMIT", async () => {
    const service = new AuthorizationService(stubRbac("PERMIT"), await repositoryWith("PERMIT"));
    const result = await service.authorize(params);
    expect(result.effect).toBe("PERMIT");
  });

  it("RBAC PERMIT + ABAC DENY -> DENY (an applicable deny policy overrides an RBAC grant)", async () => {
    const service = new AuthorizationService(stubRbac("PERMIT"), await repositoryWith("DENY"));
    const result = await service.authorize(params);
    expect(result.effect).toBe("DENY");
  });

  it("RBAC DENY + ABAC PERMIT -> DENY (RBAC deny is authoritative)", async () => {
    const service = new AuthorizationService(stubRbac("DENY"), await repositoryWith("PERMIT"));
    const result = await service.authorize(params);
    expect(result.effect).toBe("DENY");
  });

  it("RBAC DENY + ABAC DENY -> DENY", async () => {
    const service = new AuthorizationService(stubRbac("DENY"), await repositoryWith("DENY"));
    const result = await service.authorize(params);
    expect(result.effect).toBe("DENY");
  });

  it("RBAC NOT_APPLICABLE + ABAC PERMIT -> PERMIT", async () => {
    const service = new AuthorizationService(
      stubRbac("NOT_APPLICABLE"),
      await repositoryWith("PERMIT"),
    );
    const result = await service.authorize(params);
    expect(result.effect).toBe("PERMIT");
  });

  it("RBAC NOT_APPLICABLE + ABAC DENY -> DENY", async () => {
    const service = new AuthorizationService(
      stubRbac("NOT_APPLICABLE"),
      await repositoryWith("DENY"),
    );
    const result = await service.authorize(params);
    expect(result.effect).toBe("DENY");
  });

  it("RBAC NOT_APPLICABLE + ABAC NOT_APPLICABLE -> DENY (fail-closed default)", async () => {
    const service = new AuthorizationService(
      stubRbac("NOT_APPLICABLE"),
      await repositoryWith(undefined),
    );
    const result = await service.authorize(params);
    expect(result.effect).toBe("DENY");
  });

  it("RBAC PERMIT + ABAC NOT_APPLICABLE -> PERMIT (RBAC-only decisions work unchanged from Phase 07 behavior)", async () => {
    const service = new AuthorizationService(stubRbac("PERMIT"), await repositoryWith(undefined));
    const result = await service.authorize(params);
    expect(result.effect).toBe("PERMIT");
  });

  it("RBAC DENY + ABAC NOT_APPLICABLE -> DENY (RBAC-only decisions work unchanged from Phase 07 behavior)", async () => {
    const service = new AuthorizationService(stubRbac("DENY"), await repositoryWith(undefined));
    const result = await service.authorize(params);
    expect(result.effect).toBe("DENY");
  });

  it("reports which policies actually matched", async () => {
    const repository = await repositoryWith("PERMIT");
    const service = new AuthorizationService(stubRbac("NOT_APPLICABLE"), repository);
    const result = await service.authorize(params);
    expect(result.matchedPolicyIds).toHaveLength(1);
  });

  it("reports no matched policies when none were applicable", async () => {
    const service = new AuthorizationService(stubRbac("PERMIT"), await repositoryWith(undefined));
    const result = await service.authorize(params);
    expect(result.matchedPolicyIds).toEqual([]);
  });

  it("integrates a real role check (NoRbacGrants) with a real policy", async () => {
    const repository = new InMemoryPolicyRepository();
    const created = Policy.create({
      name: "owners-may-read",
      target: { resourceType: "document", actions: ["read"] },
      rules: [
        Rule.create({
          effect: "PERMIT",
          condition: Condition.comparison("resource.ownerId", "eq", "user-1"),
        }),
      ],
    });
    if (created.kind === "err") {
      throw created.error;
    }
    await repository.save(created.value);

    const service = new AuthorizationService(new NoRbacGrants(), repository);

    const ownerResult = await service.authorize({
      ...params,
      context: AttributeContext.create({ resource: { ownerId: "user-1" } }),
    });
    expect(ownerResult.effect).toBe("PERMIT");

    const nonOwnerResult = await service.authorize({
      ...params,
      context: AttributeContext.create({ resource: { ownerId: "user-2" } }),
    });
    expect(nonOwnerResult.effect).toBe("DENY");
  });
});
