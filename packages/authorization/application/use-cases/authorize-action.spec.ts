import { describe, expect, it } from "vitest";

import { Policy } from "../../domain/entities/policy.js";
import { Condition } from "../../domain/value-objects/condition.js";
import { Rule } from "../../domain/value-objects/rule.js";
import { InMemoryPolicyRepository } from "../../infrastructure/fakes/in-memory-policy-repository.js";
import { NoRbacGrants } from "../ports/rbac-authorization.js";
import type { RbacAuthorizationPort, RbacDecision } from "../ports/rbac-authorization.js";
import { AuthorizationService } from "../services/authorization-service.js";
import { ResourceAttributeResolverRegistry } from "../services/resource-attribute-resolver-registry.js";

import { AuthorizeAction } from "./authorize-action.js";

function stubRbac(decision: RbacDecision): RbacAuthorizationPort {
  return { checkGrant: () => Promise.resolve(decision) };
}

async function repositoryWithOwnerPolicy(): Promise<InMemoryPolicyRepository> {
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
  return repository;
}

describe("AuthorizeAction", () => {
  describe("grant path", () => {
    it("grants and reports the matching policy when a policy permits", async () => {
      const repository = await repositoryWithOwnerPolicy();
      const useCase = new AuthorizeAction(new AuthorizationService(new NoRbacGrants(), repository));

      const decision = await useCase.execute({
        subjectId: "user-1",
        action: "read",
        resourceType: "document",
        resourceId: "doc-1",
        resourceAttributes: { ownerId: "user-1" },
      });

      expect(decision.granted).toBe(true);
      expect(decision.reason).toContain("policy permits");
      expect(decision.matchedPolicyIds).toHaveLength(1);
      expect(decision.evaluatedAt).toBeInstanceOf(Date);
    });

    it("grants via RBAC and says so in the reason, with no matched policies", async () => {
      const useCase = new AuthorizeAction(
        new AuthorizationService(stubRbac("PERMIT"), new InMemoryPolicyRepository()),
      );

      const decision = await useCase.execute({
        subjectId: "user-1",
        action: "read",
        resourceType: "document",
        resourceId: "doc-1",
      });

      expect(decision.granted).toBe(true);
      expect(decision.reason).toContain("role/permission grant permits");
      expect(decision.matchedPolicyIds).toEqual([]);
    });
  });

  describe("deny path", () => {
    it("denies and names the matching policy when a policy denies", async () => {
      const repository = new InMemoryPolicyRepository();
      const created = Policy.create({
        name: "deny-locked",
        target: { resourceType: "document", actions: ["read"] },
        rules: [Rule.create({ effect: "DENY", condition: Condition.always() })],
      });
      if (created.kind === "err") {
        throw created.error;
      }
      await repository.save(created.value);

      const useCase = new AuthorizeAction(new AuthorizationService(stubRbac("PERMIT"), repository));
      const decision = await useCase.execute({
        subjectId: "user-1",
        action: "read",
        resourceType: "document",
        resourceId: "doc-1",
      });

      expect(decision.granted).toBe(false);
      expect(decision.reason).toContain("policy denies");
      expect(decision.matchedPolicyIds).toHaveLength(1);
    });

    it("denies via RBAC when RBAC denies and no policy applies", async () => {
      const useCase = new AuthorizeAction(
        new AuthorizationService(stubRbac("DENY"), new InMemoryPolicyRepository()),
      );

      const decision = await useCase.execute({
        subjectId: "user-1",
        action: "read",
        resourceType: "document",
        resourceId: "doc-1",
      });

      expect(decision.granted).toBe(false);
      expect(decision.reason).toContain("role/permission grant denies");
    });

    it("denies with the fail-closed default reason when neither RBAC nor ABAC has an opinion", async () => {
      const useCase = new AuthorizeAction(
        new AuthorizationService(new NoRbacGrants(), new InMemoryPolicyRepository()),
      );

      const decision = await useCase.execute({
        subjectId: "user-1",
        action: "read",
        resourceType: "document",
        resourceId: "doc-1",
      });

      expect(decision.granted).toBe(false);
      expect(decision.reason).toContain("fail-closed default");
      expect(decision.matchedPolicyIds).toEqual([]);
    });

    it("denies when the resource's attributes don't satisfy the policy's condition", async () => {
      const repository = await repositoryWithOwnerPolicy();
      const useCase = new AuthorizeAction(new AuthorizationService(new NoRbacGrants(), repository));

      const decision = await useCase.execute({
        subjectId: "user-2",
        action: "read",
        resourceType: "document",
        resourceId: "doc-2",
        resourceAttributes: { ownerId: "user-2" },
      });

      expect(decision.granted).toBe(false);
    });
  });

  describe("policy-error path", () => {
    it("denies and names the failure when resource-attribute resolution throws", async () => {
      const registry = new ResourceAttributeResolverRegistry();
      registry.register("document", {
        resolve: () => Promise.reject(new Error("upstream lookup failed")),
      });

      const useCase = new AuthorizeAction(
        new AuthorizationService(stubRbac("PERMIT"), new InMemoryPolicyRepository()),
        registry,
      );

      const decision = await useCase.execute({
        subjectId: "user-1",
        action: "read",
        resourceType: "document",
        resourceId: "doc-1",
      });

      expect(decision.granted).toBe(false);
      expect(decision.reason).toContain("could not resolve");
      expect(decision.reason).toContain("upstream lookup failed");
      expect(decision.matchedPolicyIds).toEqual([]);
    });

    it("resolves resource attributes automatically when a resolver is registered", async () => {
      const repository = await repositoryWithOwnerPolicy();
      const registry = new ResourceAttributeResolverRegistry();
      registry.register("document", { resolve: () => Promise.resolve({ ownerId: "user-1" }) });

      const useCase = new AuthorizeAction(
        new AuthorizationService(new NoRbacGrants(), repository),
        registry,
      );

      const decision = await useCase.execute({
        subjectId: "user-1",
        action: "read",
        resourceType: "document",
        resourceId: "doc-1",
      });

      expect(decision.granted).toBe(true);
    });

    it("proceeds with no resource attributes when no resolver is registered for the resource type", async () => {
      const registry = new ResourceAttributeResolverRegistry();
      const useCase = new AuthorizeAction(
        new AuthorizationService(stubRbac("PERMIT"), new InMemoryPolicyRepository()),
        registry,
      );

      const decision = await useCase.execute({
        subjectId: "user-1",
        action: "read",
        resourceType: "document",
        resourceId: "doc-1",
      });

      expect(decision.granted).toBe(true);
    });
  });
});
