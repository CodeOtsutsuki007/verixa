import { createId } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { PolicyRepository } from "../../../application/ports/policy-repository.js";
import { Policy } from "../../../domain/entities/policy.js";
import { Condition } from "../../../domain/value-objects/condition.js";
import { Rule } from "../../../domain/value-objects/rule.js";

function aPolicy(overrides?: {
  name?: string;
  resourceType?: string;
  actions?: readonly string[];
}): Policy {
  const created = Policy.create({
    name: overrides?.name ?? "a-policy",
    target: {
      resourceType: overrides?.resourceType ?? "document",
      actions: overrides?.actions ?? ["read"],
    },
    rules: [Rule.create({ effect: "PERMIT", condition: Condition.always() })],
  });
  if (created.kind === "err") {
    throw created.error;
  }
  return created.value;
}

/**
 * Shared contract every {@link PolicyRepository} implementation — the
 * in-memory fake here, and the Prisma-backed adapter in Issue 150 — must
 * satisfy identically. See `packages/identity/infrastructure/testing/` for
 * the established pattern this follows (Issue 031).
 */
export function policyRepositoryContract(createRepository: () => PolicyRepository): void {
  describe("PolicyRepository contract", () => {
    it("returns undefined for a policy that was never saved", async () => {
      const repository = createRepository();
      await expect(repository.findById(createId<"PolicyId">())).resolves.toBeUndefined();
    });

    it("finds a saved policy by id", async () => {
      const repository = createRepository();
      const policy = aPolicy();

      await repository.save(policy);
      const found = await repository.findById(policy.id);

      expect(found?.id).toBe(policy.id);
      expect(found?.name).toBe(policy.name);
      expect(found?.version).toBe(1);
    });

    it("save is idempotent for the same (id, version) pair", async () => {
      const repository = createRepository();
      const policy = aPolicy();

      await repository.save(policy);
      await repository.save(policy);

      const versions = await repository.listVersionsFor(policy.id);
      expect(versions).toHaveLength(1);
    });

    it("findById returns the latest version once a new one is published", async () => {
      const repository = createRepository();
      const v1 = aPolicy();
      await repository.save(v1);

      const publish = v1.publishNewVersion([
        Rule.create({ effect: "DENY", condition: Condition.always() }),
      ]);
      if (publish.kind === "err") {
        throw publish.error;
      }
      await repository.save(publish.value);

      const found = await repository.findById(v1.id);
      expect(found?.version).toBe(2);
    });

    it("listVersionsFor returns every version, oldest first, and an empty list for an unknown id", async () => {
      const repository = createRepository();
      const v1 = aPolicy();
      await repository.save(v1);

      const publish = v1.publishNewVersion([
        Rule.create({ effect: "DENY", condition: Condition.always() }),
      ]);
      if (publish.kind === "err") {
        throw publish.error;
      }
      await repository.save(publish.value);

      const versions = await repository.listVersionsFor(v1.id);
      expect(versions.map((version) => version.version)).toEqual([1, 2]);

      await expect(repository.listVersionsFor(createId<"PolicyId">())).resolves.toEqual([]);
    });

    it("findApplicableTo matches on resource type and action", async () => {
      const repository = createRepository();
      const matching = aPolicy({ resourceType: "document", actions: ["read", "write"] });
      const wrongResourceType = aPolicy({ resourceType: "invoice", actions: ["read"] });
      const wrongAction = aPolicy({ resourceType: "document", actions: ["delete"] });

      await repository.save(matching);
      await repository.save(wrongResourceType);
      await repository.save(wrongAction);

      const applicable = await repository.findApplicableTo("document", "read");
      expect(applicable.map((policy) => policy.id)).toEqual([matching.id]);
    });

    it("findApplicableTo considers only the latest version of a policy", async () => {
      const repository = createRepository();
      const v1 = aPolicy({ resourceType: "document", actions: ["read"] });
      await repository.save(v1);

      const publish = v1.publishNewVersion([
        Rule.create({ effect: "DENY", condition: Condition.always() }),
      ]);
      if (publish.kind === "err") {
        throw publish.error;
      }
      await repository.save(publish.value);

      const applicable = await repository.findApplicableTo("document", "read");
      expect(applicable).toHaveLength(1);
      expect(applicable[0]?.version).toBe(2);
    });

    it("findApplicableTo returns no results for a resource type with no policies", async () => {
      const repository = createRepository();
      const results = await repository.findApplicableTo("nonexistent-resource-type", "read");
      expect(results).toEqual([]);
    });

    it("does not return draft or archived policies for authorization", async () => {
      const repository = createRepository();
      const draft = Policy.create({
        name: "draft",
        target: { resourceType: "document", actions: ["read"] },
        rules: [Rule.create({ effect: "PERMIT", condition: Condition.always() })],
        status: "draft",
      });
      const archived = Policy.create({
        name: "archived",
        target: { resourceType: "document", actions: ["read"] },
        rules: [Rule.create({ effect: "PERMIT", condition: Condition.always() })],
        status: "archived",
      });
      if (draft.kind === "err") throw draft.error;
      if (archived.kind === "err") throw archived.error;
      await repository.save(draft.value);
      await repository.save(archived.value);

      await expect(repository.findApplicableTo("document", "read")).resolves.toEqual([]);
    });

    it("does not fall back to a published version when the latest version is archived", async () => {
      const repository = createRepository();
      const published = aPolicy();
      await repository.save(published);
      const archived = Policy.reconstitute({
        ...published,
        version: published.version + 1,
        status: "archived",
      });
      await repository.save(archived);

      await expect(repository.findApplicableTo("document", "read")).resolves.toEqual([]);
    });

    it("findApplicableTo can return multiple applicable policies", async () => {
      const repository = createRepository();
      const first = aPolicy({ name: "first", resourceType: "document", actions: ["read"] });
      const second = aPolicy({ name: "second", resourceType: "document", actions: ["read"] });

      await repository.save(first);
      await repository.save(second);

      const applicable = await repository.findApplicableTo("document", "read");
      expect(applicable.map((policy) => policy.id).sort()).toEqual([first.id, second.id].sort());
    });
  });
}
