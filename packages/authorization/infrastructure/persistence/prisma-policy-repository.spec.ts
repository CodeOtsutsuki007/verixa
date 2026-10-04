import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { Policy } from "../../domain/entities/policy.js";
import { Condition } from "../../domain/value-objects/condition.js";
import { Rule } from "../../domain/value-objects/rule.js";
import { policyRepositoryContract } from "../testing/contracts/policy-repository.contract.js";
import { startTestDatabase, type TestDatabase } from "../testing/database-harness.js";

import { PrismaPolicyRepository } from "./prisma-policy-repository.js";

const database = await startTestDatabase();

describe.skipIf(database === undefined)("PrismaPolicyRepository (real Postgres)", () => {
  const db = database as TestDatabase;

  beforeAll(async () => {
    await db.prisma.$connect();
  }, 120_000);

  afterEach(async () => {
    await db.prisma.policy.deleteMany({});
  });

  afterAll(async () => {
    await db.stop();
  }, 120_000);

  policyRepositoryContract(() => new PrismaPolicyRepository(db.prisma));

  it("round-trips DSL source, status, selector, and the parsed rule tree", async () => {
    const created = Policy.create({
      name: "document readers",
      target: { resourceType: "document", actions: ["read"] },
      rules: [
        Rule.create({
          effect: "PERMIT",
          condition: Condition.comparison("resource.ownerId", "eq", "subject.id"),
          description: "owners may read their documents",
        }),
      ],
      status: "draft",
      dslSource: "permit if resource.ownerId == subject.id",
    });
    if (created.kind === "err") throw created.error;

    const repository = new PrismaPolicyRepository(db.prisma);
    await repository.save(created.value);
    const loaded = await repository.findById(created.value.id);

    expect(loaded).toMatchObject({
      id: created.value.id,
      name: "document readers",
      status: "draft",
      dslSource: "permit if resource.ownerId == subject.id",
      target: { resourceType: "document", actions: ["read"] },
      rules: [
        {
          effect: "PERMIT",
          condition: {
            kind: "comparison",
            attribute: "resource.ownerId",
            operator: "eq",
            value: "subject.id",
          },
          description: "owners may read their documents",
        },
      ],
    });
  });

  it("keeps a previously published row unchanged when a later version is saved", async () => {
    const first = Policy.create({
      name: "immutable history",
      target: { resourceType: "invoice", actions: ["read"] },
      rules: [Rule.create({ effect: "PERMIT", condition: Condition.always() })],
      dslSource: "permit if always",
    });
    if (first.kind === "err") throw first.error;

    const repository = new PrismaPolicyRepository(db.prisma);
    await repository.save(first.value);
    const before = await db.prisma.policy.findUniqueOrThrow({
      where: { id_version: { id: first.value.id, version: 1 } },
    });

    const second = first.value.publishNewVersion([
      Rule.create({ effect: "DENY", condition: Condition.always() }),
    ]);
    if (second.kind === "err") throw second.error;
    await repository.save(second.value);

    const after = await db.prisma.policy.findUniqueOrThrow({
      where: { id_version: { id: first.value.id, version: 1 } },
    });
    expect(after).toEqual(before);
    await expect(repository.listVersionsFor(first.value.id)).resolves.toHaveLength(2);
  });
});
