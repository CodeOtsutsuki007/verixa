import { describe, expect, it } from "vitest";

import { Policy } from "../../domain/entities/policy.js";
import { Condition } from "../../domain/value-objects/condition.js";
import { Rule } from "../../domain/value-objects/rule.js";

import { PolicyMapper } from "./policy-mapper.js";

describe("PolicyMapper", () => {
  it("round-trips policy metadata and nested rule ASTs", () => {
    const created = Policy.create({
      name: "owner access",
      target: { resourceType: "document", actions: ["read", "download"] },
      rules: [
        Rule.create({
          effect: "PERMIT",
          condition: Condition.and([
            Condition.comparison("resource.ownerId", "eq", "subject.id"),
            Condition.not(Condition.comparison("resource.archived", "eq", true)),
          ]),
          description: "the owner can access active documents",
        }),
      ],
      status: "draft",
      dslSource: "permit if owner and not archived",
    });
    if (created.kind === "err") throw created.error;

    const persisted = PolicyMapper.toRow(created.value);
    const loaded = PolicyMapper.toDomain({
      ...persisted,
      rules: persisted.rules as never,
      status: "draft",
    });

    expect(loaded).toMatchObject({
      id: created.value.id,
      status: "draft",
      dslSource: "permit if owner and not archived",
      target: { resourceType: "document", actions: ["read", "download"] },
      rules: [
        {
          effect: "PERMIT",
          description: "the owner can access active documents",
          condition: {
            kind: "and",
            operands: [
              {
                kind: "comparison",
                attribute: "resource.ownerId",
                operator: "eq",
                value: "subject.id",
              },
              {
                kind: "not",
                operand: {
                  kind: "comparison",
                  attribute: "resource.archived",
                  operator: "eq",
                  value: true,
                },
              },
            ],
          },
        },
      ],
    });
  });

  it("fails loudly when persisted rule JSON is malformed", () => {
    const created = Policy.create({
      name: "broken",
      target: { resourceType: "document", actions: ["read"] },
      rules: [Rule.create({ effect: "DENY", condition: Condition.always() })],
    });
    if (created.kind === "err") throw created.error;
    const persisted = PolicyMapper.toRow(created.value);

    expect(() =>
      PolicyMapper.toDomain({
        ...persisted,
        rules: [{ effect: "ALLOW", condition: { kind: "always" } }] as never,
        status: "published",
      }),
    ).toThrow("has an invalid rule at index 0");
  });
});
