import type { PolicyRow, PrismaInputJsonValue } from "@verixa/database";
import { asId } from "@verixa/shared-kernel";

import { Policy } from "../../domain/entities/policy.js";
import type { Condition } from "../../domain/value-objects/condition.js";
import { Rule } from "../../domain/value-objects/rule.js";

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCondition(value: unknown): value is Condition {
  if (!isRecord(value)) return false;

  switch (value["kind"]) {
    case "always":
      return true;
    case "comparison":
      return (
        typeof value["attribute"] === "string" &&
        ["eq", "neq", "lt", "lte", "gt", "gte", "in", "contains"].includes(
          String(value["operator"]),
        ) &&
        (typeof value["value"] === "string" ||
          typeof value["value"] === "number" ||
          typeof value["value"] === "boolean" ||
          (Array.isArray(value["value"]) &&
            value["value"].every((item) => typeof item === "string" || typeof item === "number")))
      );
    case "and":
    case "or":
      return Array.isArray(value["operands"]) && value["operands"].every(isCondition);
    case "not":
      return isCondition(value["operand"]);
    default:
      return false;
  }
}

function rulesFromJson(value: unknown, policyId: string): Rule[] {
  if (!Array.isArray(value)) {
    throw new Error(`policies.id=${policyId} has a rules value that is not an array.`);
  }

  return value.map((rule, index) => {
    if (
      !isRecord(rule) ||
      (rule["effect"] !== "PERMIT" && rule["effect"] !== "DENY") ||
      !isCondition(rule["condition"]) ||
      (rule["description"] !== undefined && typeof rule["description"] !== "string")
    ) {
      throw new Error(`policies.id=${policyId} has an invalid rule at index ${index}.`);
    }

    return Rule.create({
      effect: rule["effect"],
      condition: rule["condition"],
      ...(typeof rule["description"] === "string" ? { description: rule["description"] } : {}),
    });
  });
}

export const PolicyMapper = {
  toDomain(row: PolicyRow): Policy {
    if (!Array.isArray(row.actions) || row.actions.some((action) => typeof action !== "string")) {
      throw new Error(`policies.id=${row.id} has an invalid actions selector.`);
    }

    return Policy.reconstitute({
      id: asId<"PolicyId">(row.id),
      name: row.name,
      target: { resourceType: row.resourceType, actions: Object.freeze([...row.actions]) },
      rules: Object.freeze(rulesFromJson(row.rules, row.id)),
      version: row.version,
      createdAt: row.createdAt,
      status: row.status,
      dslSource: row.dslSource ?? undefined,
    });
  },

  toRow(policy: Policy) {
    return {
      id: policy.id,
      version: policy.version,
      name: policy.name,
      resourceType: policy.target.resourceType,
      actions: [...policy.target.actions],
      rules: JSON.parse(
        JSON.stringify(
          policy.rules.map((rule) => ({
            effect: rule.effect,
            condition: rule.condition,
            ...(rule.description === undefined ? {} : { description: rule.description }),
          })),
        ),
      ) as PrismaInputJsonValue,
      dslSource: policy.dslSource ?? null,
      status: policy.status,
      createdAt: policy.createdAt,
    };
  },
};
