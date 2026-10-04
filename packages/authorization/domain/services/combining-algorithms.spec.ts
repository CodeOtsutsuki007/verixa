import { describe, expect, it } from "vitest";

import { AttributeContext } from "../value-objects/attribute-context.js";
import { Condition } from "../value-objects/condition.js";
import { Rule } from "../value-objects/rule.js";

import {
  deriveRuleOutcomes,
  denyOverrides,
  firstApplicable,
  permitOverrides,
  type RuleOutcome,
} from "./combining-algorithms.js";

describe("deriveRuleOutcomes", () => {
  it("maps a matching rule to its effect and a non-matching rule to NOT_APPLICABLE", () => {
    const context = AttributeContext.create({ subject: { role: "guest" } });
    const rules = [
      Rule.create({
        effect: "PERMIT",
        condition: Condition.comparison("subject.role", "eq", "admin"),
      }),
      Rule.create({ effect: "DENY", condition: Condition.always() }),
    ];

    expect(deriveRuleOutcomes(rules, context)).toEqual(["NOT_APPLICABLE", "DENY"]);
  });
});

describe("denyOverrides", () => {
  it.each`
    outcomes                                | expected
    ${["PERMIT", "DENY"]}                   | ${"DENY"}
    ${["PERMIT", "PERMIT"]}                 | ${"PERMIT"}
    ${["DENY", "DENY"]}                     | ${"DENY"}
    ${["NOT_APPLICABLE", "NOT_APPLICABLE"]} | ${"NOT_APPLICABLE"}
    ${["NOT_APPLICABLE", "PERMIT"]}         | ${"PERMIT"}
  `(
    "reduces $outcomes to $expected",
    ({ outcomes, expected }: { outcomes: RuleOutcome[]; expected: RuleOutcome }) => {
      expect(denyOverrides(outcomes)).toBe(expected);
    },
  );
});

describe("permitOverrides", () => {
  it.each`
    outcomes                                | expected
    ${["PERMIT", "DENY"]}                   | ${"PERMIT"}
    ${["DENY", "DENY"]}                     | ${"DENY"}
    ${["NOT_APPLICABLE", "NOT_APPLICABLE"]} | ${"NOT_APPLICABLE"}
  `(
    "reduces $outcomes to $expected",
    ({ outcomes, expected }: { outcomes: RuleOutcome[]; expected: RuleOutcome }) => {
      expect(permitOverrides(outcomes)).toBe(expected);
    },
  );
});

describe("firstApplicable", () => {
  it("returns the first non-NOT_APPLICABLE outcome, ignoring order beyond it", () => {
    expect(firstApplicable(["NOT_APPLICABLE", "DENY", "PERMIT"])).toBe("DENY");
    expect(firstApplicable(["PERMIT", "DENY"])).toBe("PERMIT");
  });

  it("returns NOT_APPLICABLE when every rule is NOT_APPLICABLE", () => {
    expect(firstApplicable(["NOT_APPLICABLE", "NOT_APPLICABLE"])).toBe("NOT_APPLICABLE");
  });

  it("returns NOT_APPLICABLE for an empty outcome list", () => {
    expect(firstApplicable([])).toBe("NOT_APPLICABLE");
  });
});
