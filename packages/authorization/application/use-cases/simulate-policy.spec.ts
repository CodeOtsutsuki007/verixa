import { describe, expect, it } from "vitest";

import { emptyAttributeContext, type AttributeContext } from "../../domain/attribute-context.js";
import type { PolicyEffect } from "../../domain/authorization-decision.js";
import type {
  PolicySimulationEngine,
  PolicySimulationRun,
  PolicySource,
  SimulatedRuleOutcome,
} from "../ports/policy-simulation-engine.js";
import { SimulatePolicy, type PolicyFixtureSet } from "./simulate-policy.js";

/**
 * A policy engine that answers with whatever the test tells it, so the use case
 * can be exercised without a DSL, a repository or a database. It records its
 * calls, because half of what this use case must guarantee is what it *passes
 * through* (Issue 155).
 */
class StubPolicySimulationEngine implements PolicySimulationEngine {
  readonly calls: { policy: PolicySource; context: AttributeContext }[] = [];

  constructor(private readonly outcome: PolicySimulationRun | Error) {}

  async simulate(policy: PolicySource, context: AttributeContext): Promise<PolicySimulationRun> {
    this.calls.push({ policy, context });
    if (this.outcome instanceof Error) {
      throw this.outcome;
    }
    return this.outcome;
  }
}

const CONTEXT: AttributeContext = {
  subject: { subjectId: "user-1" },
  resource: { ownerId: "user-1" },
  action: { name: "document:read" },
  environment: { now: "2026-08-01T09:00:00Z" },
};

function rule(ruleId: string, effect: PolicyEffect, decisive: boolean): SimulatedRuleOutcome {
  return { ruleId, effect, decisive };
}

function run(effect: PolicyEffect, label = "document-access"): PolicySimulationRun {
  return {
    policyLabel: label,
    combinedEffect: effect,
    combiningAlgorithm: "deny-overrides",
    matchedPolicyIds: ["document-access"],
    rules: [rule("document-ownership", effect, true)],
  };
}

const STORED_POLICY: PolicySource = { kind: "stored", ref: "document-access" };

function fixtureSet(
  fixtures: PolicyFixtureSet["fixtures"],
  policy: PolicySource = STORED_POLICY,
): PolicyFixtureSet {
  return { policy, fixtures };
}

describe("SimulatePolicy", () => {
  it("passes a fixture whose expectation matches what the engine decided", async () => {
    const engine = new StubPolicySimulationEngine(run("PERMIT"));
    const simulate = new SimulatePolicy(engine);

    const result = await simulate.execute(
      fixtureSet([{ name: "owner may read", expectedEffect: "PERMIT", context: CONTEXT }]),
    );

    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") {
      return;
    }
    expect(result.value.success).toBe(true);
    expect(result.value.passed).toBe(1);
    expect(result.value.failed).toBe(0);
    expect(result.value.results).toHaveLength(1);
    expect(result.value.results[0]?.actualEffect).toBe("PERMIT");
  });

  it("reports a mismatch as a result rather than an error, keeping the run for explanation", async () => {
    const engine = new StubPolicySimulationEngine({
      ...run("PERMIT"),
      combiningAlgorithm: "deny-overrides",
      rules: [
        rule("document-ownership", "PERMIT", true),
        rule("document-suspension", "NOT_APPLICABLE", false),
      ],
    });
    const simulate = new SimulatePolicy(engine);

    const result = await simulate.execute(
      fixtureSet([{ name: "suspension wins", expectedEffect: "DENY", context: CONTEXT }]),
    );

    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") {
      return;
    }
    expect(result.value.success).toBe(false);
    expect(result.value.failed).toBe(1);
    const [first] = result.value.results;
    expect(first?.passed).toBe(false);
    expect(first?.expectedEffect).toBe("DENY");
    expect(first?.actualEffect).toBe("PERMIT");
    // The rule detail is what makes the failure actionable, so it has to survive
    // into the report rather than being discarded after the comparison.
    expect(first?.run.rules).toHaveLength(2);
    expect(first?.run.combiningAlgorithm).toBe("deny-overrides");
  });

  it("evaluates every fixture even after a mismatch, so one run reveals every disagreement", async () => {
    const engine = new StubPolicySimulationEngine(run("PERMIT"));
    const simulate = new SimulatePolicy(engine);

    const result = await simulate.execute(
      fixtureSet([
        { name: "first", expectedEffect: "PERMIT", context: CONTEXT },
        { name: "second", expectedEffect: "DENY", context: CONTEXT },
        { name: "third", expectedEffect: "NOT_APPLICABLE", context: CONTEXT },
      ]),
    );

    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") {
      return;
    }
    expect(engine.calls).toHaveLength(3);
    expect(result.value.passed).toBe(1);
    expect(result.value.failed).toBe(2);
  });

  it("hands each fixture's attribute context to the engine unchanged", async () => {
    const context: AttributeContext = {
      ...CONTEXT,
      resource: { ...CONTEXT.resource, sensitivity: "restricted" },
    };
    const engine = new StubPolicySimulationEngine(run("DENY"));
    const simulate = new SimulatePolicy(engine);

    await simulate.execute(fixtureSet([{ name: "restricted", expectedEffect: "DENY", context }]));

    expect(engine.calls[0]?.context).toEqual(context);
  });

  it("hands the policy source through unchanged, for both a stored ref and a draft", async () => {
    const engine = new StubPolicySimulationEngine(run("PERMIT"));
    const simulate = new SimulatePolicy(engine);
    const draft: PolicySource = {
      kind: "draft",
      label: "document-access-draft",
      dsl: "permit if resource.ownerId == subject.subjectId",
    };

    await simulate.execute(
      fixtureSet([{ name: "draft case", expectedEffect: "PERMIT", context: CONTEXT }], draft),
    );

    expect(engine.calls[0]?.policy).toEqual(draft);
  });

  it("labels the report with the engine's resolved policy, not the reference it was asked for", async () => {
    // A moving reference ("document-access") resolves to a version
    // ("document-access@7"); a report that printed the ref would hide which
    // version was actually simulated.
    const engine = new StubPolicySimulationEngine(run("PERMIT", "document-access@7"));
    const simulate = new SimulatePolicy(engine);

    const result = await simulate.execute(
      fixtureSet([{ name: "owner may read", expectedEffect: "PERMIT", context: CONTEXT }]),
    );

    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") {
      return;
    }
    expect(result.value.policyLabel).toBe("document-access@7");
  });

  it("treats an empty fixture set as invalid rather than as a green run", async () => {
    const engine = new StubPolicySimulationEngine(run("PERMIT"));
    const simulate = new SimulatePolicy(engine);

    const result = await simulate.execute(fixtureSet([]));

    expect(result.kind).toBe("err");
    if (result.kind !== "err") {
      return;
    }
    expect(result.error.fieldErrors["fixtures"]).toBeDefined();
    // Nothing to evaluate means nothing to ask the engine.
    expect(engine.calls).toHaveLength(0);
  });

  it("rejects duplicate fixture names, which would make a result ambiguous", async () => {
    const engine = new StubPolicySimulationEngine(run("PERMIT"));
    const simulate = new SimulatePolicy(engine);

    const result = await simulate.execute(
      fixtureSet([
        { name: "owner may read", expectedEffect: "PERMIT", context: CONTEXT },
        { name: "owner may read", expectedEffect: "DENY", context: CONTEXT },
      ]),
    );

    expect(result.kind).toBe("err");
    if (result.kind !== "err") {
      return;
    }
    expect(result.error.fieldErrors["fixtures[1].name"]).toBeDefined();
    expect(engine.calls).toHaveLength(0);
  });

  it("rejects a blank fixture name", async () => {
    const engine = new StubPolicySimulationEngine(run("PERMIT"));
    const simulate = new SimulatePolicy(engine);

    const result = await simulate.execute(
      fixtureSet([{ name: "   ", expectedEffect: "PERMIT", context: CONTEXT }]),
    );

    expect(result.kind).toBe("err");
    if (result.kind !== "err") {
      return;
    }
    expect(result.error.fieldErrors["fixtures[0].name"]).toBeDefined();
  });

  it("rejects a draft with no DSL source and a stored ref with no reference", async () => {
    const engine = new StubPolicySimulationEngine(run("PERMIT"));
    const simulate = new SimulatePolicy(engine);
    const fixtures = [
      { name: "owner may read", expectedEffect: "PERMIT" as const, context: CONTEXT },
    ];

    const emptyDraft = await simulate.execute(
      fixtureSet(fixtures, { kind: "draft", label: "draft", dsl: "  " }),
    );
    const emptyRef = await simulate.execute(fixtureSet(fixtures, { kind: "stored", ref: "" }));

    expect(emptyDraft.kind).toBe("err");
    expect(emptyRef.kind).toBe("err");
    if (emptyDraft.kind === "err") {
      expect(emptyDraft.error.fieldErrors["policy.dsl"]).toBeDefined();
    }
    if (emptyRef.kind === "err") {
      expect(emptyRef.error.fieldErrors["policy.ref"]).toBeDefined();
    }
    expect(engine.calls).toHaveLength(0);
  });

  it("collects every validation problem in one message instead of stopping at the first", async () => {
    const engine = new StubPolicySimulationEngine(run("PERMIT"));
    const simulate = new SimulatePolicy(engine);

    const result = await simulate.execute(
      fixtureSet([
        { name: "", expectedEffect: "PERMIT", context: emptyAttributeContext() },
        { name: "duplicate", expectedEffect: "PERMIT", context: emptyAttributeContext() },
        { name: "duplicate", expectedEffect: "DENY", context: emptyAttributeContext() },
      ]),
    );

    expect(result.kind).toBe("err");
    if (result.kind !== "err") {
      return;
    }
    expect(result.error.fieldErrors["fixtures[0].name"]).toBeDefined();
    expect(result.error.fieldErrors["fixtures[2].name"]).toBeDefined();
  });

  it("lets an unreachable engine throw, so it cannot be mistaken for a policy mismatch", async () => {
    const engine = new StubPolicySimulationEngine(new Error("policy store unreachable"));
    const simulate = new SimulatePolicy(engine);

    const outcome = simulate.execute(
      fixtureSet([{ name: "owner may read", expectedEffect: "PERMIT", context: CONTEXT }]),
    );

    await expect(outcome).rejects.toThrowError("policy store unreachable");
  });
});
