import { Result, ValidationError, ValidationErrorAggregator } from "@verixa/shared-kernel";

import type { AttributeContext } from "../../domain/attribute-context.js";
import type { PolicyEffect } from "../../domain/authorization-decision.js";
import type {
  PolicySimulationEngine,
  PolicySimulationRun,
  PolicySource,
} from "../ports/policy-simulation-engine.js";

/**
 * Issue 155 (roadmap 155): evaluate a policy against author-supplied attribute
 * fixtures and report where it disagreed with what its author expected.
 *
 * The use case owns *the comparison*, and nothing else. It does not parse the
 * DSL, does not know what a condition is, and does not touch a database — all of
 * that arrives through {@link PolicySimulationEngine}. What it does own is the
 * judgement the tool exists to make: a fixture states an expected effect, the
 * engine states an actual one, and a run either agrees with its author or it
 * does not.
 *
 * ## Why this is a use case rather than a CLI script
 *
 * The alternative — doing the comparison inside the CLI command, iterating
 * fixtures and printing as it goes — was rejected for the usual reason and one
 * specific to this tool. The usual reason is testability: comparison logic in a
 * `console.log` loop is only testable through stdout. The specific one is that
 * *the report is the deliverable*: the CI exit code, the JSON output a pipeline
 * consumes and the table a human reads all have to be derived from the same
 * structured result, or the three drift and a passing local run starts failing
 * in CI for reasons that are about the printer rather than the policy.
 *
 * So the shape is: {@link SimulatePolicy} returns a
 * {@link PolicySimulationReport}, and every renderer — table, JSON, exit code —
 * reads that same object.
 */

/** One fixture: a named attribute context plus the effect its author expects from it. */
export interface PolicyFixture {
  /**
   * What this case is about, in the author's words ("owner may read",
   * "suspended owner is denied"). It is the only thing tying a failing row in a
   * CI log to the scenario the author had in mind, so it is required and must be
   * unique within a set.
   */
  readonly name: string;
  /** What the policy is supposed to decide for {@link context}. */
  readonly expectedEffect: PolicyEffect;
  /** The attributes the policy will be evaluated against. */
  readonly context: AttributeContext;
}

/** A fixture set: the policy under test, plus the expectations to check it against. */
export interface PolicyFixtureSet {
  readonly policy: PolicySource;
  readonly fixtures: readonly PolicyFixture[];
}

/** One fixture's expectation paired with what the engine actually concluded. */
export interface SimulationFixtureResult {
  readonly name: string;
  readonly expectedEffect: PolicyEffect;
  readonly actualEffect: PolicyEffect;
  readonly passed: boolean;
  /** The full run, kept so a report can explain *why* a fixture failed. */
  readonly run: PolicySimulationRun;
}

/** The outcome of a whole dry run. */
export interface PolicySimulationReport {
  readonly policyLabel: string;
  readonly results: readonly SimulationFixtureResult[];
  readonly passed: number;
  readonly failed: number;
  /** True when every fixture matched its expectation. The CLI's exit code derives from this. */
  readonly success: boolean;
}

/**
 * Simulates a policy against a fixture set.
 *
 * Returns a `Result` rather than throwing for a fixture set that cannot be
 * interpreted — the fixtures are author input, and bad author input is an
 * expected failure, not an exceptional one. An engine that cannot be reached
 * still throws: that is infrastructure failing, and the caller must not be able
 * to mistake it for a policy mismatch.
 */
export class SimulatePolicy {
  constructor(private readonly engine: PolicySimulationEngine) {}

  async execute(
    fixtureSet: PolicyFixtureSet,
  ): Promise<Result<PolicySimulationReport, ValidationError>> {
    const invalid = validate(fixtureSet);
    if (invalid) {
      return Result.err(invalid);
    }

    const results: SimulationFixtureResult[] = [];
    for (const fixture of fixtureSet.fixtures) {
      const run = await this.engine.simulate(fixtureSet.policy, fixture.context);
      results.push({
        name: fixture.name,
        expectedEffect: fixture.expectedEffect,
        actualEffect: run.combinedEffect,
        passed: run.combinedEffect === fixture.expectedEffect,
        run,
      });
    }

    const passed = results.filter((result) => result.passed).length;

    return Result.ok({
      // The engine's own label wins over the caller's ref: an implementation may
      // resolve a moving reference ("document-access") to the version it actually
      // evaluated ("document-access@7"), and a report that printed the ref would
      // hide the difference between the two.
      policyLabel: results[0]?.run.policyLabel ?? describePolicy(fixtureSet.policy),
      results,
      passed,
      failed: results.length - passed,
      success: passed === results.length,
    });
  }
}

/** A fixture set that fails validation is reported with every problem at once. */
function validate(fixtureSet: PolicyFixtureSet): ValidationError | undefined {
  const errors = new ValidationErrorAggregator();

  if (fixtureSet.policy.kind === "stored" && fixtureSet.policy.ref.trim() === "") {
    errors.merge({ "policy.ref": ["A stored policy reference is required."] });
  }
  if (fixtureSet.policy.kind === "draft" && fixtureSet.policy.dsl.trim() === "") {
    errors.merge({
      "policy.dsl": ["A draft policy must contain DSL source; an empty draft evaluates nothing."],
    });
  }

  // An empty fixture set is a validation failure rather than a report with zero
  // passing and zero failing. A run that asserts nothing would otherwise exit 0
  // in CI and read exactly like a run that asserted everything correctly — the
  // one way this tool could be green and useless at the same time.
  if (fixtureSet.fixtures.length === 0) {
    errors.merge({
      fixtures: ["At least one fixture is required — a simulation with none asserts nothing."],
    });
  }

  const seen = new Set<string>();
  fixtureSet.fixtures.forEach((fixture, index) => {
    const field = `fixtures[${index}].name`;

    if (fixture.name.trim() === "") {
      errors.merge({ [field]: ["A fixture name is required."] });
    } else if (seen.has(fixture.name)) {
      errors.merge({
        [field]: [
          `Duplicate fixture name "${fixture.name}" — a duplicate makes it ambiguous which case a result belongs to.`,
        ],
      });
    } else {
      seen.add(fixture.name);
    }
  });

  return errors.hasErrors() ? errors.toError("Invalid policy fixture set.") : undefined;
}

/** Falls back to the caller's own words when no fixture ran to ask the engine for a label. */
function describePolicy(policy: PolicySource): string {
  return policy.kind === "stored" ? policy.ref : policy.label;
}
