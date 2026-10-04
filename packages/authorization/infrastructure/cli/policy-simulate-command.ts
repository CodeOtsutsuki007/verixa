import { Result, ValidationError, ValidationErrorAggregator } from "@verixa/shared-kernel";

import type {
  PolicySimulationEngine,
  PolicySource,
  SimulatedRuleOutcome,
} from "../../application/ports/policy-simulation-engine.js";
import {
  SimulatePolicy,
  type PolicyFixture,
  type PolicyFixtureSet,
  type PolicySimulationReport,
  type SimulationFixtureResult,
} from "../../application/use-cases/simulate-policy.js";
import {
  emptyAttributeContext,
  type AttributeBag,
  type AttributeContext,
} from "../../domain/attribute-context.js";
import type { PolicyEffect } from "../../domain/authorization-decision.js";

/**
 * The `policy-simulate` command (Issue 155, roadmap 155).
 *
 * Lives in `packages/authorization/infrastructure/` rather than
 * `apps/cli/src/commands/` because `apps/cli` does not exist yet — this is the
 * same call the sibling tooling issue (roadmap 156, the policy linter) made for
 * the same reason. The command is written as an adapter with its I/O injected
 * ({@link PolicySimulateIo}), so it is a complete, testable command rather than a
 * stub: mounting it in the CLI application is then a matter of passing
 * `process.stdout.write` and `fs.readFile` and returning the exit code, with no
 * logic moving between layers.
 *
 * ## Exit codes are the CI contract
 *
 * Three outcomes, not two, because collapsing them is how a CI check starts
 * lying. `1` means the policy decided something its author did not expect — the
 * signal this tool exists to produce, and the one a pipeline should fail on.
 * `2` means the simulation never ran (unusable arguments, an unreadable or
 * malformed fixture file, an unreachable policy store): also a failure, but a
 * different one, and a reviewer reading the log needs to be able to tell them
 * apart. A malformed fixtures file reported as "policy mismatch" would send an
 * author hunting through rules for a bug that is a stray comma.
 */

export const POLICY_SIMULATE_EXIT_CODES = {
  /** Every fixture matched its expected effect. */
  matched: 0,
  /** At least one fixture disagreed with its expectation. */
  mismatched: 1,
  /** Nothing was decided: bad arguments, unusable fixtures, or an unreachable engine. */
  couldNotRun: 2,
} as const;

export type PolicySimulateFormat = "table" | "json";

/** Where the command gets its inputs and puts its output — injected, never imported. */
export interface PolicySimulateIo {
  readonly readFile: (path: string) => Promise<string>;
  readonly write: (line: string) => void;
}

export interface PolicySimulateOptions {
  readonly fixturesPath: string;
  readonly format: PolicySimulateFormat;
  /** `--policy <ref>`: simulate a stored policy, overriding the fixture file's `policy` block. */
  readonly policyRef?: string;
  /** `--dsl <path>`: simulate draft DSL source read from this file, overriding the fixture file. */
  readonly dslPath?: string;
  /** `--verbose`: explain every fixture, not only the failing ones. */
  readonly explainAll: boolean;
}

export const POLICY_SIMULATE_USAGE = [
  "usage: policy-simulate --fixtures <path> [--policy <ref> | --dsl <path>] [--format table|json] [--verbose]",
  "",
  "  --fixtures <path>  fixture file: the policy under test plus expected-effect fixtures",
  "  --policy <ref>     simulate a stored policy by reference, overriding the fixture file",
  "  --dsl <path>       simulate a draft policy from a DSL source file, overriding the fixture file",
  "  --format <format>  output format, `table` (default) or `json`",
  "  --verbose          explain the rules behind every fixture, including passing ones",
  "",
  "exit codes: 0 every fixture matched, 1 a fixture mismatched, 2 the simulation could not run",
].join("\n");

/** The fields a fixture file may carry, at each level — anything else is a typo. */
const FIXTURE_FILE_KEYS = ["policy", "fixtures"] as const;
const FIXTURE_KEYS = ["name", "expectedEffect", "context"] as const;
const POLICY_KEYS = ["kind", "ref", "label", "dsl"] as const;
const CONTEXT_AXES = ["subject", "resource", "action", "environment"] as const;
const POLICY_EFFECTS: readonly PolicyEffect[] = ["PERMIT", "DENY", "NOT_APPLICABLE"];

export class PolicySimulateCommand {
  private readonly useCase: SimulatePolicy;

  constructor(
    engine: PolicySimulationEngine,
    private readonly io: PolicySimulateIo,
  ) {
    this.useCase = new SimulatePolicy(engine);
  }

  /** Runs the command and returns the process exit code — see {@link POLICY_SIMULATE_EXIT_CODES}. */
  async run(argv: readonly string[]): Promise<number> {
    if (argv.includes("--help") || argv.includes("-h")) {
      this.io.write(POLICY_SIMULATE_USAGE);
      return POLICY_SIMULATE_EXIT_CODES.matched;
    }

    const options = parseArgv(argv);
    if (Result.isErr(options)) {
      this.io.write(`${options.error}\n\n${POLICY_SIMULATE_USAGE}`);
      return POLICY_SIMULATE_EXIT_CODES.couldNotRun;
    }

    const fixtureSet = await this.loadFixtureSet(options.value);
    if (Result.isErr(fixtureSet)) {
      this.io.write(renderValidationError(fixtureSet.error));
      return POLICY_SIMULATE_EXIT_CODES.couldNotRun;
    }

    let report: PolicySimulationReport;
    try {
      const simulated = await this.useCase.execute(fixtureSet.value);
      if (Result.isErr(simulated)) {
        this.io.write(renderValidationError(simulated.error));
        return POLICY_SIMULATE_EXIT_CODES.couldNotRun;
      }
      report = simulated.value;
    } catch (error) {
      // Deliberately not a mismatch: the policy was never decided, so reporting
      // it as one would tell the author their policy is wrong when the store is.
      this.io.write(`simulation could not run: ${errorText(error)}`);
      return POLICY_SIMULATE_EXIT_CODES.couldNotRun;
    }

    this.io.write(
      options.value.format === "json"
        ? renderJson(report)
        : renderTable(report, { explainAll: options.value.explainAll }),
    );

    return report.success
      ? POLICY_SIMULATE_EXIT_CODES.matched
      : POLICY_SIMULATE_EXIT_CODES.mismatched;
  }

  /** Reads, parses and validates the fixture file. Every failure here is `couldNotRun`. */
  private async loadFixtureSet(
    options: PolicySimulateOptions,
  ): Promise<Result<PolicyFixtureSet, ValidationError>> {
    const override = await this.resolvePolicyOverride(options);
    if (Result.isErr(override)) {
      return override;
    }

    let raw: string;
    try {
      raw = await this.io.readFile(options.fixturesPath);
    } catch (error) {
      return Result.err(
        validationError("fixtures", `Cannot read "${options.fixturesPath}": ${errorText(error)}`),
      );
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      return Result.err(
        validationError(
          "fixtures",
          `"${options.fixturesPath}" is not valid JSON: ${errorText(error)}`,
        ),
      );
    }

    return parseFixtureSet(
      parsed,
      override.value === undefined ? {} : { override: override.value },
    );
  }

  /**
   * Resolves `--policy` / `--dsl` into a {@link PolicySource}, or `undefined`
   * when the fixture file is to name its own policy.
   *
   * Reading the DSL file here rather than inside `parseFixtureSet` keeps that
   * function pure: it parses a document, it does not do I/O, which is what lets
   * the fixture format be unit-tested with plain objects.
   */
  private async resolvePolicyOverride(
    options: PolicySimulateOptions,
  ): Promise<Result<PolicySource | undefined, ValidationError>> {
    if (options.policyRef !== undefined) {
      return Result.ok({ kind: "stored", ref: options.policyRef });
    }
    if (options.dslPath === undefined) {
      return Result.ok(undefined);
    }

    try {
      const dsl = await this.io.readFile(options.dslPath);
      if (dsl.trim() === "") {
        return Result.err(
          validationError(
            "policy.dsl",
            `"${options.dslPath}" is empty; there is nothing to simulate.`,
          ),
        );
      }
      return Result.ok({ kind: "draft", label: draftLabel(options.dslPath), dsl });
    } catch (error) {
      return Result.err(
        validationError("policy.dsl", `Cannot read "${options.dslPath}": ${errorText(error)}`),
      );
    }
  }
}

/** Parses the command line. `--help` is handled before this runs. */
export function parseArgv(argv: readonly string[]): Result<PolicySimulateOptions, string> {
  let fixturesPath: string | undefined;
  let policyRef: string | undefined;
  let dslPath: string | undefined;
  let format: PolicySimulateFormat = "table";
  let explainAll = false;

  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];

    if (flag === "--verbose") {
      explainAll = true;
      continue;
    }

    if (flag === "--fixtures" || flag === "--policy" || flag === "--dsl" || flag === "--format") {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("--")) {
        return Result.err(`${flag} requires a value.`);
      }
      index += 1;

      if (flag === "--fixtures") {
        fixturesPath = value;
      } else if (flag === "--policy") {
        policyRef = value;
      } else if (flag === "--dsl") {
        dslPath = value;
      } else if (value === "table" || value === "json") {
        format = value;
      } else {
        return Result.err(`Unknown --format "${value}"; expected "table" or "json".`);
      }
      continue;
    }

    return Result.err(`Unknown argument "${String(flag)}".`);
  }

  if (fixturesPath === undefined) {
    return Result.err("--fixtures <path> is required.");
  }
  if (policyRef !== undefined && dslPath !== undefined) {
    return Result.err("--policy and --dsl are mutually exclusive; pass one.");
  }

  // `exactOptionalPropertyTypes` is on repo-wide, so an unused selector is an
  // omitted key rather than a key set to `undefined`.
  const base = { fixturesPath, format, explainAll };
  if (policyRef !== undefined) {
    return Result.ok({ ...base, policyRef });
  }
  if (dslPath !== undefined) {
    return Result.ok({ ...base, dslPath });
  }
  return Result.ok(base);
}

/**
 * Parses the fixture file into a typed {@link PolicyFixtureSet}.
 *
 * Strict about *shape* — an unknown key or a misspelled `expectedEffect` is an
 * error, because a fixture that silently ignored a key would still "pass" while
 * asserting something other than what its author wrote. Lenient about *context
 * axes*: a fixture that only exercises `resource` and `subject` may omit the
 * other two, which are then empty. Requiring all four would add noise to every
 * fixture to say "this axis is unused", and an empty bag is already the domain's
 * representation of "nothing resolved".
 */
export function parseFixtureSet(
  raw: unknown,
  options: { readonly override?: PolicySource } = {},
): Result<PolicyFixtureSet, ValidationError> {
  if (!isRecord(raw)) {
    return Result.err(validationError("fixtures", "The fixture file must contain a JSON object."));
  }

  const unexpected = unexpectedKeys(raw, FIXTURE_FILE_KEYS);
  if (unexpected.length > 0) {
    return Result.err(
      validationError(
        "fixtures",
        `Unknown top-level key(s): ${unexpected.join(", ")}. Expected ${FIXTURE_FILE_KEYS.join(
          " and ",
        )}.`,
      ),
    );
  }

  const policy =
    options.override !== undefined
      ? Result.ok<PolicySource>(options.override)
      : parsePolicySource(raw["policy"]);
  if (Result.isErr(policy)) {
    return policy;
  }

  const fixtures = parseFixtures(raw["fixtures"]);
  if (Result.isErr(fixtures)) {
    return fixtures;
  }

  return Result.ok({ policy: policy.value, fixtures: fixtures.value });
}

function parsePolicySource(raw: unknown): Result<PolicySource, ValidationError> {
  if (raw === undefined) {
    return Result.err(
      validationError(
        "policy",
        "No policy given: add a `policy` block to the fixture file, or pass --policy <ref> / --dsl <path>.",
      ),
    );
  }
  if (!isRecord(raw)) {
    return Result.err(validationError("policy", "`policy` must be an object."));
  }

  const unexpected = unexpectedKeys(raw, POLICY_KEYS);
  if (unexpected.length > 0) {
    return Result.err(
      validationError("policy", `Unknown policy key(s): ${unexpected.join(", ")}.`),
    );
  }

  const kind = raw["kind"];
  if (kind === "stored") {
    const ref = raw["ref"];
    if (typeof ref !== "string" || ref.trim() === "") {
      return Result.err(validationError("policy.ref", "A stored policy needs a non-empty `ref`."));
    }
    return Result.ok({ kind: "stored", ref });
  }

  if (kind === "draft") {
    const label = raw["label"];
    const dsl = raw["dsl"];
    if (typeof label !== "string" || label.trim() === "") {
      return Result.err(
        validationError("policy.label", "A draft policy needs a non-empty `label`."),
      );
    }
    if (typeof dsl !== "string" || dsl.trim() === "") {
      return Result.err(
        validationError("policy.dsl", "A draft policy needs non-empty `dsl` source."),
      );
    }
    return Result.ok({ kind: "draft", label, dsl });
  }

  return Result.err(
    validationError(
      "policy.kind",
      '`policy.kind` must be "stored" (a published policy ref) or "draft".',
    ),
  );
}

function parseFixtures(raw: unknown): Result<PolicyFixture[], ValidationError> {
  if (!Array.isArray(raw)) {
    return Result.err(
      validationError("fixtures", "`fixtures` must be an array of fixture objects."),
    );
  }

  const errors = new ValidationErrorAggregator();
  const parsed: PolicyFixture[] = [];

  raw.forEach((entry, index) => {
    const field = `fixtures[${index}]`;

    if (!isRecord(entry)) {
      errors.merge({ [field]: ["Each fixture must be an object."] });
      return;
    }

    const unexpected = unexpectedKeys(entry, FIXTURE_KEYS);
    if (unexpected.length > 0) {
      errors.merge({
        [`${field}.unknown`]: [`Unknown field(s): ${unexpected.join(", ")} — check for a typo.`],
      });
    }

    const name = entry["name"];
    if (typeof name !== "string" || name.trim() === "") {
      errors.merge({ [`${field}.name`]: ["`name` must be a non-empty string."] });
    }

    const expectedEffect = entry["expectedEffect"];
    if (!isPolicyEffect(expectedEffect)) {
      errors.merge({
        [`${field}.expectedEffect`]: [
          "`expectedEffect` must be one of PERMIT, DENY, NOT_APPLICABLE (quoted).",
        ],
      });
    }

    const context = parseContext(entry["context"], field);
    if (Result.isErr(context)) {
      errors.merge(context.error.fieldErrors);
      return;
    }

    if (
      typeof name === "string" &&
      name.trim() !== "" &&
      isPolicyEffect(expectedEffect) &&
      Result.isOk(context)
    ) {
      parsed.push({ name, expectedEffect, context: context.value });
    }
  });

  if (errors.hasErrors()) {
    return Result.err(errors.toError("Invalid fixture file."));
  }
  return Result.ok(parsed);
}

function parseContext(raw: unknown, field: string): Result<AttributeContext, ValidationError> {
  if (raw === undefined) {
    return Result.ok(emptyAttributeContext());
  }
  if (!isRecord(raw)) {
    return Result.err(
      validationError(`${field}.context`, "`context` must be an object of attribute bags."),
    );
  }

  const unexpected = unexpectedKeys(raw, CONTEXT_AXES);
  if (unexpected.length > 0) {
    return Result.err(
      validationError(
        `${field}.context`,
        `Unknown context axis/axes: ${unexpected.join(", ")}. Expected any of ${CONTEXT_AXES.join(
          ", ",
        )}.`,
      ),
    );
  }

  const errors = new ValidationErrorAggregator();
  const bags: Record<(typeof CONTEXT_AXES)[number], AttributeBag> = {
    subject: {},
    resource: {},
    action: {},
    environment: {},
  };

  for (const axis of CONTEXT_AXES) {
    const bag = raw[axis];
    if (bag === undefined) {
      continue;
    }
    if (!isRecord(bag)) {
      errors.merge({
        [`${field}.context.${axis}`]: [`\`${axis}\` must be an object of attributes.`],
      });
      continue;
    }
    bags[axis] = bag;
  }

  if (errors.hasErrors()) {
    return Result.err(errors.toError("Invalid fixture context."));
  }

  return Result.ok({
    subject: bags.subject,
    resource: bags.resource,
    action: bags.action,
    environment: bags.environment,
  });
}

/**
 * Renders the report as a fixed-width table.
 *
 * Column widths come from the content, never from the terminal: this output is
 * compared byte-for-byte in the spec and pasted into CI logs and issue comments,
 * and a table that re-wraps itself per $COLUMNS is neither testable nor
 * diff-friendly.
 */
export function renderTable(
  report: PolicySimulationReport,
  options: { readonly explainAll: boolean },
): string {
  const headers = ["fixture", "expected", "actual", "rules", "result"] as const;
  const rows = report.results.map((result) => [
    result.name,
    result.expectedEffect,
    result.actualEffect,
    `${matchedRuleCount(result)}/${result.run.rules.length}`,
    result.passed ? "PASS" : "FAIL",
  ]);

  const widths = headers.map((header, column) =>
    Math.max(header.length, ...rows.map((row) => (row[column] ?? "").length)),
  );
  const line = (cells: readonly string[]): string =>
    cells
      .map((cell, column) => cell.padEnd(widths[column] ?? 0))
      .join("  ")
      .trimEnd();

  const outline = widths.map((width) => "-".repeat(width)).join("  ");
  const lines = [
    `policy ${report.policyLabel}`,
    "",
    line(headers),
    outline,
    ...rows.map(line),
    "",
    summaryLine(report),
  ];

  const explained = report.results.filter((result) => options.explainAll || !result.passed);
  for (const result of explained) {
    lines.push("", ...explainFixture(result));
  }

  return lines.join("\n");
}

/** Machine-readable form, for a pipeline that wants to gate on more than the exit code. */
export function renderJson(report: PolicySimulationReport): string {
  return JSON.stringify(report, null, 2);
}

function summaryLine(report: PolicySimulationReport): string {
  const total = report.results.length;
  return `${total} fixture${total === 1 ? "" : "s"} — ${report.passed} passed, ${
    report.failed
  } failed`;
}

/**
 * The rules behind one fixture.
 *
 * Printed for failures by default because a mismatch is only actionable with
 * them: "expected DENY, got PERMIT" is a symptom, and the rule that said PERMIT
 * while the `deny-overrides` step failed to override it is the diagnosis.
 */
function explainFixture(result: SimulationFixtureResult): string[] {
  const outcome =
    result.expectedEffect === result.actualEffect
      ? `resolved to ${result.actualEffect}`
      : `resolved to ${result.actualEffect}, expected ${result.expectedEffect}`;

  const lines = [`rules for "${result.name}" — ${result.run.combiningAlgorithm} ${outcome}:`];
  if (result.run.rules.length === 0) {
    lines.push("  (no rules evaluated — check the policy targets this action/resource)");
  }
  for (const rule of result.run.rules) {
    lines.push(`  ${rule.ruleId.padEnd(28)} ${rule.effect.padEnd(15)} ${describeRule(rule)}`);
  }
  return lines;
}

function describeRule(rule: SimulatedRuleOutcome): string {
  if (rule.decisive) {
    return "decisive";
  }
  return rule.effect === "NOT_APPLICABLE" ? "did not match" : "overridden by the combining step";
}

/** Rules whose condition matched. Reported next to the total so "0/3" reads as "the policy never applied". */
function matchedRuleCount(result: SimulationFixtureResult): number {
  return result.run.rules.filter((rule) => rule.effect !== "NOT_APPLICABLE").length;
}

function renderValidationError(error: ValidationError): string {
  const fields = Object.entries(error.fieldErrors);
  if (fields.length === 0) {
    return error.message;
  }
  return [
    error.message,
    ...fields.map(([field, messages]) => `  ${field}: ${messages.join(" ")}`),
  ].join("\n");
}

function validationError(field: string, message: string): ValidationError {
  return new ValidationError("Invalid policy simulation input.", { [field]: [message] });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPolicyEffect(value: unknown): value is PolicyEffect {
  return typeof value === "string" && POLICY_EFFECTS.includes(value as PolicyEffect);
}

function unexpectedKeys(record: Record<string, unknown>, allowed: readonly string[]): string[] {
  return Object.keys(record).filter((key) => !allowed.includes(key));
}

/** The file's own name, minus directory and extension, is the most useful label a draft can have. */
function draftLabel(path: string): string {
  const file = path.split("/").pop() ?? path;
  return file.replace(/\.(policy|txt|dsl)$/i, "");
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
