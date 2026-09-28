import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

import type {
  PolicySimulationEngine,
  PolicySimulationRun,
  PolicySource,
} from "../../application/ports/policy-simulation-engine.js";
import type { PolicySimulationReport } from "../../application/use-cases/simulate-policy.js";
import type { AttributeContext } from "../../domain/attribute-context.js";
import type { PolicyEffect } from "../../domain/authorization-decision.js";
import {
  POLICY_SIMULATE_EXIT_CODES,
  POLICY_SIMULATE_USAGE,
  PolicySimulateCommand,
  parseArgv,
  parseFixtureSet,
  type PolicySimulateIo,
} from "./policy-simulate-command.js";

/**
 * The command's I/O, faked.
 *
 * `files` is the filesystem the command sees; a path that is not in it behaves
 * like an unreadable file. Everything the command writes is captured so the
 * specs can assert on the rendered table rather than on a spy's call count.
 */
class FakePolicySimulateIo implements PolicySimulateIo {
  readonly written: string[] = [];

  constructor(private readonly files: Record<string, string> = {}) {}

  async readFile(path: string): Promise<string> {
    const content = this.files[path];
    if (content === undefined) {
      throw new Error(`ENOENT: no such file or directory, open '${path}'`);
    }
    return content;
  }

  write(line: string): void {
    this.written.push(line);
  }

  get output(): string {
    return this.written.join("\n");
  }
}

/**
 * A miniature policy engine: "you may read what you own, unless you are
 * suspended". Small enough to hold in your head, complete enough to produce the
 * three outcomes the report has to distinguish (permit, deny by rule, deny by
 * absence of any matching rule).
 */
class OwnershipPolicySimulationEngine implements PolicySimulationEngine {
  readonly calls: { policy: PolicySource; context: AttributeContext }[] = [];

  async simulate(policy: PolicySource, context: AttributeContext): Promise<PolicySimulationRun> {
    this.calls.push({ policy, context });

    const owns = context.resource["ownerId"] === context.subject["subjectId"];
    const suspended = context.subject["suspended"] === true;
    const combinedEffect: PolicyEffect = suspended ? "DENY" : owns ? "PERMIT" : "DENY";

    const rules: { ruleId: string; effect: PolicyEffect; decisive: boolean }[] = [
      { ruleId: "document-ownership", effect: owns ? "PERMIT" : "NOT_APPLICABLE", decisive: false },
      {
        ruleId: "document-suspension",
        effect: suspended ? "DENY" : "NOT_APPLICABLE",
        decisive: false,
      },
    ];

    return {
      policyLabel: policy.kind === "stored" ? policy.ref : policy.label,
      combinedEffect,
      combiningAlgorithm: "deny-overrides",
      matchedPolicyIds: ["document-access"],
      rules: rules.map((rule) => ({ ...rule, decisive: rule.effect === combinedEffect })),
    };
  }
}

/** An engine whose only job is to record what the command passed it. */
class RecordingPolicySimulationEngine implements PolicySimulationEngine {
  readonly calls: { policy: PolicySource; context: AttributeContext }[] = [];

  constructor(
    private readonly effect: PolicyEffect = "PERMIT",
    private readonly label?: string,
  ) {}

  async simulate(policy: PolicySource, context: AttributeContext): Promise<PolicySimulationRun> {
    this.calls.push({ policy, context });
    return {
      policyLabel: this.label ?? (policy.kind === "stored" ? policy.ref : policy.label),
      combinedEffect: this.effect,
      combiningAlgorithm: "deny-overrides",
      matchedPolicyIds: [],
      rules: [],
    };
  }
}

/** Stands in for a policy store that cannot be reached — an infrastructure failure, not a mismatch. */
class UnreachablePolicySimulationEngine implements PolicySimulationEngine {
  simulate(): Promise<PolicySimulationRun> {
    return Promise.reject(new Error("policy store unreachable"));
  }
}

const STORED_POLICY = { kind: "stored", ref: "document-access" };

const OWNER_CONTEXT = {
  subject: { subjectId: "user-1" },
  resource: { ownerId: "user-1" },
  action: { name: "document:read" },
};

const STRANGER_CONTEXT = {
  subject: { subjectId: "user-3" },
  resource: { ownerId: "user-1" },
  action: { name: "document:read" },
};

const SUSPENDED_CONTEXT = {
  subject: { subjectId: "user-2", suspended: true },
  resource: { ownerId: "user-2" },
  action: { name: "document:read" },
};

const OWNER_FIXTURE = {
  name: "owner may read their own document",
  expectedEffect: "PERMIT",
  context: OWNER_CONTEXT,
};

const STRANGER_FIXTURE = {
  name: "a stranger is denied",
  expectedEffect: "DENY",
  context: STRANGER_CONTEXT,
};

const SUSPENDED_FIXTURE = {
  name: "suspension beats ownership",
  expectedEffect: "PERMIT",
  context: SUSPENDED_CONTEXT,
};

function fixtureFile(fixtures: readonly unknown[], policy: unknown = STORED_POLICY): string {
  return JSON.stringify(policy === null ? { fixtures } : { policy, fixtures });
}

async function run(
  engine: PolicySimulationEngine,
  argv: readonly string[],
  files: Record<string, string>,
): Promise<{ code: number; io: FakePolicySimulateIo }> {
  const io = new FakePolicySimulateIo(files);
  const code = await new PolicySimulateCommand(engine, io).run(argv);
  return { code, io };
}

describe("policy-simulate command", () => {
  it("prints a table per fixture and exits 0 when every expectation holds", async () => {
    const engine = new OwnershipPolicySimulationEngine();
    const { code, io } = await run(engine, ["--fixtures", "fixtures.json"], {
      "fixtures.json": fixtureFile([OWNER_FIXTURE, STRANGER_FIXTURE]),
    });

    expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.matched);
    expect(io.output).toBe(
      [
        "policy document-access",
        "",
        "fixture                            expected  actual  rules  result",
        "---------------------------------  --------  ------  -----  ------",
        "owner may read their own document  PERMIT    PERMIT  1/2    PASS",
        "a stranger is denied               DENY      DENY    0/2    PASS",
        "",
        "2 fixtures — 2 passed, 0 failed",
      ].join("\n"),
    );
  });

  it("exits 1 on a mismatch and explains the failing fixture without hiding the passing ones", async () => {
    const engine = new OwnershipPolicySimulationEngine();
    const { code, io } = await run(engine, ["--fixtures", "fixtures.json"], {
      "fixtures.json": fixtureFile([OWNER_FIXTURE, SUSPENDED_FIXTURE]),
    });

    expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.mismatched);
    expect(io.output).toBe(
      [
        "policy document-access",
        "",
        "fixture                            expected  actual  rules  result",
        "---------------------------------  --------  ------  -----  ------",
        "owner may read their own document  PERMIT    PERMIT  1/2    PASS",
        "suspension beats ownership         PERMIT    DENY    2/2    FAIL",
        "",
        "2 fixtures — 1 passed, 1 failed",
        "",
        'rules for "suspension beats ownership" — deny-overrides resolved to DENY, expected PERMIT:',
        "  document-ownership           PERMIT          overridden by the combining step",
        "  document-suspension          DENY            decisive",
      ].join("\n"),
    );
  });

  it("explains a deny-by-absence as a rule set that never matched", async () => {
    const engine = new OwnershipPolicySimulationEngine();
    const { io } = await run(engine, ["--fixtures", "fixtures.json"], {
      "fixtures.json": fixtureFile([{ ...STRANGER_FIXTURE, expectedEffect: "PERMIT" }]),
    });

    expect(io.output).toContain("  document-ownership");
    expect(io.output).toContain("did not match");
    expect(io.output).toContain("0/2");
  });

  it("says so when a policy reported no rules at all", async () => {
    // An empty rule list is what an unresolvable or mistargeted policy looks
    // like from here, and silently printing nothing would read like a policy
    // that evaluated cleanly.
    const engine = new RecordingPolicySimulationEngine("DENY");
    const { io } = await run(engine, ["--fixtures", "fixtures.json"], {
      "fixtures.json": fixtureFile([OWNER_FIXTURE]),
    });

    expect(io.output).toContain("(no rules evaluated");
  });

  it("only explains failing fixtures by default, and every fixture with --verbose", async () => {
    const engine = new OwnershipPolicySimulationEngine();
    const files = { "fixtures.json": fixtureFile([OWNER_FIXTURE, STRANGER_FIXTURE]) };

    const quiet = await run(engine, ["--fixtures", "fixtures.json"], files);
    const verbose = await run(engine, ["--fixtures", "fixtures.json", "--verbose"], files);

    expect(quiet.io.output).not.toContain("rules for");
    expect(verbose.io.output).toContain('rules for "owner may read their own document"');
    expect(verbose.io.output).toContain('rules for "a stranger is denied"');
  });

  it("emits the report as JSON when asked, so a pipeline can gate on more than the exit code", async () => {
    const engine = new OwnershipPolicySimulationEngine();
    const { code, io } = await run(engine, ["--fixtures", "fixtures.json", "--format", "json"], {
      "fixtures.json": fixtureFile([OWNER_FIXTURE, STRANGER_FIXTURE]),
    });

    expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.matched);
    const report = JSON.parse(io.output) as PolicySimulationReport;
    expect(report.policyLabel).toBe("document-access");
    expect(report.success).toBe(true);
    expect(report.passed).toBe(2);
    expect(report.results[0]?.actualEffect).toBe("PERMIT");
    expect(report.results[1]?.run.combiningAlgorithm).toBe("deny-overrides");
  });

  it("overrides the fixture file's policy with --policy", async () => {
    const engine = new RecordingPolicySimulationEngine();
    const { code } = await run(
      engine,
      ["--fixtures", "fixtures.json", "--policy", "document-access@7"],
      { "fixtures.json": fixtureFile([OWNER_FIXTURE]) },
    );

    expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.matched);
    expect(engine.calls[0]?.policy).toEqual({ kind: "stored", ref: "document-access@7" });
  });

  it("reads draft DSL from --dsl and labels it after the file", async () => {
    const engine = new RecordingPolicySimulationEngine();
    const { code } = await run(
      engine,
      ["--fixtures", "fixtures.json", "--dsl", "drafts/document-access.dsl"],
      {
        "fixtures.json": fixtureFile([OWNER_FIXTURE]),
        "drafts/document-access.dsl": "permit if resource.ownerId == subject.subjectId",
      },
    );

    expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.matched);
    expect(engine.calls[0]?.policy).toEqual({
      kind: "draft",
      label: "document-access",
      dsl: "permit if resource.ownerId == subject.subjectId",
    });
  });

  it("exits 2 rather than 1 when the engine cannot be reached", async () => {
    const { code, io } = await run(new UnreachablePolicySimulationEngine(), ["--fixtures", "f"], {
      f: fixtureFile([OWNER_FIXTURE]),
    });

    expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.couldNotRun);
    expect(io.output).toContain("policy store unreachable");
    expect(io.output).not.toContain("FAIL");
  });

  it("exits 2 for unusable arguments, and prints how to use the command", async () => {
    for (const argv of [
      [],
      ["--fixtures"],
      ["--fixtures", "f", "--format", "xml"],
      ["--fixtures", "f", "--wat"],
      ["--fixtures", "f", "--policy", "ref", "--dsl", "source.dsl"],
    ]) {
      const { code, io } = await run(new RecordingPolicySimulationEngine(), argv, { f: "{}" });
      expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.couldNotRun);
      expect(io.output).toContain(POLICY_SIMULATE_USAGE);
    }
  });

  it("exits 2 for an unreadable or malformed fixture file", async () => {
    const missing = await run(
      new RecordingPolicySimulationEngine(),
      ["--fixtures", "nope.json"],
      {},
    );
    expect(missing.code).toBe(POLICY_SIMULATE_EXIT_CODES.couldNotRun);
    expect(missing.io.output).toContain('Cannot read "nope.json"');

    const malformed = await run(new RecordingPolicySimulationEngine(), ["--fixtures", "f"], {
      f: "{ fixtures: [] }",
    });
    expect(malformed.code).toBe(POLICY_SIMULATE_EXIT_CODES.couldNotRun);
    expect(malformed.io.output).toContain("is not valid JSON");
  });

  it("exits 2 for an empty DSL file", async () => {
    const { code, io } = await run(
      new RecordingPolicySimulationEngine(),
      ["--fixtures", "f", "--dsl", "empty.dsl"],
      { f: fixtureFile([OWNER_FIXTURE]), "empty.dsl": "\n" },
    );

    expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.couldNotRun);
    expect(io.output).toContain('"empty.dsl" is empty');
  });

  it("exits 2 when the fixture file names no policy and none was passed", async () => {
    const { code, io } = await run(new RecordingPolicySimulationEngine(), ["--fixtures", "f"], {
      f: JSON.stringify({ fixtures: [OWNER_FIXTURE] }),
    });

    expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.couldNotRun);
    expect(io.output).toContain("No policy given");
  });

  it("exits 2 when the fixture file asserts nothing", async () => {
    const { code, io } = await run(new RecordingPolicySimulationEngine(), ["--fixtures", "f"], {
      f: fixtureFile([]),
    });

    expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.couldNotRun);
    expect(io.output).toContain("At least one fixture is required");
  });

  it("exits 2 and names the field for a misspelled fixture field", async () => {
    const { code, io } = await run(new RecordingPolicySimulationEngine(), ["--fixtures", "f"], {
      f: fixtureFile([{ name: "typo", expect: "PERMIT", context: OWNER_CONTEXT }]),
    });

    expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.couldNotRun);
    expect(io.output).toContain("Unknown field(s): expect");
    expect(io.output).toContain("expectedEffect");
  });

  it("exits 2 for an unknown expected effect and for an unknown context axis", async () => {
    const badEffect = await run(new RecordingPolicySimulationEngine(), ["--fixtures", "f"], {
      f: fixtureFile([{ ...OWNER_FIXTURE, expectedEffect: "ALLOW" }]),
    });
    expect(badEffect.code).toBe(POLICY_SIMULATE_EXIT_CODES.couldNotRun);
    expect(badEffect.io.output).toContain("expectedEffect");

    const badAxis = await run(new RecordingPolicySimulationEngine(), ["--fixtures", "f"], {
      f: fixtureFile([{ ...OWNER_FIXTURE, context: { principal: {} } }]),
    });
    expect(badAxis.code).toBe(POLICY_SIMULATE_EXIT_CODES.couldNotRun);
    expect(badAxis.io.output).toContain("Unknown context axis/axes: principal");
  });

  it("exits 2 for a misspelled top-level key", async () => {
    const { code, io } = await run(new RecordingPolicySimulationEngine(), ["--fixtures", "f"], {
      f: JSON.stringify({ policy: STORED_POLICY, fixture: [OWNER_FIXTURE] }),
    });

    expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.couldNotRun);
    expect(io.output).toContain("Unknown top-level key(s): fixture");
  });

  it("prints usage and exits 0 for --help", async () => {
    const { code, io } = await run(new RecordingPolicySimulationEngine(), ["--help"], {});

    expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.matched);
    expect(io.output).toBe(POLICY_SIMULATE_USAGE);
  });

  it("parses the fixture file's own policy block, stored or draft", async () => {
    const stored = parseFixtureSet({ policy: STORED_POLICY, fixtures: [OWNER_FIXTURE] });
    expect(stored.kind).toBe("ok");
    if (stored.kind === "ok") {
      expect(stored.value.policy).toEqual({ kind: "stored", ref: "document-access" });
    }

    const draft = parseFixtureSet({
      policy: { kind: "draft", label: "draft", dsl: "permit if true" },
      fixtures: [OWNER_FIXTURE],
    });
    expect(draft.kind).toBe("ok");
    if (draft.kind === "ok") {
      expect(draft.value.policy).toEqual({ kind: "draft", label: "draft", dsl: "permit if true" });
    }
  });

  it("defaults omitted context axes to empty bags instead of rejecting the fixture", async () => {
    const parsed = parseFixtureSet({
      policy: STORED_POLICY,
      fixtures: [{ ...OWNER_FIXTURE, context: { subject: { subjectId: "user-1" } } }],
    });

    expect(parsed.kind).toBe("ok");
    if (parsed.kind !== "ok") {
      return;
    }
    expect(parsed.value.fixtures[0]?.context).toEqual({
      subject: { subjectId: "user-1" },
      resource: {},
      action: {},
      environment: {},
    });
  });

  it("parses --format and --verbose without a fixtures path, which the caller then supplies", () => {
    const parsed = parseArgv(["--fixtures", "f.json", "--format", "json", "--verbose"]);

    expect(parsed.kind).toBe("ok");
    if (parsed.kind !== "ok") {
      return;
    }
    expect(parsed.value.format).toBe("json");
    expect(parsed.value.explainAll).toBe(true);
  });

  it("ships a fixture example that the command actually accepts", async () => {
    // The example is documentation, and documentation that does not run is a
    // lie waiting to happen — so it is parsed by the same code the CLI uses.
    const raw = await readFile(
      new URL("./examples/document-access.fixtures.json", import.meta.url),
      "utf8",
    );
    const document: unknown = JSON.parse(raw);
    const parsed = parseFixtureSet(document);
    expect(parsed.kind).toBe("ok");
    if (parsed.kind === "ok") {
      expect(parsed.value.fixtures).toHaveLength(3);
    }

    const { code, io } = await run(
      new OwnershipPolicySimulationEngine(),
      ["--fixtures", "examples/document-access.fixtures.json"],
      { "examples/document-access.fixtures.json": raw },
    );
    expect(code).toBe(POLICY_SIMULATE_EXIT_CODES.matched);
    expect(io.output).toContain("3 fixtures — 3 passed, 0 failed");
  });
});
