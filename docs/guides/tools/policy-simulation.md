# Policy Simulation: Dry-Running a Policy Before Publishing It

This document describes `policy-simulate`, the tool behind Issue 155 (roadmap 155): why a
policy needs the same testing discipline as code, what the fixture format is, and which
alternatives were rejected. It is the tooling counterpart to
[authorization-model.md](../../security/authorization-model.md) (the composition the fixtures
exercise) and [policy-cache.md](../../security/policy-cache.md) (the cache the simulator
deliberately does not use).

---

## Why policies need tests

Every other artifact in this repository is held to a test: a use case has a spec, an adapter
has a contract suite, a migration has a drift check. A policy was, until this tool, an
exception — reviewed by hand, published, and then trusted until a request did something
nobody expected.

The failure mode is specific and worth stating plainly, because it is what motivates the whole
tool. When authorization is wrong in production, it is usually **correct code implementing an
incorrect policy** (threat model T-1 in
[threat-model-abac.md](../../security/threat-model-abac.md)). No amount of unit-testing the
evaluator catches a rule that says `permit if resource.sensitivity == "public"` when its author
meant `!=`. The only thing that catches it is running the policy against cases whose answers a
human already knows.

That is all this tool does: it takes a policy, a list of attribute contexts, and, for each one,
the effect its author _believes_ the policy should produce — then reports the disagreements.

## What it is not

- **It is not a decision endpoint.** The simulator never asks "is this subject allowed"; it
  asks "what would this policy decide for this context", with no subject row, no resource row
  and no database behind it. That is what makes it usable on a laptop and in CI.
- **It is not a cache consumer.** A simulation must not go through `PolicyCache` (Issue 154).
  A cached decision is correct for a live request whose policy version is current; for a dry
  run it would mean the tool reports the _previous_ generation's answer, and a policy author
  would see "PASS" for the version they just replaced. The engine port is therefore
  evaluation-only, and the read-only contract on `PolicySimulationEngine.simulate` says so.
- **It does not publish anything.** Draft text is evaluated where it lies. A tool that could
  change the policy it is inspecting is a liability on a CI runner.

## The fixture file

A fixture file names the policy and the cases to check it against:

```json
{
  "policy": { "kind": "stored", "ref": "document-access" },
  "fixtures": [
    {
      "name": "owner may read their own document",
      "expectedEffect": "PERMIT",
      "context": {
        "subject": { "subjectId": "user-1", "tenantId": "tenant-1" },
        "resource": { "ownerId": "user-1", "sensitivity": "public" },
        "action": { "name": "document:read" },
        "environment": { "now": "2026-08-01T09:00:00Z" }
      }
    }
  ]
}
```

- `policy.kind` is `"stored"` (a published policy, referenced by id — the thing production
  evaluates) or `"draft"` (DSL source carried in the file, or read with `--dsl`).
- `fixtures[].name` identifies the case. It is required, and unique within the file, because it
  is the only thing linking a failing row in a CI log back to the scenario its author had in
  mind.
- `fixtures[].expectedEffect` is what the author believes the policy decides here.
- `fixtures[].context` is the four-bag `AttributeContext` the policy is evaluated against.
  Axes may be omitted (they default to empty) — a fixture exercising only `subject` and
  `resource` should not have to write down two empty objects to say "the rest is unused".

A complete, runnable example lives at
`packages/authorization/infrastructure/cli/examples/document-access.fixtures.json`, and the CLI
spec parses and runs it, so the documented format cannot drift from the accepted one.

### Parsing is strict about shape and lenient about axes

An unknown key — `expect` instead of `expectedEffect`, `principle` instead of `subject` — is an
error, not something to ignore. A fixture whose misspelled key was silently dropped would still
report PASS while asserting nothing about the case its author wrote. A missing _axis_, by
contrast, is not an error: empty is already the domain's representation of "nothing resolved",
and the evaluator treats missing attributes as a non-match rather than a failure.

## Usage

```
policy-simulate --fixtures <path> [--policy <ref> | --dsl <path>] [--format table|json] [--verbose]
```

| Flag             | Meaning                                                                     |
| :--------------- | :-------------------------------------------------------------------------- |
| `--fixtures`     | The fixture file. Required.                                                 |
| `--policy <ref>` | Simulate a stored policy, overriding the fixture file's `policy` block.     |
| `--dsl <path>`   | Simulate draft DSL source read from a file, overriding the fixture file.    |
| `--format json`  | Emit the report as JSON for a pipeline, instead of the default human table. |
| `--verbose`      | Explain the rules behind every fixture, including the passing ones.         |

### Exit codes

| Code | Meaning                                                                    |
| :--- | :------------------------------------------------------------------------- |
| `0`  | Every fixture matched its expected effect.                                 |
| `1`  | At least one fixture disagreed — the policy does something else.           |
| `2`  | Nothing was decided: bad arguments, unusable fixtures, unreachable engine. |

Three outcomes rather than two, because collapsing the last two is how a CI check starts lying.
A malformed fixture file reported as "policy mismatch" sends an author hunting through rule
logic for a bug that is a stray comma; an unreachable policy store reported as a mismatch
accuses a policy that was never evaluated.

### The report

```
policy document-access

fixture                            expected  actual  rules  result
---------------------------------  --------  ------  -----  ------
owner may read their own document  PERMIT    PERMIT  1/2    PASS
a stranger is denied               DENY      DENY    0/2    PASS
suspension beats ownership         PERMIT    DENY    2/2    FAIL

3 fixtures — 2 passed, 1 failed

rules for "suspension beats ownership" — deny-overrides resolved to DENY, expected PERMIT:
  document-ownership           PERMIT          overridden by the combining step
  document-suspension          DENY            decisive
```

- `rules` is _matched / evaluated_: how many of the policy's rules applied at all. `0/2` across
  a passing fixture says the fixture passed by the default effect rather than by a rule — often
  the difference between a policy that works and one that never fires.
- The rule detail is printed for failures by default and for every fixture with `--verbose`.
  "expected DENY, got PERMIT" is a symptom; the rule that permitted while `deny-overrides`
  failed to override it is the diagnosis.

### In CI

```yaml
- name: Simulate the authorization policies
  run: |
    node apps/cli/dist/index.js policy-simulate \
      --fixtures policies/document-access.fixtures.json
```

Any non-zero exit fails the step, which is the whole point: a policy change that surprises its
author fails review rather than a request in production. Until the CLI application mounts the
command, a spec that calls `PolicySimulateCommand` with a real `readFile` and the fixture file
serves the same purpose.

## Where the code lives

The use case is `packages/authorization/application/use-cases/simulate-policy.ts`; the command
adapter is `packages/authorization/infrastructure/cli/policy-simulate-command.ts`.

Issue 155's file list suggests `apps/cli/src/commands/policy-simulate.ts`, and the command is
written for exactly that home — but `apps/cli` does not exist yet. The same call was made for
the sibling tooling issue (roadmap 156, the policy linter). Rather than stub an app package to
hold one file, the command is a complete adapter with its I/O injected
(`PolicySimulateIo`: a `readFile` and a `write`), so mounting it in the CLI application is a
composition-root change — pass `fs.readFile` and `process.stdout.write`, return the exit code —
with no logic moving between layers when the app lands.

## Decisions and rejected alternatives

**Declared expectations, not recorded goldens.** The alternative was to run a policy, record the
resulting decisions as a golden file, and fail when a later run differs. It is less work to
author and it is the wrong trade here: a golden file can be regenerated, and regenerating it is
a one-command way to accept a bug. A fixture says what the answer _should_ be, so a policy
change that flips a decision fails even when the person who changed the policy is the person
re-running the tool. The cost is that authors must write down an expected effect per case, which
is the thinking the tool exists to force.

**One report, three renderers.** The comparison could have happened inside the CLI loop, printing
as it went. It lives in the use case instead, and the table, the JSON and the exit code are all
derived from the same `PolicySimulationReport`: otherwise the three drift, and a run that passes
locally starts failing in CI for reasons that are about the printer rather than the policy.

**An empty fixture set is invalid, not green.** Zero fixtures means zero assertions, and a run
that asserts nothing exits `0`. That is the one way this tool could be green and useless at the
same time, so it exits `2` instead.

**Validation failures return `Result`; engine failures throw.** Bad fixture input is expected —
authors type it — so `SimulatePolicy` returns `Result<PolicySimulationReport, ValidationError>`
and reports every problem at once rather than the first. An unreachable policy store is
infrastructure failing, and it throws; the command turns that into exit `2`, never into a
mismatch, and the distinction is asserted in the specs.
