// Curated public surface of @verixa/authorization. Nothing outside this package
// should import from a deep path (`@verixa/authorization/domain/...`,
// `@verixa/authorization/application/...`) — see docs/guides/domain-modeling.md
// ("Package encapsulation") for why, and eslint.config.mjs's
// `no-restricted-imports` rule, which enforces it.

// Domain: the decision vocabulary and the precedence contract
export {
  AUTHORIZATION_PRECEDENCE,
  AUTHORIZATION_REASONS,
  UnsafeAuthorizationPrecedenceError,
  assertAuthorizationPrecedenceIsSafe,
  resolveAuthorizationPrecedence,
} from "./domain/authorization-decision.js";
export type {
  AuthorizationDecision,
  AuthorizationDecisionSource,
  AuthorizationEffect,
  AuthorizationPrecedence,
  PolicyEffect,
} from "./domain/authorization-decision.js";
export { emptyAttributeContext } from "./domain/attribute-context.js";
export type {
  AttributeBag,
  AttributeContext,
  AuthorizationRequest,
  ResourceRef,
  SubjectRef,
} from "./domain/attribute-context.js";

// Application: ports (implemented by infrastructure adapters — see
// docs/guides/domain-modeling.md)
export type {
  PolicySimulationEngine,
  PolicySimulationRun,
  PolicySource,
  SimulatedRuleOutcome,
} from "./application/ports/policy-simulation-engine.js";

// Application: use cases
export { SimulatePolicy } from "./application/use-cases/simulate-policy.js";
export type {
  PolicyFixture,
  PolicyFixtureSet,
  PolicySimulationReport,
  SimulationFixtureResult,
} from "./application/use-cases/simulate-policy.js";

// Infrastructure: the `policy-simulate` command (Issue 155). It is exported
// because the CLI application mounts it through this surface like any other
// consumer — see docs/guides/tools/policy-simulation.md for why it lives here
// until `apps/cli` exists.
export {
  POLICY_SIMULATE_EXIT_CODES,
  POLICY_SIMULATE_USAGE,
  PolicySimulateCommand,
  parseArgv,
  parseFixtureSet,
  renderJson,
  renderTable,
} from "./infrastructure/cli/policy-simulate-command.js";
export type {
  PolicySimulateFormat,
  PolicySimulateIo,
  PolicySimulateOptions,
} from "./infrastructure/cli/policy-simulate-command.js";
