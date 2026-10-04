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
  PolicyDecisionPoint,
  PolicyEvaluation,
} from "./application/ports/policy-decision-point.js";
export type {
  RoleCheckRequest,
  RoleDecision,
  RoleDecisionKind,
  RolePermissionGate,
} from "./application/ports/role-permission-gate.js";

// Application: services
export { AuthorizationService } from "./application/services/authorization-service.js";
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
export type { PermissionRepository } from "./application/ports/permission-repository.js";
export type { RoleRepository } from "./application/ports/role-repository.js";
export type {
  FindUserRoleAssignmentsOptions,
  UserRoleAssignmentRepository,
} from "./application/ports/user-role-assignment-repository.js";
export {
  PermissionChecker,
  type PermissionCheckerOptions,
} from "./application/services/permission-checker.js";
export {
  requirePermission,
  requireAnyPermission,
  requireAllPermissions,
  type AuthenticatedPrincipal,
  type GuardReply,
  type OrgIdResolver,
  type PermissionCheckerLike,
  type RequestWithPrincipal,
} from "./interface/guards/require-permission.js";
export {
  createResolvePrincipalHook,
  type PermissionResolverLike,
  type ResolvePrincipalOptions,
} from "./interface/hooks/resolve-principal.js";
export {
  AssignPermissionToRole,
  type AssignPermissionToRoleCommand,
  type AssignPermissionToRoleError,
} from "./application/use-cases/assign-permission-to-role.js";
export {
  AssignRoleToUser,
  type AssignRoleToUserCommand,
  type AssignRoleToUserError,
} from "./application/use-cases/assign-role-to-user.js";
export {
  CreateRole,
  type CreateRoleCommand,
  type CreateRoleError,
} from "./application/use-cases/create-role.js";
export {
  DefinePermission,
  type DefinePermissionCommand,
  type DefinePermissionError,
} from "./application/use-cases/define-permission.js";
export {
  RevokePermissionFromRole,
  type RevokePermissionFromRoleCommand,
  type RevokePermissionFromRoleError,
} from "./application/use-cases/revoke-permission-from-role.js";
export {
  RevokeRoleFromUser,
  type RevokeRoleFromUserCommand,
  type RevokeRoleFromUserError,
} from "./application/use-cases/revoke-role-from-user.js";
export {
  Role,
  type CreateRoleParams,
  type OrgId,
  type RoleId,
  type RoleProps,
} from "./domain/entities/role.js";
export {
  SystemRoleImmutableError,
  type SystemRoleAction,
} from "./domain/errors/system-role-immutable-error.js";
export { Permission } from "./domain/value-objects/permission.js";
export { PermissionMatcher } from "./domain/services/permission-matcher.js";
export { InMemoryPermissionRepository } from "./infrastructure/fakes/in-memory-permission-repository.js";
export { InMemoryRoleRepository } from "./infrastructure/fakes/in-memory-role-repository.js";
export { InMemoryUserRoleAssignmentRepository } from "./infrastructure/fakes/in-memory-user-role-assignment-repository.js";
export { permissionRepositoryContract } from "./infrastructure/testing/contracts/permission-repository.contract.js";
export { roleRepositoryContract } from "./infrastructure/testing/contracts/role-repository.contract.js";
export { userRoleAssignmentRepositoryContract } from "./infrastructure/testing/contracts/user-role-assignment-repository.contract.js";
export {
  UserRoleAssignment,
  type CreateUserRoleAssignmentParams,
  type UserId,
  type UserRoleAssignmentId,
  type UserRoleAssignmentProps,
} from "./domain/entities/user-role-assignment.js";
export { AttributeContext } from "./domain/value-objects/attribute-context.js";
export type {
  AttributeBag,
  AttributeBagName,
  AttributeBags,
  AttributeCategory,
  AttributeRecord,
  AttributeValue,
  AttributeValueType,
} from "./domain/value-objects/attribute-context.js";
export { between, evaluateOperator } from "./domain/dsl/operators.js";
export type { ComparisonOperator, OperatorResult } from "./domain/dsl/operators.js";
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
  AttributeProviderFailure,
  AttributeResolutionResult,
} from "./application/services/attribute-resolution-pipeline.js";
export {
  Policy,
  type PolicyId,
  type PolicyStatus,
  type PolicyTarget,
} from "./domain/entities/policy.js";
export {
  Condition,
  type AlwaysCondition,
  type AndCondition,
  type ComparisonCondition,
  type ComparisonLiteral,
  type NotCondition,
  type OrCondition,
} from "./domain/value-objects/condition.js";
export type { Effect } from "./domain/value-objects/effect.js";
export { Rule } from "./domain/value-objects/rule.js";
export type { PolicyRepository } from "./application/ports/policy-repository.js";
export { InMemoryPolicyRepository } from "./infrastructure/fakes/in-memory-policy-repository.js";
export { PrismaPolicyRepository } from "./infrastructure/persistence/prisma-policy-repository.js";
export type {
  ResourceAttributeResolver,
  ResourceAttributes,
  ResourceAttributeValue,
} from "./application/ports/resource-attribute-resolver.js";
export {
  ResourceAttributeResolverRegistry,
  UnknownResourceTypeError,
} from "./application/services/resource-attribute-resolver-registry.js";
export { evaluateCondition, evaluateRule } from "./domain/services/policy-evaluation-engine.js";
export {
  deriveRuleOutcomes,
  denyOverrides,
  permitOverrides,
  firstApplicable,
  type CombiningAlgorithm,
  type RuleOutcome,
} from "./domain/services/combining-algorithms.js";
export {
  NoRbacGrants,
  type RbacAuthorizationPort,
  type RbacDecision,
} from "./application/ports/rbac-authorization.js";
export {
  AuthorizationService,
  type AuthorizeParams,
  type AuthorizationEffect,
  type AuthorizationResult,
} from "./application/services/authorization-service.js";
export type { AuthorizationDecision } from "./application/dto/authorization-decision.js";
export {
  AuthorizeAction,
  type AuthorizeActionCommand,
} from "./application/use-cases/authorize-action.js";

// RBAC: default role/permission catalog, persistence and admin routes.
export { Permission, Role, AuthorizationError } from "./domain/authorization.js";
export type { PermissionKey, RoleRecord, RoleAssignment } from "./domain/authorization.js";
export type { AuthorizationRepository } from "./application/authorization-repository.js";
export { PrismaAuthorizationRepository } from "./infrastructure/prisma-authorization-repository.js";
export {
  DEFAULT_PERMISSIONS,
  DEFAULT_ROLES,
  seedDefaultRoles,
} from "./infrastructure/seed/seed-default-roles.js";
export { registerAdminAuthorizationRoutes } from "./interface/admin-roles.routes.js";
