export type { PermissionRepository } from "./application/ports/permission-repository.js";
export type { RoleRepository } from "./application/ports/role-repository.js";
export type {
  FindUserRoleAssignmentsOptions,
  UserRoleAssignmentRepository,
} from "./application/ports/user-role-assignment-repository.js";
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
  AttributeRecord,
  AttributeValue,
  AttributeValueType,
} from "./domain/value-objects/attribute-context.js";
export { between, evaluateOperator } from "./domain/dsl/operators.js";
export type { ComparisonOperator, OperatorResult } from "./domain/dsl/operators.js";
export type {
  AttributeProvider,
  AttributeResolutionRequest,
} from "./application/ports/attribute-provider.js";
export {
  AttributeProviderResolutionError,
  AttributeResolutionPipeline,
} from "./application/services/attribute-resolution-pipeline.js";
export type {
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
