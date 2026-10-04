import { DomainError } from "@verixa/shared-kernel";

export type SystemRoleAction = "revoke" | "rename" | "delete";

/**
 * Thrown when an operation attempts to mutate or revoke invariants on a protected
 * system role (e.g. revoking permissions from `super-admin` or renaming it).
 *
 * System roles are built-in roles that guarantee system recoverability and platform
 * administration. Protecting them at the domain layer ensures that no UI, script,
 * or background job can accidentally lock out administrative access.
 *
 * Distinguished from {@link ValidationError} with HTTP status code 403 Forbidden.
 */
export class SystemRoleImmutableError extends DomainError {
  readonly code = "SYSTEM_ROLE_IMMUTABLE";
  readonly httpStatusHint = 403;
  readonly roleId: string;
  readonly roleName: string;
  readonly attemptedAction: SystemRoleAction;

  constructor(
    roleId: string,
    roleName: string,
    attemptedAction: SystemRoleAction,
    options?: ErrorOptions,
  ) {
    const actionDescription =
      attemptedAction === "revoke"
        ? "revoke permissions from"
        : attemptedAction === "rename"
          ? "rename"
          : "delete";

    super(
      `Cannot ${actionDescription} system role "${roleName}" (${roleId}): system roles are protected against modification to guarantee system recoverability.`,
      options,
    );
    this.roleId = roleId;
    this.roleName = roleName;
    this.attemptedAction = attemptedAction;
  }

  override toJSON(): ReturnType<DomainError["toJSON"]> & {
    roleId: string;
    roleName: string;
    attemptedAction: SystemRoleAction;
  } {
    return {
      ...super.toJSON(),
      roleId: this.roleId,
      roleName: this.roleName,
      attemptedAction: this.attemptedAction,
    };
  }
}
