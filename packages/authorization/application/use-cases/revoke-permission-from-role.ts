import { NotFoundError, Result, ValidationError } from "@verixa/shared-kernel";

import type { Role, RoleId } from "../../domain/entities/role.js";
import type { SystemRoleImmutableError } from "../../domain/errors/system-role-immutable-error.js";
import { Permission } from "../../domain/value-objects/permission.js";
import type { RoleRepository } from "../ports/role-repository.js";

export interface RevokePermissionFromRoleCommand {
  readonly roleId: RoleId;
  readonly permission: string;
}

export type RevokePermissionFromRoleError =
  NotFoundError | ValidationError | SystemRoleImmutableError;

/**
 * Orchestrates revoking a permission from a Role (Issue 132).
 *
 * Enforces domain invariants:
 * - Rejects mutation on system roles (guaranteeing system recoverability).
 * - Persists updated role state via the `RoleRepository` port.
 */
export class RevokePermissionFromRole {
  constructor(private readonly roleRepository: RoleRepository) {}

  async execute(
    command: RevokePermissionFromRoleCommand,
  ): Promise<Result<Role, RevokePermissionFromRoleError>> {
    const role = await this.roleRepository.findById(command.roleId);
    if (role === undefined) {
      return Result.err(new NotFoundError(`Role with ID "${command.roleId}" was not found.`));
    }

    const permissionResult = Permission.create(command.permission);
    if (Result.isErr(permissionResult)) {
      return permissionResult;
    }

    const permission = permissionResult.value;

    try {
      role.revoke(permission);
    } catch (error) {
      return Result.err(error as SystemRoleImmutableError);
    }

    await this.roleRepository.save(role);

    return Result.ok(role);
  }
}
