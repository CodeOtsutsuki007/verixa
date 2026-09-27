import { NotFoundError, Result, ValidationError } from "@verixa/shared-kernel";

import type { Role, RoleId } from "../../domain/entities/role.js";
import { Permission } from "../../domain/value-objects/permission.js";
import type { PermissionRepository } from "../ports/permission-repository.js";
import type { RoleRepository } from "../ports/role-repository.js";

export interface AssignPermissionToRoleCommand {
  readonly roleId: RoleId;
  readonly permission: string;
}

export type AssignPermissionToRoleError = NotFoundError | ValidationError;

/**
 * Orchestrates assigning a permission to a Role (Issue 132).
 *
 * Enforces cross-aggregate catalog validation: verifies that the target permission exists in
 * the authoritative `PermissionRepository` catalog before modifying the `Role` aggregate.
 */
export class AssignPermissionToRole {
  constructor(
    private readonly roleRepository: RoleRepository,
    private readonly permissionRepository: PermissionRepository,
  ) {}

  async execute(
    command: AssignPermissionToRoleCommand,
  ): Promise<Result<Role, AssignPermissionToRoleError>> {
    const role = await this.roleRepository.findById(command.roleId);
    if (role === undefined) {
      return Result.err(new NotFoundError(`Role with ID "${command.roleId}" was not found.`));
    }

    const permissionResult = Permission.create(command.permission);
    if (Result.isErr(permissionResult)) {
      return permissionResult;
    }

    const permission = permissionResult.value;

    const catalogPermission = await this.permissionRepository.findByKey(permission.key);
    if (catalogPermission === undefined) {
      return Result.err(
        new ValidationError(
          `Permission "${permission.key}" is not registered in the system catalog.`,
          { permission: ["unregistered_permission"] },
        ),
      );
    }

    role.grant(permission);
    await this.roleRepository.save(role);

    return Result.ok(role);
  }
}
