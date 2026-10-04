import { ConflictError, Result, ValidationError } from "@verixa/shared-kernel";

import { type OrgId, Role } from "../../domain/entities/role.js";
import { PermissionMatcher } from "../../domain/services/permission-matcher.js";
import type { Permission } from "../../domain/value-objects/permission.js";
import type { RoleRepository } from "../ports/role-repository.js";

export interface CreateRoleCommand {
  readonly name: string;
  readonly description?: string | undefined;
  readonly orgId?: OrgId | null | undefined;
  readonly isSystemRole?: boolean | undefined;
  readonly permissions?: Iterable<Permission | string> | undefined;
}

export type CreateRoleError = ValidationError | ConflictError;

/**
 * Orchestrates creating a new Role: validate input, enforce unique role name
 * within the requested scope (per-organization or globally), construct the Role aggregate,
 * and persist it via the RoleRepository port.
 */
export class CreateRole {
  constructor(private readonly roleRepository: RoleRepository) {}

  async execute(command: CreateRoleCommand): Promise<Result<Role, CreateRoleError>> {
    const roleResult = Role.create({
      name: command.name,
      ...(command.description !== undefined ? { description: command.description } : {}),
      ...(command.orgId !== undefined ? { orgId: command.orgId } : {}),
      ...(command.isSystemRole !== undefined ? { isSystemRole: command.isSystemRole } : {}),
      ...(command.permissions !== undefined ? { permissions: command.permissions } : {}),
    });

    if (Result.isErr(roleResult)) {
      return roleResult;
    }

    const role = roleResult.value;

    if (!role.isSystemRole) {
      for (const permKey of role.permissions) {
        if (PermissionMatcher.isGlobalWildcard(permKey)) {
          return Result.err(
            new ValidationError('Global wildcard "*:*" can only be granted to system roles.', {
              permissions: ["system_role_only"],
            }),
          );
        }
      }
    }

    const existing = await this.roleRepository.findByName(role.name, role.orgId);
    if (existing !== undefined) {
      const scopeDescription = role.orgId !== null ? `in organization "${role.orgId}"` : "globally";
      return Result.err(
        new ConflictError(`Role with name "${role.name}" already exists ${scopeDescription}.`),
      );
    }

    await this.roleRepository.save(role);

    return Result.ok(role);
  }
}
