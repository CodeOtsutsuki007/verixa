import { Result, type ValidationError } from "@verixa/shared-kernel";

import { Permission } from "../../domain/value-objects/permission.js";
import type { PermissionRepository } from "../ports/permission-repository.js";

export interface DefinePermissionCommand {
  readonly key: string;
}

export type DefinePermissionError = ValidationError;

/**
 * Orchestrates registering a new Permission in the authoritative catalog (Issue 131).
 *
 * Typically invoked during application bootstrap by feature modules declaring the permissions
 * they protect.
 *
 * Invariants:
 * - Registering a duplicate permission key is idempotent (no-op) and returns the existing permission.
 * - Registering an invalid key format is rejected with a {@link ValidationError}.
 */
export class DefinePermission {
  constructor(private readonly permissionRepository: PermissionRepository) {}

  async execute(
    command: DefinePermissionCommand,
  ): Promise<Result<Permission, DefinePermissionError>> {
    const permissionResult = Permission.create(command.key);
    if (Result.isErr(permissionResult)) {
      return permissionResult;
    }

    const permission = permissionResult.value;

    const existing = await this.permissionRepository.findByKey(permission.key);
    if (existing !== undefined) {
      return Result.ok(existing);
    }

    await this.permissionRepository.save(permission);

    return Result.ok(permission);
  }
}
