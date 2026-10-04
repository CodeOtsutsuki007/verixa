import type { OrgId, RoleId } from "../../domain/entities/role.js";
import type { UserId } from "../../domain/entities/user-role-assignment.js";
import { Permission } from "../../domain/value-objects/permission.js";
import type { RoleRepository } from "../ports/role-repository.js";
import type { UserRoleAssignmentRepository } from "../ports/user-role-assignment-repository.js";

export interface PermissionCheckerOptions {
  readonly now?: Date;
}

/**
 * Application service responsible for resolving and evaluating a user's effective permissions (Issue 134).
 *
 * Enforces deny-by-default: a user with no role assignments or expired assignments has no permissions.
 * Aggregates all granted permissions across all active (non-expired) roles assigned to the user
 * in the specified scope (including global roles and organization-scoped roles).
 */
export class PermissionChecker {
  constructor(
    private readonly userRoleAssignmentRepository: UserRoleAssignmentRepository,
    private readonly roleRepository: RoleRepository,
  ) {}

  /**
   * Evaluates whether a user has a specific permission in the given organization context (or globally).
   */
  async hasPermission(
    userId: UserId,
    orgId: OrgId | null,
    permission: Permission | string,
    options?: PermissionCheckerOptions,
  ): Promise<boolean> {
    const required = typeof permission === "string" ? Permission.from(permission) : permission;

    const effectivePermissions = await this.resolveEffectivePermissions(userId, orgId, options);

    for (const granted of effectivePermissions) {
      if (granted.matches(required)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Evaluates whether a user has at least one of the candidate permissions.
   */
  async hasAnyPermission(
    userId: UserId,
    orgId: OrgId | null,
    permissions: Iterable<Permission | string>,
    options?: PermissionCheckerOptions,
  ): Promise<boolean> {
    const requiredList = Array.from(permissions).map((p) =>
      typeof p === "string" ? Permission.from(p) : p,
    );

    if (requiredList.length === 0) {
      return false;
    }

    const effectivePermissions = await this.resolveEffectivePermissions(userId, orgId, options);

    for (const required of requiredList) {
      for (const granted of effectivePermissions) {
        if (granted.matches(required)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Evaluates whether a user has all of the required permissions.
   */
  async hasAllPermissions(
    userId: UserId,
    orgId: OrgId | null,
    permissions: Iterable<Permission | string>,
    options?: PermissionCheckerOptions,
  ): Promise<boolean> {
    const requiredList = Array.from(permissions).map((p) =>
      typeof p === "string" ? Permission.from(p) : p,
    );

    if (requiredList.length === 0) {
      return true;
    }

    const effectivePermissions = await this.resolveEffectivePermissions(userId, orgId, options);

    for (const required of requiredList) {
      let matched = false;
      for (const granted of effectivePermissions) {
        if (granted.matches(required)) {
          matched = true;
          break;
        }
      }
      if (!matched) {
        return false;
      }
    }

    return true;
  }

  /**
   * Resolves the full union of active granted permissions for a user within a scope.
   */
  async resolveEffectivePermissions(
    userId: UserId,
    orgId: OrgId | null,
    options?: PermissionCheckerOptions,
  ): Promise<Set<Permission>> {
    const now = options?.now ?? new Date();

    // Fetch active assignments for the scoped org, plus global assignments
    const scopedAssignments =
      orgId !== null
        ? await this.userRoleAssignmentRepository.findByUserAndOrg(userId, orgId, {
            includeExpired: false,
            now,
          })
        : [];

    const globalAssignments = await this.userRoleAssignmentRepository.findByUserAndOrg(
      userId,
      null,
      {
        includeExpired: false,
        now,
      },
    );

    const activeAssignments = [...scopedAssignments, ...globalAssignments];

    const uniqueRoleIds = new Set<RoleId>(activeAssignments.map((a) => a.roleId));
    const effectivePermissions = new Set<Permission>();

    for (const roleId of uniqueRoleIds) {
      const role = await this.roleRepository.findById(roleId);
      if (role !== undefined) {
        for (const permValue of role.permissions) {
          effectivePermissions.add(Permission.from(permValue));
        }
      }
    }

    return effectivePermissions;
  }
}
