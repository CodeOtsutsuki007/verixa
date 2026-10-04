import { NotFoundError, Result, ValidationError } from "@verixa/shared-kernel";

import {
  type OrgId,
  type RoleId,
  type UserId,
  UserRoleAssignment,
  type UserRoleAssignmentId,
} from "../../domain/entities/user-role-assignment.js";
import type { UserRoleAssignmentRepository } from "../ports/user-role-assignment-repository.js";

export interface RevokeRoleFromUserCommand {
  /** Target assignment ID to revoke directly, if known. */
  readonly assignmentId?: UserRoleAssignmentId | undefined;

  /** Target user ID if revoking by role and scope. */
  readonly userId?: UserId | undefined;

  /** Target role ID if revoking by role and scope. */
  readonly roleId?: RoleId | undefined;

  /** Scope organization ID (or null for global), if revoking by user/role. */
  readonly orgId?: OrgId | null | undefined;
}

export type RevokeRoleFromUserError = NotFoundError | ValidationError;

/**
 * Orchestrates revoking a user's role assignment (Issue 133).
 *
 * ## Revocation Capabilities & Semantics:
 * 1. **By Assignment ID:** Looks up the exact assignment by ID; if found, revokes it.
 *    If the assignment does not exist, returns `NotFoundError`.
 * 2. **By User, Role, and Scope:** Finds the matching active assignment for the given
 *    `(userId, roleId, orgId)` tuple and revokes it. Returns `NotFoundError` if no active
 *    assignment exists.
 * 3. **Input Validation:** Rejects queries where neither `assignmentId` nor the complete
 *    `(userId, roleId, orgId)` tuple is provided.
 */
export class RevokeRoleFromUser {
  constructor(private readonly userRoleAssignmentRepository: UserRoleAssignmentRepository) {}

  async execute(
    command: RevokeRoleFromUserCommand,
  ): Promise<Result<UserRoleAssignment, RevokeRoleFromUserError>> {
    // 1. Revocation by explicit assignmentId
    if (command.assignmentId !== undefined) {
      const assignment = await this.userRoleAssignmentRepository.findById(command.assignmentId);
      if (assignment === undefined) {
        return Result.err(
          new NotFoundError(`Role assignment with ID "${command.assignmentId}" was not found.`),
        );
      }

      await this.userRoleAssignmentRepository.revoke(assignment.id);
      return Result.ok(assignment);
    }

    // 2. Revocation by (userId, roleId, orgId) tuple
    if (
      command.userId !== undefined &&
      command.roleId !== undefined &&
      command.orgId !== undefined
    ) {
      const activeAssignments = await this.userRoleAssignmentRepository.findByUserAndOrg(
        command.userId,
        command.orgId,
        { includeExpired: false },
      );

      const matchingAssignment = activeAssignments.find((a) => a.roleId === command.roleId);
      if (matchingAssignment === undefined) {
        const scopeDesc =
          command.orgId !== null ? `organization "${command.orgId}"` : "global scope";
        return Result.err(
          new NotFoundError(
            `No active role assignment found for user "${command.userId}" with role "${command.roleId}" in ${scopeDesc}.`,
          ),
        );
      }

      await this.userRoleAssignmentRepository.revoke(matchingAssignment.id);
      return Result.ok(matchingAssignment);
    }

    // 3. Ambiguous parameters
    return Result.err(
      new ValidationError(
        "Either assignmentId or a complete (userId, roleId, orgId) tuple must be provided to revoke a role assignment.",
        {
          command: ["missing_identifier"],
        },
      ),
    );
  }
}
