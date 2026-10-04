import { type ConflictError, NotFoundError, Result, ValidationError } from "@verixa/shared-kernel";

import {
  type OrgId,
  type RoleId,
  type UserId,
  UserRoleAssignment,
} from "../../domain/entities/user-role-assignment.js";
import type { RoleRepository } from "../ports/role-repository.js";
import type { UserRoleAssignmentRepository } from "../ports/user-role-assignment-repository.js";

export interface AssignRoleToUserCommand {
  readonly userId: UserId;
  readonly roleId: RoleId;
  readonly orgId: OrgId | null;
  readonly assignedBy: UserId;
  readonly expiresAt?: Date | undefined;
  readonly assignedAt?: Date | undefined;
}

export type AssignRoleToUserError = NotFoundError | ValidationError | ConflictError;

/**
 * Orchestrates assigning a role to a user within an organization or globally (Issue 133).
 *
 * ## Business Invariants & Privilege Management:
 * 1. **Role Existence:** Verifies that the target role exists in `RoleRepository`.
 * 2. **Scope Compatibility:** If a role is scoped to a specific tenant organization,
 *    it cannot be assigned to a different organization or assigned globally.
 * 3. **Idempotency:** If the user already has an active, non-expired assignment for the
 *    exact same role and scope, the operation completes idempotently and returns the existing assignment.
 * 4. **Persistence:** Newly created assignments are persisted via `UserRoleAssignmentRepository`.
 */
export class AssignRoleToUser {
  constructor(
    private readonly userRoleAssignmentRepository: UserRoleAssignmentRepository,
    private readonly roleRepository: RoleRepository,
  ) {}

  async execute(
    command: AssignRoleToUserCommand,
  ): Promise<Result<UserRoleAssignment, AssignRoleToUserError>> {
    // 1. Verify that the referenced role exists
    const role = await this.roleRepository.findById(command.roleId);
    if (role === undefined) {
      return Result.err(new NotFoundError(`Role with ID "${command.roleId}" was not found.`));
    }

    // 2. Enforce scope compatibility
    if (role.isScoped()) {
      if (command.orgId !== role.orgId) {
        return Result.err(
          new ValidationError(
            `Scoped role "${role.name}" belongs to organization "${role.orgId}" and cannot be assigned to scope "${command.orgId}".`,
            { orgId: ["scope_mismatch"] },
          ),
        );
      }
    }

    // 3. Check for existing active assignment to ensure idempotency
    if (command.orgId !== undefined) {
      const activeAssignments = await this.userRoleAssignmentRepository.findByUserAndOrg(
        command.userId,
        command.orgId,
        { includeExpired: false },
      );

      const existingAssignment = activeAssignments.find((a) => a.roleId === command.roleId);
      if (existingAssignment !== undefined) {
        return Result.ok(existingAssignment);
      }
    }

    // 4. Instantiate domain entity and validate invariants
    const assignmentResult = UserRoleAssignment.create({
      userId: command.userId,
      roleId: command.roleId,
      orgId: command.orgId,
      assignedBy: command.assignedBy,
      ...(command.assignedAt !== undefined ? { assignedAt: command.assignedAt } : {}),
      ...(command.expiresAt !== undefined ? { expiresAt: command.expiresAt } : {}),
    });

    if (Result.isErr(assignmentResult)) {
      return assignmentResult;
    }

    const assignment = assignmentResult.value;

    // 5. Persist via repository
    await this.userRoleAssignmentRepository.save(assignment);

    return Result.ok(assignment);
  }
}
