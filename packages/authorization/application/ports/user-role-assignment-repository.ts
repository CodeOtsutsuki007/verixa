import type {
  OrgId,
  UserId,
  UserRoleAssignment,
  UserRoleAssignmentId,
} from "../../domain/entities/user-role-assignment.js";

export interface FindUserRoleAssignmentsOptions {
  /**
   * If true, expired assignments are included in the results.
   * Defaults to `false` (safe-by-default: expired assignments are excluded).
   */
  readonly includeExpired?: boolean;

  /**
   * Reference timestamp to evaluate expiration against.
   * Defaults to the current time (`new Date()`).
   */
  readonly now?: Date;
}

/**
 * The persistence contract for `UserRoleAssignment` — the **port** half
 * of ports & adapters (hexagonal architecture).
 *
 * Models role assignments independently from `User` and `Role` aggregates,
 * enabling multi-tenant scoping and temporary access elevations.
 *
 * ## Method Contracts
 *
 * - `save(assignment: UserRoleAssignment)`:
 *   Idempotent upsert: persists whatever assignment state it is given.
 *
 * - `findById(id: UserRoleAssignmentId)`:
 *   Returns the matching assignment, or `undefined` when no assignment exists with the given id.
 *
 * - `findByUser(userId: UserId, options?: FindUserRoleAssignmentsOptions)`:
 *   Returns all role assignments for the specified user across all scopes (both organization-scoped
 *   and global assignments).
 *   - Excludes expired assignments by default. Callers must pass `{ includeExpired: true }`
 *     to include lapsed assignments (e.g. for audit or admin history views).
 *
 * - `findByUserAndOrg(userId: UserId, orgId: OrgId | null, options?: FindUserRoleAssignmentsOptions)`:
 *   Returns role assignments for a user within a specific scope:
 *   - When `orgId` is an `OrgId`: returns assignments scoped to that organization.
 *   - When `orgId` is `null`: returns global assignments applicable system-wide.
 *   - **Excludes expired assignments by default**. Pass `{ includeExpired: true }` to opt in.
 *
 * - `revoke(id: UserRoleAssignmentId)`:
 *   Revokes and removes the specified role assignment.
 *   - If the assignment does not exist: completes silently as an idempotent no-op.
 */
export interface UserRoleAssignmentRepository {
  findById(id: UserRoleAssignmentId): Promise<UserRoleAssignment | undefined>;
  findByUser(
    userId: UserId,
    options?: FindUserRoleAssignmentsOptions,
  ): Promise<UserRoleAssignment[]>;
  findByUserAndOrg(
    userId: UserId,
    orgId: OrgId | null,
    options?: FindUserRoleAssignmentsOptions,
  ): Promise<UserRoleAssignment[]>;
  save(assignment: UserRoleAssignment): Promise<void>;
  revoke(id: UserRoleAssignmentId): Promise<void>;
}
