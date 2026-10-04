import type {
  FindUserRoleAssignmentsOptions,
  UserRoleAssignmentRepository,
} from "../../application/ports/user-role-assignment-repository.js";
import type {
  OrgId,
  UserId,
  UserRoleAssignment,
  UserRoleAssignmentId,
} from "../../domain/entities/user-role-assignment.js";

/**
 * An in-memory fake implementation of `UserRoleAssignmentRepository` backed by a `Map`.
 *
 * Exists so permission resolution and assignment use cases can be executed and
 * tested quickly without database dependencies.
 */
export class InMemoryUserRoleAssignmentRepository implements UserRoleAssignmentRepository {
  private readonly assignmentsById = new Map<UserRoleAssignmentId, UserRoleAssignment>();

  findById(id: UserRoleAssignmentId): Promise<UserRoleAssignment | undefined> {
    return Promise.resolve(this.assignmentsById.get(id));
  }

  findByUser(
    userId: UserId,
    options?: FindUserRoleAssignmentsOptions,
  ): Promise<UserRoleAssignment[]> {
    const includeExpired = options?.includeExpired ?? false;
    const now = options?.now ?? new Date();

    const matches = [...this.assignmentsById.values()].filter((assignment) => {
      if (assignment.userId !== userId) {
        return false;
      }
      if (!includeExpired && assignment.isExpired(now)) {
        return false;
      }
      return true;
    });

    return Promise.resolve(matches);
  }

  findByUserAndOrg(
    userId: UserId,
    orgId: OrgId | null,
    options?: FindUserRoleAssignmentsOptions,
  ): Promise<UserRoleAssignment[]> {
    const includeExpired = options?.includeExpired ?? false;
    const now = options?.now ?? new Date();

    const matches = [...this.assignmentsById.values()].filter((assignment) => {
      if (assignment.userId !== userId || assignment.orgId !== orgId) {
        return false;
      }
      if (!includeExpired && assignment.isExpired(now)) {
        return false;
      }
      return true;
    });

    return Promise.resolve(matches);
  }

  save(assignment: UserRoleAssignment): Promise<void> {
    this.assignmentsById.set(assignment.id, assignment);
    return Promise.resolve();
  }

  revoke(id: UserRoleAssignmentId): Promise<void> {
    this.assignmentsById.delete(id);
    return Promise.resolve();
  }
}
