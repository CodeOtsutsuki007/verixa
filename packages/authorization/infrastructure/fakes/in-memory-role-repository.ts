import type { RoleRepository } from "../../application/ports/role-repository.js";
import type { OrgId, Role, RoleId } from "../../domain/entities/role.js";
import { SystemRoleImmutableError } from "../../domain/errors/system-role-immutable-error.js";

/**
 * An in-memory fake implementation of `RoleRepository` backed by a `Map`.
 *
 * Exists so application use cases and domain tests can execute in-memory
 * without requiring a live database. Shares the exact same behavioral contract
 * tests as production adapters.
 */
export class InMemoryRoleRepository implements RoleRepository {
  private readonly rolesById = new Map<RoleId, Role>();

  findById(id: RoleId): Promise<Role | undefined> {
    return Promise.resolve(this.rolesById.get(id));
  }

  findByName(name: string, orgId?: OrgId | null): Promise<Role | undefined> {
    const targetOrgId = orgId ?? null;
    const targetName = name.trim();

    const match = [...this.rolesById.values()].find(
      (role) => role.name === targetName && role.orgId === targetOrgId,
    );

    return Promise.resolve(match);
  }

  findAllForOrg(orgId: OrgId): Promise<Role[]> {
    const matches = [...this.rolesById.values()].filter((role) => role.orgId === orgId);
    return Promise.resolve(matches);
  }

  save(role: Role): Promise<void> {
    this.rolesById.set(role.id, role);
    return Promise.resolve();
  }

  delete(id: RoleId): Promise<void> {
    const role = this.rolesById.get(id);
    if (!role) {
      return Promise.resolve();
    }

    if (role.isSystemRole) {
      return Promise.reject(new SystemRoleImmutableError(role.id, role.name, "delete"));
    }

    this.rolesById.delete(id);
    return Promise.resolve();
  }
}
