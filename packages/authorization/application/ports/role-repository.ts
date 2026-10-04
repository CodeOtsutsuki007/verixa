import type { OrgId, Role, RoleId } from "../../domain/entities/role.js";

/**
 * The persistence contract for `Role` — the **port** half of ports & adapters
 * (hexagonal architecture). No Prisma, SQL, or database implementation details appear here;
 * concrete adapters implement this interface without the domain or application layers
 * ever depending on infrastructure. See `docs/guides/domain-modeling.md`.
 *
 * ## Method Contracts
 *
 * - `findById(id: RoleId)`:
 *   Returns the matching `Role`, or `undefined` when no role exists with the given id.
 *   Missing role is an expected outcome (e.g. looking up a referenced role), not an
 *   exceptional error condition.
 *
 * - `findByName(name: string, orgId?: OrgId | null)`:
 *   Finds a role by its unique name within a specific scope.
 *   - When `orgId` is provided (scoped role): looks up the role matching `name` within that organization.
 *   - When `orgId` is omitted or `null` (global role): looks up the global system or platform role.
 *   Returns `undefined` if no matching role exists in that scope.
 *
 * - `findAllForOrg(orgId: OrgId)`:
 *   Returns an array of all roles explicitly scoped to the given organization.
 *   Returns an empty array if the organization has no custom roles defined.
 *
 * - `save(role: Role)`:
 *   Idempotent upsert: persists whatever `Role` aggregate state it is given, whether
 *   the role is newly created or previously existed. Callers do not distinguish "create"
 *   from "update" — the aggregate's own state is the single source of truth.
 *
 * - `delete(id: RoleId)`:
 *   Removes the specified role from persistence.
 *   - If the role does not exist: completes silently as an idempotent no-op.
 *   - If the role is a protected system role (`isSystemRole: true`): implementations
 *     MUST throw {@link SystemRoleImmutableError} with `attemptedAction: "delete"`
 *     to prevent accidental destruction of system recoverability roles.
 */
export interface RoleRepository {
  findById(id: RoleId): Promise<Role | undefined>;
  findByName(name: string, orgId?: OrgId | null): Promise<Role | undefined>;
  findAllForOrg(orgId: OrgId): Promise<Role[]>;
  save(role: Role): Promise<void>;
  delete(id: RoleId): Promise<void>;
}
