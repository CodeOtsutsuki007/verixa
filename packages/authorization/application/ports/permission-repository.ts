import type { Permission } from "../../domain/value-objects/permission.js";

/**
 * The persistence contract for the canonical `Permission` catalog — the **port**
 * half of ports & adapters (hexagonal architecture).
 *
 * Provides the authoritative source of truth for which permissions the system
 * recognizes, independent of which roles happen to reference them. This enables:
 * - Admin APIs and role-management UIs to validate permission assignments and
 *   reject misspelled or unregistered keys.
 * - Bootstrap routines to declare and verify application permissions.
 *
 * ## Method Contracts
 *
 * - `save(permission: Permission)`:
 *   Registers a new `Permission` entry in the system catalog.
 *   - Implementations MUST reject duplicate key registrations by throwing
 *     {@link ConflictError} if a permission with the same normalized key is already
 *     registered in the catalog.
 *
 * - `findByKey(key: string)`:
 *   Looks up a registered permission by its string identifier (e.g. `users:read`, `roles:write`).
 *   - The lookup is case-insensitive and trims surrounding whitespace.
 *   - Returns the matching `Permission` value object, or `undefined` when no matching
 *     permission is registered. Missing permissions are expected outcomes, not errors.
 *
 * - `findAll()`:
 *   Returns an array of all permissions currently registered in the catalog.
 *   - Returns an empty array if no permissions have been registered yet.
 */
export interface PermissionRepository {
  save(permission: Permission): Promise<void>;
  findByKey(key: string): Promise<Permission | undefined>;
  findAll(): Promise<Permission[]>;
}
