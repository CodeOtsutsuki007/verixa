import { ConflictError } from "@verixa/shared-kernel";

import type { PermissionRepository } from "../../application/ports/permission-repository.js";
import type { Permission } from "../../domain/value-objects/permission.js";

/**
 * An in-memory fake implementation of `PermissionRepository` backed by a `Map`.
 *
 * Stores the canonical catalog of permissions recognized by the system.
 * Used by application services, permission-checking guards, and unit tests
 * without requiring database connectivity.
 */
export class InMemoryPermissionRepository implements PermissionRepository {
  private readonly permissionsByKey = new Map<string, Permission>();

  save(permission: Permission): Promise<void> {
    const key = permission.value;
    if (this.permissionsByKey.has(key)) {
      return Promise.reject(
        new ConflictError(`Permission with key "${key}" is already registered.`),
      );
    }

    this.permissionsByKey.set(key, permission);
    return Promise.resolve();
  }

  findByKey(key: string): Promise<Permission | undefined> {
    const normalizedKey = key.trim().toLowerCase();
    return Promise.resolve(this.permissionsByKey.get(normalizedKey));
  }

  findAll(): Promise<Permission[]> {
    return Promise.resolve([...this.permissionsByKey.values()]);
  }
}
