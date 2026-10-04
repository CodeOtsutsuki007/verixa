import { Result } from "@verixa/shared-kernel";

import { Permission } from "../value-objects/permission.js";

/**
 * Pure domain service encapsulating wildcard and hierarchical permission matching logic (Issue 135).
 *
 * ## Matching Semantics:
 * 1. **Exact Match:** `granted.value === required.value` (e.g., `users:read` satisfies `users:read`).
 * 2. **Global Wildcard:** `*:*` matches any valid permission (e.g., `*:*` satisfies `users:read`, `audit:export`).
 *    - Note: Granting `*:*` is restricted to system roles (`isSystemRole: true`) at the use case layer.
 * 3. **Resource Wildcard / Action Wildcard:**
 *    - `resource:*` matches any action on that specific resource (e.g., `users:*` satisfies `users:read`, `users:write`).
 *    - `*:action` matches that specific action across all resources (e.g., `*:read` satisfies `users:read`, `docs:read`).
 * 4. **Boundary Isolation:** `users:*` does NOT match `orgs:read` or `user_profiles:read`.
 */
export class PermissionMatcher {
  /**
   * Evaluates whether a granted permission satisfies a required permission.
   *
   * @param granted The permission granted to the role/user.
   * @param required The permission required by the operation or route.
   */
  static matches(granted: Permission | string, required: Permission | string): boolean {
    const grantedRes =
      typeof granted === "string" ? Permission.create(granted) : Result.ok(granted);
    const requiredRes =
      typeof required === "string" ? Permission.create(required) : Result.ok(required);

    if (Result.isErr(grantedRes) || Result.isErr(requiredRes)) {
      return false;
    }

    const grantedPerm = grantedRes.value;
    const requiredPerm = requiredRes.value;

    // 1. Direct value equivalence
    if (grantedPerm.value === requiredPerm.value) {
      return true;
    }

    // 2. Global wildcard (*:*) matches everything
    if (grantedPerm.resource === "*" && grantedPerm.action === "*") {
      return true;
    }

    // 3. Action wildcard within identical resource (e.g. users:* matches users:read)
    if (grantedPerm.resource === requiredPerm.resource && grantedPerm.action === "*") {
      return true;
    }

    // 4. Resource wildcard for identical action (e.g. *:read matches users:read)
    if (grantedPerm.resource === "*" && grantedPerm.action === requiredPerm.action) {
      return true;
    }

    return false;
  }

  /**
   * Helper to determine whether a permission is the reserved global wildcard `*:*`.
   */
  static isGlobalWildcard(permission: Permission | string): boolean {
    const permRes =
      typeof permission === "string" ? Permission.create(permission) : Result.ok(permission);
    if (Result.isErr(permRes)) {
      return false;
    }
    const perm = permRes.value;
    return perm.resource === "*" && perm.action === "*";
  }
}
