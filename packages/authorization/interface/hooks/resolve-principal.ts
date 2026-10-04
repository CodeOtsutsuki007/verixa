import type { OrgId, UserId } from "../../domain/entities/user-role-assignment.js";
import { Permission } from "../../domain/value-objects/permission.js";
import type {
  AuthenticatedPrincipal,
  OrgIdResolver,
  RequestWithPrincipal,
} from "../guards/require-permission.js";

export interface ResolvePrincipalOptions {
  readonly orgIdResolver?: OrgIdResolver | undefined;
}

export type PermissionResolverLike = {
  resolveEffectivePermissions(
    userId: UserId,
    orgId: OrgId | null,
  ): Promise<Set<Permission | string> | Iterable<Permission | string>>;
};

/**
 * Fastify `onRequest`/`preHandler` hook factory that resolves the authenticated user's
 * effective permissions once per request and memoizes them on `request.principal` (Issue 137).
 *
 * ## Lifecycle & Caching Guarantees:
 * 1. **Per-Request Memoization:** Resolved permissions are attached to `request.principal.permissions`.
 *    Subsequent guards on the same route inspect this cache without redundant database/service queries.
 * 2. **Unauthenticated Safety:** If no authenticated user is present (`request.principal` is undefined
 *    or missing `userId`), the hook completes silently without throwing, allowing upstream auth
 *    middleware or downstream route guards to handle the unauthenticated state cleanly.
 * 3. **Tenant Context Awareness:** Resolves permissions using either the custom `orgIdResolver`
 *    or the `principal.orgId` context.
 */
export function createResolvePrincipalHook(
  checker: PermissionResolverLike,
  options?: ResolvePrincipalOptions,
) {
  return async function resolvePrincipal(
    request: RequestWithPrincipal,
    _reply?: unknown,
  ): Promise<void> {
    void _reply;
    const principal = request.principal as
      (AuthenticatedPrincipal & { permissions?: Set<string> }) | undefined;

    if (!principal || !principal.userId) {
      return;
    }

    // Return early if permissions have already been resolved for this request
    if (principal.permissions instanceof Set) {
      return;
    }

    const orgId = options?.orgIdResolver
      ? options.orgIdResolver(request)
      : (principal.orgId ?? null);

    const effective = await checker.resolveEffectivePermissions(principal.userId, orgId);
    const permissionKeys = new Set<string>();

    for (const item of effective) {
      if (typeof item === "string") {
        permissionKeys.add(item);
      } else if (item instanceof Permission) {
        permissionKeys.add(item.key);
      } else if (item && typeof item === "object" && "key" in item) {
        permissionKeys.add(String((item as { key: string }).key));
      }
    }

    principal.permissions = permissionKeys;
  };
}
