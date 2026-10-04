# Route Guards (Authorization)

Fastify route guards in Verixa provide a declarative mechanism to enforce role-based access control (RBAC) at the routing layer without leaking sensitive domain logic or resource existence.

## `requirePermission` Route Guard

`requirePermission` (`packages/authorization/interface/guards/require-permission.ts`, Issue 136) is a Fastify `preHandler` factory that inspects the authenticated `request.principal` (established by authentication middleware) and evaluates effective permissions via `PermissionChecker`.

### Usage

```ts
import {
  requirePermission,
  requireAnyPermission,
  requireAllPermissions,
} from "@verixa/authorization";

// Enforce a single permission
app.get(
  "/admin/users",
  { preHandler: [requirePermission(permissionChecker, "users:read")] },
  async (request, reply) => {
    return { users: [] };
  },
);

// Enforce that the principal possesses any of the listed permissions
app.get(
  "/dashboard",
  { preHandler: [requireAnyPermission(permissionChecker, ["articles:read", "billing:manage"])] },
  async (request, reply) => {
    return { status: "ok" };
  },
);

// Enforce that the principal possesses all listed permissions
app.delete(
  "/organizations/:id",
  { preHandler: [requireAllPermissions(permissionChecker, ["orgs:write", "orgs:delete"])] },
  async (request, reply) => {
    return { deleted: true };
  },
);
```

## Security & Design Principles

1. **Deny-By-Default & Fail-Closed**:
   If `request.principal` is missing, unauthenticated, or lacks the necessary granted permissions within the organization scope, the guard immediately rejects the request with `403 Forbidden`.

2. **No Permission Name Leakage**:
   The response returns a generic JSON error body:
   ```json
   {
     "error": {
       "code": "FORBIDDEN",
       "message": "You do not have permission to perform this action."
     }
   }
   ```
   Permission identifiers (e.g. `orgs:delete`) are never reflected back to unauthorized callers, preventing external permission-enumeration oracle attacks.

---

## Request-Scoped Principal Resolution & Per-Request Memoization (Issue 137)

### Problem Statement

When complex routes compose multiple authorization guards (or execute route handlers that perform secondary permission checks), evaluating permissions repeatedly against the database/cache adds latency and CPU overhead.

### `createResolvePrincipalHook`

The `createResolvePrincipalHook` (`packages/authorization/interface/hooks/resolve-principal.ts`) runs as a Fastify `onRequest` or `preHandler` hook.

```ts
import { createResolvePrincipalHook, requirePermission } from "@verixa/authorization";

// Register resolution hook globally or per-router scope
app.addHook("preHandler", createResolvePrincipalHook(permissionChecker));

// Subsequent guards on the route reuse the memoized request.principal.permissions
app.get(
  "/admin/reports",
  {
    preHandler: [
      requirePermission(permissionChecker, "reports:read"),
      requirePermission(permissionChecker, "audit:read"),
    ],
  },
  async (request, reply) => {
    return { data: [] };
  },
);
```

### Architectural Guarantees & Memoization Rationale

1. **Per-Request Memoization (Request Lifetime Only):** Permissions are resolved exactly once and stored on `request.principal.permissions`.
2. **Freshness Over Cross-Request Caching:** Cross-request permission caching was deliberately **rejected**. Caching permissions across HTTP requests would reintroduce the risk of serving stale permissions after a role revocation or session termination (similar to the session invalidation guarantees in Issue 088). Per-request memoization delivers high performance for complex pipelines while ensuring absolute freshness for every new incoming request.
3. **Unauthenticated Safety:** If a request has not been authenticated, the resolution hook completes as a no-op without throwing errors, allowing upstream auth middleware or downstream guards to handle unauthenticated requests consistently.
