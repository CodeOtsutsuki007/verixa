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
