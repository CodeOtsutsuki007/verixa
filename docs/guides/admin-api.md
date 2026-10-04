# RBAC administration API

The API exposes role management under `/admin/roles` and user assignments
under `/admin/users/:userId/roles`. Requests must include the authenticated
principal's `x-user-id`; the principal must hold `roles:read` for reads and
`roles:write` for mutations. `x-organization-id` selects the tenant scope.

Mutating endpoints return `403` for an insufficient principal, including
attempts to delete a system role, grant `*:*` to a tenant role, or assign a
role that would elevate the caller beyond its current permissions. Repeating
an assignment is idempotent. The seed command creates the initial protected
roles before these endpoints are used.

Routes:

- `GET /admin/roles`, `POST /admin/roles`, `PATCH /admin/roles/:roleId`, `DELETE /admin/roles/:roleId`
- `GET /admin/permissions`
- `POST/DELETE /admin/roles/:roleId/permissions`
- `GET/POST /admin/users/:userId/roles`
- `DELETE /admin/user-role-assignments/:assignmentId`
