# RBAC design

Verixa uses roles as named bundles of permissions. Permission keys follow
`resource:action`; `resource:*` grants all actions for one resource and
`*:*` is reserved for the protected platform `super-admin` role.

## Default roles

| Role          | Scope        | Grants                                              |
| ------------- | ------------ | --------------------------------------------------- |
| `super-admin` | Platform     | `*:*`                                               |
| `org-owner`   | Organization | User, role, and organization read/write permissions |
| `member`      | Organization | `users:read`, `orgs:read`                           |
| `viewer`      | Organization | Read-only user, organization, and role access       |

The catalog and roles are installed by `seedDefaultRoles`. It uses stable
natural keys and upserts, so it is safe to run during every deployment. The
seed never grants `*:*` to a tenant role and never removes permissions that an
operator deliberately added to an existing role.

The viewer role is intentionally read-only. Keeping it explicit prevents a
new write permission from accidentally becoming available to every user who
was given the least-privilege role.
