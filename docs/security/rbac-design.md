# Role-Based Access Control (RBAC) Design

This document details the security architecture and domain invariants governing Role-Based Access Control (RBAC) in Verixa (`packages/authorization`).

---

## 1. Core Abstractions

Verixa's authorization model decomposes access control into three decoupled primitives:

1. **`Permission` (Value Object):** An immutable identifier in `resource:action` format (e.g., `users:read`, `roles:write`, `audit:export`). Permissions represent fine-grained capabilities.
2. **`Role` (Aggregate Root):** A named bundle of permissions. Roles allow operational scaling: instead of managing individual permissions for thousands of users, administrators manage permission bundles that are assigned to users.
3. **`UserRoleAssignment` (Domain Entity):** A join entity linking a user to a role, optionally scoped to a tenant organization (`orgId`) or designated globally (`orgId: null`), with temporal bounds (`expiresAt`) for elevation.

---

## 2. System-Role Protection & Invariants (Issue 123)

### The Purpose of System Roles

Every deployment requires at least one break-glass administrative role (typically seeded as `super-admin`) that guarantees platform manageability, disaster recovery, and tenant troubleshooting.

If an operator, administrative user interface, or automation script were to inadvertently strip permissions from or rename a system role, the system could enter an unrecoverable lockout state where no user has sufficient privileges to restore normal operations.

To eliminate this vulnerability, roles flagged with `isSystemRole: true` enforce strict protection invariants directly at the domain layer:

- **Permission Revocation is Strictly Prohibited:** Calling `role.revoke(permission)` on a system role unconditionally throws a `SystemRoleImmutableError` (HTTP 403).
- **Renaming is Strictly Prohibited:** Calling `role.rename(newName)` on a system role unconditionally throws a `SystemRoleImmutableError` (HTTP 403).
- **Permission Expansion is Allowed:** Calling `role.grant(permission)` remains permissible. As new subsystems and capabilities are deployed, administrators must be able to endow break-glass roles with newly introduced permissions.
- **Description Updates are Allowed:** Informational metadata (such as documentation notes in `role.description`) can be updated without compromising access guarantees.

---

## 3. Design Decisions & Alternatives Rejected

### Alternative 1: API-Layer Enforcement Only

- **Proposed:** Only check `isSystemRole` inside Fastify route handlers or application use cases before calling role mutation methods.
- **Why Rejected:** Enforcing protection exclusively at the perimeter leaves the domain vulnerable to internal maintenance scripts, database seeders, scheduled jobs, and developer tooling. If an internal script calls `role.revoke()` directly, the restriction would be bypassed. Enforcing invariants inside the `Role` aggregate root guarantees that the rule holds regardless of how the entity is invoked.

### Alternative 2: Complete Immutability (Rejecting `grant` as Well)

- **Proposed:** Freeze system roles completely, forbidding both `grant` and `revoke`.
- **Why Rejected:** Applications evolve over time. When new resource types and actions are introduced in future releases (e.g. Phase 09 verification reviews, Phase 10 governance policies), system roles must be granted access to these new resources. Forbidding grants would require high-risk raw database migrations to upgrade system role capabilities. Granting permissions expands access safely without risking lockout.

### Alternative 3: Silent No-Op on Revocation

- **Proposed:** If `revoke()` or `rename()` is called on a system role, silently return without mutating the entity instead of throwing an error.
- **Why Rejected:** Silent no-ops create severe operational hazards. An administrator attempting to tighten permissions or retire an obsolete capability would see an apparent success in the UI while the permission remains fully active behind the scenes. Raising a dedicated `SystemRoleImmutableError` (distinguishable from general validation errors) ensures the caller is immediately informed that system roles cannot be degraded.

---

## 4. Role Assignment & Scope Invariants (Issue 133)

### Multi-Tenant Isolation

1. **Tenant-Scoped Roles:** A role created with an explicit `orgId` represents an organization-specific policy (e.g. `billing-manager` for Acme Corp). The `AssignRoleToUser` use case strictly validates that an organization-scoped role can only be assigned within its designated organization. Attempting to assign an Org A role to Org B or assigning it globally (`orgId: null`) is rejected with a `ValidationError`.
2. **Global Roles:** Roles created with `orgId: null` represent platform-level or cross-tenant templates. They may be assigned either globally (`orgId: null`) for system operators, or bound to a specific tenant scope (`orgId: <OrgId>`) if acting as an organization role template.

### Temporal Elevation & Expiration

Assignments support optional `expiresAt` timestamps for temporary access elevation (e.g., break-glass debugging or on-call rotations).

- Domain rules enforce that `expiresAt` must be strictly in the future relative to `assignedAt`.
- The `PermissionChecker` application service enforces deny-by-default and filters out expired assignments by default at query time.

### Idempotent Assignment

If `AssignRoleToUser` is invoked for a `(userId, roleId, orgId)` tuple where an active, non-expired assignment already exists, the use case completes idempotently and returns the existing assignment.

---

## 5. Revocation Semantics & Privilege Escalation Prevention

### Dual Revocation Modes

The `RevokeRoleFromUser` use case supports two revocation pathways:

1. **By Assignment ID:** Revokes a specific assignment by its unique `UserRoleAssignmentId`. Returns `NotFoundError` if the assignment does not exist.
2. **By Composite Key `(userId, roleId, orgId)`:** Locates the active role assignment for the given subject and scope, then removes it. Returns `NotFoundError` if no matching active assignment is found.

### Privilege Escalation Prevention

To prevent unauthorized privilege escalation when managing roles and assignments:

- Route guards (`requirePermission("roles:assign")` / `requirePermission("roles:revoke")`) gate role assignment endpoints.
- Actor attribution (`assignedBy`, `assignedAt`) is permanently captured on every assignment entity to maintain a complete security audit trail.

---

## 6. Permission Resolution Architecture (`PermissionChecker`) (Issue 134)

### Purpose & Responsibilities

The `PermissionChecker` application service provides the single authoritative engine for evaluating access decisions (`hasPermission`, `hasAnyPermission`, `hasAllPermissions`, and `resolveEffectivePermissions`).

### Deny-by-Default (Fail-Closed Security)

- Any principal without active, non-expired role assignments has an empty effective permission set and is unconditionally denied access (`hasPermission` returns `false`).
- Empty permission requirements:
  - `hasAllPermissions` with an empty collection vacuously returns `true`.
  - `hasAnyPermission` with an empty collection returns `false`.

### Multi-Role Union & Overlapping Permissions

When a user holds multiple active role assignments in a given scope (e.g. `reader` and `writer`), `PermissionChecker` unions the granted permissions across all active roles. Overlapping grants are deduplicated.

### Temporal Filtering

When resolving active assignments, `UserRoleAssignmentRepository` excludes expired assignments based on reference evaluation time `options.now` (`new Date()`). Lapsed temporary elevations immediately cease granting privileges without manual administrative intervention.

### Scope Merging

When evaluating a tenant context (`orgId: OrgId`):

1. `PermissionChecker` resolves all active assignments specifically scoped to `orgId`.
2. It simultaneously merges system-wide global assignments (`orgId: null`).
3. It evaluates whether any granted permission matches the required permission (supporting action wildcards such as `admin:*`).
