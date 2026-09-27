# Use Cases (Application Layer)

`RegisterUser` (`packages/identity/application/use-cases/register-user.ts`,
Issue 030) is the first concrete example of the **command-handler pattern**
every use case in Verixa follows: one class, one job, orchestrating domain
objects and ports without containing business rules of its own.

## The shape

```ts
export interface RegisterUserCommand {
  readonly email: string;
  readonly displayName: string;
  readonly givenName?: string;
  readonly familyName?: string;
}

export type RegisterUserError = ValidationError | ConflictError;

export class RegisterUser {
  constructor(private readonly userRepository: UserRepository) {}

  async execute(command: RegisterUserCommand): Promise<Result<User, RegisterUserError>> {
    // 1. Parse/validate primitive input into value objects
    // 2. Check any cross-aggregate invariant the entity itself can't check alone
    //    (e.g. email uniqueness — a single User can't know about other Users)
    // 3. Construct/mutate the aggregate (which enforces its own invariants)
    // 4. Persist via the port
    // 5. Return the result
  }
}
```

Every use case:

- Is a class with **one public method**, conventionally named `execute`,
  taking a single **command** object (a plain data shape, `RegisterUserCommand`
  here) rather than positional parameters — adding a field later doesn't
  break every call site.
- Takes its dependencies (repositories, other ports) as **constructor
  parameters**, typed as the port interface, never a concrete adapter. This
  is what makes it testable without a database: pass an in-memory fake that
  satisfies the same interface (see `docs/guides/testing.md`).
- Returns `Result<T, E>` rather than throwing for expected failure modes
  (validation failure, a conflicting duplicate) — the same convention used
  throughout the domain layer, for the same reason: callers are forced to
  handle failure, and the type signature documents what can go wrong.

## Why use cases are the unit of application logic

A use case is deliberately the _only_ place that orchestrates multiple
steps against ports and aggregates for a single business operation. The
alternative — putting that orchestration in an HTTP route handler, or
spreading it across multiple entity methods — makes the same operation hard
to test without spinning up the interface layer, and hard to reuse if a
second interface (a CLI, a background job) needs to trigger the same
operation later. `RegisterUser.execute()` can be called identically from an
HTTP handler, a CLI command, or a test, with zero HTTP/CLI-specific code
inside it.

Business _rules_ still live in the domain layer, not here: `RegisterUser`
doesn't decide what makes an email valid (`Email.create` does) or what
status a new user starts in (`User.register` does). The use case's job is
narrower — sequencing calls to the domain and ports correctly — which is
exactly what keeps it a thin, easy-to-read orchestration layer instead of a
second place business rules could drift out of sync.

## Validate-before-write ordering

Note the order inside `RegisterUser.execute()`: every input validation
happens first (email format, display name, optional person name), _then_
the uniqueness check against the repository, _then_ the write. A failing
validation never reaches the repository at all — not even a read. This
isn't just tidiness: it means a caller retrying after a validation error
can trust that nothing was persisted, and it avoids spending a database
round-trip on input that was never going to succeed regardless of what the
repository would have said.

## What's deliberately not here yet

`RegisterUser` does not publish the `UserRegistered` event the created
`User` is carrying (`user.pullDomainEvents()`) — it returns the `User`
as-is, events attached. Wiring actual event publishing (via
`DomainEventPublisher`, once an implementation exists — see
`docs/guides/domain-events.md`) is deferred to whichever future issue
introduces the first publisher adapter and an interface-layer caller that's
responsible for the pull-then-publish step after a successful use case
call.

## Partial updates: `UpdateUserProfile`

`UpdateUserProfile` (Issue 032) is the same pattern applied to a different
shape: a command where every field except the id is optional
(`displayName?`, `givenName?`, `familyName?`), and only the fields actually
present get validated and changed. The use case loads the current `User`,
then for each optional field that _is_ present, validates it and tracks a
replacement value; fields absent from the command keep the aggregate's
current value untouched. This is a deliberate alternative to accepting a
`Partial<UpdateUserProfileCommand>` and merging it blindly: a field that's
`undefined` because the caller didn't send it, and a field explicitly being
cleared, are different intents (the same distinction `exactOptionalPropertyTypes`
enforces at the type level — see `docs/guides/typescript-conventions.md`).

### Aggregating multiple field errors

Where `RegisterUser` returns on the _first_ validation failure,
`UpdateUserProfile` collects field errors from every invalid field in the
command before returning — an update with both an invalid `displayName` and
an invalid `familyName` should tell the caller about both at once, not force
a fix-resubmit-fix-resubmit cycle to discover the second error. It does this
via `ValidationErrorAggregator` (`@verixa/shared-kernel`, Issue 036) — see
`docs/guides/error-handling.md` — rather than merging each field-level
`ValidationError`'s `fieldErrors` by hand, so every future multi-field use
case aggregates errors the same way instead of reimplementing the merge.

## Admin actions requiring a reason: `SuspendUser` / `ReactivateUser`

`SuspendUser` and `ReactivateUser` (Issue 033) wrap `User.suspend()` /
`User.activate()` — which take an _optional_ reason — with a use-case-level
rule that the reason is _required_. This is a good example of where a
constraint belongs at the use-case layer rather than the domain layer: it's
not that a `User` can't be suspended without a reason (the aggregate itself
has no opinion), it's that _this specific administrative action_ shouldn't
be triggerable without one, for audit accountability (Phase 10). Domain
layer: what's structurally possible. Use case layer: what's allowed for
this particular caller/flow.

`ReactivateUser` also shows a use case narrowing a domain rule that's
technically broader than what the action should mean: `User.activate()`
legally permits `pending → active` (email verification) as well as
`suspended → active` (lifting a suspension), because both are valid states
for `active` to follow. But "reactivate" as an admin action only makes
sense for a user who was actually suspended — so the use case checks
`user.status === "suspended"` itself before calling `activate()`, rejecting
a `pending` user even though the domain layer alone would have allowed it.

## Multi-aggregate transactions: `CreateOrganization`

Every use case up to this point touches one aggregate. `CreateOrganization`
(Issue 034) touches two: it creates an `Organization` _and_ the owner's
initial `OrganizationMembership`, and both must succeed or neither should
persist. This is where the use case's orchestration role earns its keep —
"an organization always has its owner as an active member" is a rule that
spans both aggregates, so it can't live inside `Organization.create` (which
has no way to also create an unrelated `OrganizationMembership`) or inside
`OrganizationMembership.create` (which doesn't construct organizations).
Only the use case sees both, so only the use case can enforce it.

There's no real database transaction wrapping the two `save` calls yet —
there's no database until Phase 03. What exists today is the _boundary_:
the use case defines exactly which operations must be atomic together, so
when the Prisma-backed adapters land, wrapping this specific sequence in
`db.$transaction(...)` is a mechanical follow-up, not a redesign.

## Domain skeletons ahead of their delivery mechanism: `InviteUserToOrganization`

`InviteUserToOrganization` and the `Invitation` entity it creates
(Issue 035) model a complete invitation lifecycle — issued, single-use,
expiring — before any code exists to actually email an invitation. That's
intentional: Phase 14 (Notifications) needs a correct, already-tested domain
concept to hook a delivery adapter onto, not a redesign of identity's
org-membership model to accommodate email sending. The use case validates
input, creates the `Invitation` (which records its own
`OrganizationInvitationCreated` event, `token`, and `expiresAt`), and
persists it — the "send the email with this token" step is simply not
implemented anywhere yet, which is a different thing from being designed
wrong. See `docs/guides/domain-modeling.md` for the general principle this
follows.

## Scoped uniqueness: `CreateRole`

`CreateRole` (`packages/authorization/application/use-cases/create-role.ts`,
Issue 130) enforces scoped uniqueness across role aggregates:
a role name must be unique within an organization (for organization-scoped roles)
or globally (for system and platform-level roles). The aggregate `Role` cannot enforce
uniqueness on its own across sibling aggregates, so the use case queries `RoleRepository.findByName(name, orgId)`
before persisting.

## Idempotent catalog registration: `DefinePermission`

`DefinePermission` (`packages/authorization/application/use-cases/define-permission.ts`,
Issue 131) registers permissions in the system catalog during module initialization or bootstrap.
Because bootstrap routines run on every server startup, registering a pre-existing permission
is designed to be idempotent: the use case performs a catalog check via `PermissionRepository.findByKey(key)`
and returns the existing permission rather than failing with a conflict error.

## Cross-aggregate catalog validation: `AssignPermissionToRole` / `RevokePermissionFromRole`

`AssignPermissionToRole` and `RevokePermissionFromRole` (`packages/authorization/application/use-cases/`,
Issue 132) demonstrate the classic DDD principle that cross-aggregate invariants belong in use cases:

- `AssignPermissionToRole` validates that a granted permission exists in the authoritative `PermissionRepository`
  catalog before mutating `Role`, preventing typos and unmanaged permissions from entering roles.
- `RevokePermissionFromRole` invokes `Role.revoke(permission)`, which protects system roles (`super-admin`)
  from having critical permissions stripped away, translating domain-level `SystemRoleImmutableError` into
  structured results.
