# Use Cases (Application Layer)

`RegisterUser` (`packages/identity/application/use-cases/register-user.ts`,
Issue 030) is the first concrete example of the **command-handler pattern**
every use case in Verixa follows: one class, one job, orchestrating domain
events, entities, and ports without containing business rules of its own.

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

## Cyclic Verification Loops: RequestMoreInformation

`RequestMoreInformation` orchestrates the reviewer-initiated transition from
`in_review → needs_more_info` requiring an explicit, visible note. This supports
the non-linear KYC workflow where evidence is insufficient without forcing
a full new request, preserving prior evidence and history across re-submits.

Alternative rejected: forcing users to create a brand new verification request
from scratch when a minor document blur occurs. Rejected because it discards
audit history and creates unnecessary user friction.
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

## Automated Checks & Human-in-the-Loop: `RunAutomatedCheck`

`RunAutomatedCheck` (`packages/verification/application/use-cases/run-automated-check.ts`, Issue 172) illustrates how third-party provider integrations are orchestrated without letting external systems bypass domain governance. The verification provider returns an automated signal (`pass`, `fail`, or `inconclusive`), but the status always lands in `in_review` rather than auto-approving or auto-rejecting.

We deliberately rejected auto-deciding on provider signals alone in v1: false positives or negatives in automated KYC carry severe real-world consequences, so keeping the human reviewer as the authoritative decision-maker protects users while automated results inform their review.

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

## The Policy Decision Point: `AuthorizeAction`

`AuthorizeAction` (`packages/authorization/application/use-cases/authorize-action.ts`,
Issue 153) follows the same command-handler shape as every use case above,
but is worth calling out on its own: it's the **Policy Decision Point**
(PDP, in XACML terminology) — the one canonical "can this subject do this
action on this resource" entry point every other context and route handler
is meant to call, rather than each writing its own ad hoc authorization
check. The **Policy Enforcement Points** that call it from route handlers
are Phase 12's job; this use case's job is only to decide, not to enforce.

```ts
const decision = await authorizeAction.execute({
  subjectId: user.id,
  action: "read",
  resourceType: "document",
  resourceId: document.id,
});

if (!decision.granted) {
  throw new ForbiddenError(decision.reason);
}
```

It wraps `AuthorizationService` (`docs/security/authorization-model.md`)
and has no HTTP/Fastify dependency, like every use case — callable
identically from a route handler, a CLI command, or a test.

### The decision always carries a reason

`AuthorizationDecision.reason` is populated on every path — granted, denied
by a policy, denied by RBAC, denied by the fail-closed default, _and_ a
resource-attribute resolution failure — and is written to be sufficient for
audit logging (Phase 10) on its own. This matters because an audit log
entry that only records `granted: false` answers "what happened" but not
"why," and reconstructing "why" later means re-running the same check
against whatever state existed at the time — which may no longer be
recoverable. Populating `reason` at decision time, once, while every input
that produced it is still in hand, is cheaper and more reliable than trying
to recover it after the fact.

### The policy-error path: fail closed, not fail open

If a `ResourceAttributeResolverRegistry` is wired in and the registered
resolver for a resource type throws (an upstream lookup failure, say),
`AuthorizeAction` does not skip resource-attribute resolution and evaluate
against whatever it has — it denies, with a reason naming the failure. The
alternative (proceeding with an incomplete attribute set) would silently
evaluate `DENY` rules that reference the unresolved attributes as though
they simply didn't match, which can turn an infrastructure failure into a
silent over-grant. This is the same fail-closed principle
`docs/security/authorization-model.md` applies one layer down.

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

## Streaming a large result: `ExportAuditEvents`

`ExportAuditEvents` (`packages/audit/application/use-cases/export-audit-events.ts`,
Issue 189) is the same command-handler shape as everything above, with one
deliberate difference: it returns `Result<AsyncIterable<string>, ValidationError>`
rather than `Result<T, E>` over a materialised value. It reuses
`QueryAuditEvents`' filters (`AuditLogFilters`) instead of defining its own, so
a compliance export can never drift from the in-app query it is meant to
mirror.

### Why a stream, not a string

The natural implementation — query every matching entry, build one string,
return it — is a memory bug waiting for a large enough log. A compliance
export is precisely the operation that runs against a log accumulated over
years, and buffering makes peak memory grow with the history being exported;
on a small container that is an out-of-memory kill in the middle of an
audited export. So the use case fetches the log one bounded page at a time
(`batchSize`, default 500) and yields each row as it goes. Peak memory is
flat no matter how much matches, and the caller pipes chunks straight to the
HTTP response, a file, or object storage. The cost is that the caller _must_
consume the iterable — there is deliberately no "give me the whole thing"
method, because that is the behaviour the design exists to prevent.

### Why newline-delimited JSON

The issue left JSON's shape as "newline-delimited or array JSON per a
documented choice". This chose NDJSON, because it is the shape that composes
with streaming. An array would force the writer to hold the opening bracket,
insert a comma before every element after the first, and close the bracket —
state that exists only to satisfy the format, not to carry information — and
it cannot be produced incrementally on its own. NDJSON also matches what
downstream tooling (`jq`, `grep`, log pipelines) actually consumes. The one
thing an array buys is being a single valid JSON document; a consumer that
needs that can wrap the stream at the edge.

### CSV injection

Metadata is the attacker-controlled field, so it gets two layers of defence:
serialised to JSON first (a value containing a comma, quote or newline can no
longer break out of its cell), then the whole resulting string is quoted and
its quotes doubled per RFC 4180. "Just join the fields with commas" is exactly
the injection the audit-metadata issue calls out, and the round-trip test in
`export-audit-events.spec.ts` pins the escaping against metadata laden with
delimiters, quotes and line breaks.
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
## Use cases that delegate their rules: the review flow

`ClaimNextReviewCase`, `ApproveVerification`, `RejectVerification` and
`RequestMoreInformation` (Issues 174 and 175, plus Issue 176's loop) are
notably thin, on purpose.

`ClaimNextReviewCase` owns only the policy it _can_ own — the claim lease
length, and whether a reviewer already holding a case may be handed another.
The guarantee that two reviewers never receive the same case cannot be
enforced in application code at all: it is enforced by the repository, with
`SELECT ... FOR UPDATE SKIP LOCKED` over the candidate row, because an
application-level read-then-write always leaves a window in which two callers
read the same unclaimed row. The use case returns `claimed` / `none` /
`already_claiming` rather than throwing, because an empty queue is an ordinary
outcome, not an error.

The decision use cases are thin for the opposite reason: they add _no_ rules
of their own beyond one — the mandatory rationale note. Transition legality,
and "only the reviewer holding the active claim may decide", live on the
aggregate, which owns the state machine and the claim. Duplicating either here
would create a second place the rules are encoded, and therefore a second
place they can disagree. The one rule that _is_ here — a non-empty note — is
here for the same reason `SuspendUser`'s reason is: it is about what this
specific administrative action is allowed to omit, not about what a
`VerificationRequest` structurally requires. See
`docs/security/authentication-flows.md` for the reviewer-decision
cross-reference.

## Read models shaped for their consumer: `ListReviewQueue`

`ListReviewQueue` (Issue 177) is the first use case here that only reads, and
it is shaped differently from the command handlers above on purpose.

It returns a `ReviewQueuePage` — `items`, `limit`, `offset`, `hasMore` — and
each `ReviewQueueItem` is a _projection_ of a `VerificationRequest`, not the
aggregate itself. That projection is the deliverable, not a convenience:
everything a queue row must not carry has to be absent from the type rather
than merely unread. Returning the aggregates and letting a serializer pick
fields would leave "the queue response contains no evidence pointer" to
whichever HTTP layer is written months later; projecting in the use case makes
it a property of the read path, testable at the layer that owns it. The test
that asserts this compares the row's _exact_ key set, so a field added to the
summary has to be a deliberate edit to the queue rather than a side effect of
widening the aggregate. This is the same read-model-per-consumer principle as
Issue 095, applied to a different list.

**The alternative rejected: an `includeEvidenceUrls` flag.** Issue 177's
wording — "returning signed evidence URLs only on demand" — reads like a
parameter, and a parameter was the first thing tried. It is the wrong shape
for now, for two reasons. The port that would mint a signed URL is
`EvidenceStorage` (Issue 166), which does not exist yet, so an accepted flag
would either be silently inert or drag a storage adapter into the queue's
dependency list for one optional field. And signing a URL per row is not "on
demand": the list view renders no document, so every page of the queue would
pay for signing work nothing displays. Signing belongs on the per-request
detail fetch, where the reviewer actually opens the document.

**Why the filters are pushed to the store rather than applied here.**
`status`, `verificationType`, `assignment`, `limit` and `offset` all go to
`findQueueCandidates`. A use case that fetched a page and then filtered it
would return short pages ("25 asked for, three returned") and, worse, skip
rows that a later page should have contained — the dropped rows were already
charged against `limit`. The store has the index for this predicate; the use
case has only the page.

**Why the queue filter takes a set of statuses.** The default queue view spans
two: `submitted` (waiting on the automated provider check) and `in_review`
(waiting on a reviewer). Asking the store twice and merging the results cannot
produce a stable order, because each call is ordered `createdAt ASC`
independently and the caller ends up re-sorting a partial view — at which
point `offset` no longer means "rows 26 to 50 of the queue". One query over
the existing `(status, created_at)` index is both correct and cheaper. The two
non-reviewable statuses are refused rather than answered with an empty page:
"the queue is empty" and "you asked the queue for decided requests" are
different answers, and only one of them is actionable.

**Why `hasMore` and not a total count.** The use case asks the store for one
row more than the page and reports whether it came back. A `COUNT(*)` is a
second round-trip over the same predicate, and on a queue that changes while
it is being read it is also the wrong number — count and page are read at
different instants, so the total could disagree with the rows actually
returned. A total is worth having when a UI shows "page 3 of 12" and the cost
of a second query is paid deliberately; nothing needs it yet, and `hasMore`
costs one row.

**Why a lapsed lease is not an assignment.** A claim is a lease, not a lock
(see `ReviewAssignment`), and nothing clears `assigned_reviewer_id` when it
expires — there is no scheduled job, because the whole point of an expiry is
that it needs none. So "assigned" means _a live claim_, "unassigned" means
"never claimed **or** lapsed", and the row reports `claim` only while it is
live. Reporting a lapsed lease would tell the UI a case is taken when it is
free to claim. That is also why the filter needs a `now`, supplied by the
caller exactly as `findActiveClaimByReviewer` already required — the two
statuses are the cycle that makes this non-linear, and the filter has to agree
with `VerificationRequest.isClaimableAt` rather than re-derive it.
