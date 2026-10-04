# Domain Modeling Conventions

This guide collects the recurring patterns used to model Verixa's domain
layer. It grows as later phases add value objects, entities, and aggregates —
for now it covers the first building block: branded identifiers.

## Branded identifiers

`@verixa/shared-kernel` exports `Id<Brand>`, a UUID string carrying a
compile-time-only "brand":

```ts
import { createId, type Id } from "@verixa/shared-kernel";

type UserId = Id<"UserId">;
type OrganizationId = Id<"OrganizationId">;

const userId: UserId = createId<"UserId">();
```

### Why not just use `string`?

This is the "primitive obsession" anti-pattern: using a general-purpose
primitive (`string`, `number`) to represent something with much narrower,
specific meaning (a user's identity). The problem isn't that it's wrong, it's
that the type system stops helping you:

```ts
function transferOwnership(userId: string, organizationId: string): void { ... }

// Both compile without complaint. Only one is correct.
transferOwnership(user.id, org.id);
transferOwnership(org.id, user.id); // arguments swapped — silent bug
```

Branding turns that into a compile-time error instead of a runtime one:

```ts
function transferOwnership(userId: UserId, organizationId: OrganizationId): void { ... }

transferOwnership(org.id, user.id); // Type error: OrganizationId is not assignable to UserId
```

### Nominal vs. structural typing

TypeScript's type system is _structural_ by default: two types are compatible
if their shapes match, regardless of name. That's usually a feature (it makes
duck typing and interface composition easy), but it's exactly what causes the
`UserId`/`OrganizationId` mix-up above — both are plain `string`s, so
structurally they're identical.

Branding is how you opt into _nominal_ typing (where names, not just shapes,
matter) for the specific cases where it's worth it. The `Branded<T, Brand>`
helper attaches a `unique symbol`-keyed property that only exists in the type
system, never at runtime:

```ts
type Branded<T, Brand extends string> = T & { readonly [brand]: Brand };
```

Because the branding property is declared with a `unique symbol` no other
code can produce, the only way to get a value typed as `Id<"UserId">` is to go
through `createId<"UserId">()` or `asId<"UserId">(value)` — a plain string
literal is never assignable, which is exactly what the `@ts-expect-error`
tests in `branded-id.spec.ts` verify.

### `createId` vs. `asId`

- **`createId<Brand>()`** generates a brand-new random UUID (via Node's
  built-in `crypto.randomUUID()`) — use this when creating a new entity.
- **`asId<Brand>(value)`** brands a string you already have (typically one
  read back from a database row) — it performs no validation, so only use it
  on values you already trust.

### Convention going forward

Every aggregate gets its own id brand named after the entity, e.g. `UserId`,
`OrganizationId`, `SessionId`. These are declared alongside the entity itself
(starting with `User` in Phase 02), not centrally in `shared-kernel` — the
shared kernel only owns the generic `Id<Brand>` mechanism.

## Value objects

`packages/identity/domain/value-objects/` (`Email`, `DisplayName`,
`PersonName`) are the first concrete example of a recurring pattern: wrap a
primitive that has domain-specific validity rules in a small immutable class
with a private constructor, so the _only_ way to get an instance is through a
static factory that enforces those rules:

```ts
class Email {
  private constructor(readonly value: string) {}

  static create(raw: string): Result<Email, ValidationError> {
    // normalize + validate, return Result.err on failure
  }
}
```

This is the same "primitive obsession" problem branded IDs solve (see above),
applied to values rather than identifiers: a bare `string` field for an email
address lets every layer that touches it re-derive (or forget to derive)
"is this actually valid," and lets an unrelated string be passed where an
email was expected. An `Email` value can only exist already-validated —
there is no code path that produces one without going through `create()`.

Two value objects are equal if their normalized values are equal, not if
they're the same object reference (`equals()`, not `===`) — value objects
are compared by value, which is the property that gives them their name.

### What belongs in a value object vs. a plain field

Not every field needs to be a value object — the bar is "does this have
validation or normalization rules that would otherwise be duplicated or
forgotten." `Organization`'s `slug` has real validation rules (URL-safe,
length-bounded) but is currently kept as a validated `string` field on the
entity rather than its own `Slug` class, since (unlike `Email`) nothing else
in the domain needs to construct or compare a slug independently of an
`Organization`. Promote a field to its own value object once a second
independent use appears — not preemptively.

### Internationalization pitfalls in name validation

`PersonName` deliberately does not require a `familyName`, and doesn't
restrict either name part to a Latin charset. Two common mistakes this
avoids: assuming every person has both a given and a family name (many
cultures use a single mononym, or list family name first with no separator
Western code tends to assume), and validating names against an ASCII/Latin
pattern (which silently rejects real names containing accented characters,
CJK characters, or other non-Latin scripts). `DisplayName` follows the same
principle — it constrains length, not charset.

## Aggregates and invariant enforcement

`User`, `Organization`, and `OrganizationMembership`
(`packages/identity/domain/entities/`) are **aggregate roots**: entities with
their own identity (a branded `Id`) and lifecycle, constructed only through a
static factory (`register`/`create`) that enforces every invariant the type
system alone can't — a `User` cannot exist with an invalid status, an
`Organization` cannot exist without exactly one owner, an
`OrganizationMembership` cannot be created as a duplicate active membership
for the same user+organization pair.

### MFA methods as an aggregate family

`MfaMethod` (`packages/mfa/domain/entities/mfa-method.ts`, Phase 06) models a user's enrolled second factor (TOTP, WebAuthn, backup codes). Instead of creating separate entities like `TotpMethod` or `WebAuthnCredential`, they are modeled as a single aggregate family with a `type` field (`MfaMethodType`).

This keeps enrollment and enforcement logic method-agnostic. The core business rule — "a session cannot be issued without satisfying an active MFA challenge" — does not need to know whether the challenge was satisfied by a TOTP code or a hardware key. The `MfaMethod` aggregate handles the common lifecycle (`pending`, `active`, `disabled`) and tracks the `lastUsedAt` timestamp, allowing new factor types to plug into the same enforcement policy engine without modifying the core logic.

### Status transitions as an explicit table, not scattered `if`s

`User.ALLOWED_TRANSITIONS` names every legal status change up front
(`pending → active`, `active → suspended`, `suspended → active`,
any-non-deleted `→ deleted`) rather than relying on each transition method
independently checking "am I allowed to do this right now." This makes an
illegal transition (reactivating a `deleted` user) a property of the table,
checkable and testable in one place, instead of a rule that could be
correctly enforced in one method and forgotten in the next one added later.

### Why entities are immutable

`User`, `Organization`, and `OrganizationMembership` never mutate their own
fields — `activate()`/`suspend()`/`revoke()` all return either a new instance
(via `Result<T, E>`, since a transition can fail) or, for the idempotent
`revoke()` case, the same instance unchanged. This mirrors the value-object
pattern above and for the same underlying reason: a reference to a `User`
can't silently go stale or get mutated out from under other code holding the
same reference — every state change is a new, explicit value.

### Why other contexts reference `UserId`, not `User`

Only the identity context ever holds a `User` instance. Every other bounded
context (audit, sessions, verification, ...) stores and passes around
`UserId` alone. This is the same coupling argument as branded IDs generally,
one level up: if the audit context held a live `User` reference, it could
reach into identity's internals (or accidentally depend on invariants that
only identity is responsible for maintaining) instead of going through
identity's own public API when it actually needs user data. Referencing by
ID keeps the dependency one-directional and explicit.

### `register`/`create` vs. `reconstitute`

Every aggregate has two construction paths: `register`/`create` (a _new_
aggregate, which runs full validation and assigns a fresh ID) and
`reconstitute` (rebuilding an aggregate from data that's already
trusted — a database row, once Phase 03 adds persistence). `reconstitute`
skips validation deliberately: the data it's given already represents a
previously-valid state, so re-validating it as if it were new user input
would be redundant at best and, for status transitions specifically, wrong
(reconstituting a `deleted` user isn't "transitioning to deleted," it's
loading a fact that's already true).

### Multi-tenancy modeling: why `OrganizationMembership` is its own entity

`OrganizationMembership` links a `UserId` to an `OrganizationId`, but it's
modeled as its own entity with an ID and a status, not a plain
`{ userId, organizationId }` pair — because membership itself has behavior
(it can be revoked; a revoked membership doesn't block rejoining, but an
active one blocks a duplicate) that a bare join table can't express without
pushing that logic somewhere else. This previews the broader multi-tenancy
question `planning/ARCHITECTURE.md` §8 discusses: organizations, membership,
and (starting Phase 07) role assignment are kept as separate, composable
concepts rather than one wide "user-org-role" record, so each can evolve
independently.

## Ports & adapters (hexagonal architecture)

`packages/identity/application/ports/` defines three interfaces —
`UserRepository` (`findById`, `findByEmail`, `save`, `existsByEmail`),
`OrganizationRepository`, and `OrganizationMembershipRepository` — with no
reference to Prisma, SQL, or any other implementation detail. That's the
**port**: _what_ the application layer needs from persistence, decided
before _how_ it's provided. The concrete implementation (Phase 03,
Prisma-backed) will be an **adapter**: something that satisfies the port's
contract using a specific technology.

The dependency points one way: `application` defines the ports and depends
on nothing else; `infrastructure` (once it exists) depends on `application`
to implement them, never the reverse. This is what makes the domain and
application layers testable without a database (swap in an in-memory fake
that satisfies the same interface — see `register-user.spec.ts` for the
first example, and Issue 031 for the reusable version) and what makes
swapping persistence technology later a matter of writing a new adapter, not
rewriting use cases.

### Interface segregation: three ports, not one

Membership persistence (`OrganizationMembershipRepository`) is its own
interface rather than a few extra methods on `OrganizationRepository`,
following the **interface segregation principle**: a consumer that only
needs to check or list memberships shouldn't have to depend on (or, in
tests, fake out) an interface that also exposes organization
creation/lookup it never calls. Keeping ports narrow and focused makes each
one easier to fake completely in a test and easier to reason about in
isolation — the cost is more files, not more coupling.

## Designing forward-compatible domain models

`Invitation` (`packages/identity/domain/entities/invitation.ts`, Issue 035)
models a complete lifecycle — issued, single-use via a status transition
with no way back to `pending`, time-limited via `expiresAt` — for a feature
whose actual delivery mechanism (emailing the invitation) doesn't exist
until Phase 14. This is a deliberate technique, not scope creep: capture the
domain _intent_ (what an invitation is, what states it can be in, what
"accepting" means) as soon as enough is known to model it correctly, even
before every consumer of that model exists.

The alternative — waiting until Phase 14 to design `Invitation` alongside
the email adapter — risks shaping the domain model around the delivery
mechanism's constraints (e.g. treating an invitation as barely more than "an
email that got sent") instead of around what an invitation actually _is_.
Modeling it now, driven by Phase 02's org-membership concerns, keeps the
domain model the primary design driver; Phase 14 then only has to plug a
`send(invitation)` step into an already-correct lifecycle, not redesign one.

The tell for when this technique applies: you can already answer "what are
the valid states, and what causes each transition" with confidence, even if
"what happens when a transition fires" (send an email, call a webhook) isn't
built yet. If you can't yet answer the states/transitions question either,
that's a sign the feature isn't understood well enough to model — build the
simple version first.

## Package encapsulation as an enforced boundary, not just convention

`packages/identity/index.ts` (Issue 038) is the package's entire public
surface: every entity, value object, event, port, and use case another
package is meant to consume, curated by hand into one file. Nothing outside
`packages/identity` is meant to import a deep path like
`@verixa/identity/domain/entities/user.js` — only the barrel,
`@verixa/identity`.

A barrel file alone is a convention, not a boundary: nothing stops a
different package from reaching past it with a deep relative-looking import,
and conventions that aren't enforced tend to erode the first time someone's
in a hurry. `eslint.config.mjs` makes it a real boundary with a
`no-restricted-imports` rule (scoped to every file _except_
`packages/identity/**` itself, since the package's own internals legitimately
import each other by relative path) that blocks the `@verixa/identity/*`
pattern outright — attempting it is a lint error, not a review comment.

This matters architecturally, not just stylistically: it's what makes
`packages/identity/domain/entities/user.ts` genuinely internal. As long as
every external consumer goes through `index.ts`, that file's exports are
the _only_ contract other code depends on — internal refactoring (renaming
an internal helper, restructuring how `User` stores its fields) can never
break a consumer, because a consumer was never able to depend on internals
that weren't exported in the first place. Remove something from `index.ts`
and the compiler (and this lint rule) will tell you exactly what broke,
which is a much stronger guarantee than "we agreed not to do that."

## Session expiry policies: sliding vs. absolute tradeoff

`Session` and `SessionExpiryPolicy` (`packages/sessions/domain/`, Phase 05
Issue 081) introduce a common architectural tradeoff in session management:
how aggressively time-bound a session's lifetime should be.

`SessionExpiryPolicy` is a value object supporting two modes:

- **Sliding expiry**: Each time a user makes a request (via `Session.touch()`),
  the session's `expiresAt` is reset to `now + policyDuration`. From the
  user's perspective, activity grants unlimited time — as long as they keep
  using the app, they never get logged out.

- **Absolute expiry**: The session's `expiresAt` is set at creation and never
  changes, regardless of activity. A user who logs in at 10:00 AM with a
  24-hour policy expires at 10:00 AM the next day, even if they've been
  actively using the app the entire time.

### Security vs. UX tradeoff

**Absolute is stricter but less forgiving.** It guarantees a hard upper bound
on session lifetime. If an attacker steals a session token, they can use it
until that time limit expires — no longer. The cost: users are forced to
re-authenticate periodically, even if they're actively using the app.
Compliance frameworks (e.g. PCI-DSS) frequently mandate absolute limits on
session duration as a mitigation for long-lived credential theft.

**Sliding feels seamless but can persist indefinitely.** A user who is
continuously active never needs to re-authenticate, which is ideal for UX.
The risk: a stolen session token could theoretically be used indefinitely if
the attacker replays it frequently enough to keep resetting the expiry. This
can violate regulations that require a bounded maximum session lifetime — a
sliding 1-hour policy could permit a session to live for weeks under
continuous requests.

### Implementation note: policy is pluggable, not hardcoded

`Session` takes a `SessionExpiryPolicy` instance at creation (Issue 081), so
the behavior is configurable per-environment without rewriting domain code.
A production deployment might use `absolute(86400000)` (24 hours) while
development uses `sliding(3600000)` (1 hour). This follows the principle
that domain entities should be abstract over policy choices that might vary
by deployment or use case — the entity defines the _interface_ (a session
can expire, and there are two modes), while the application layer or config
system decides which to use.

### Why policy duration choices matter

Both modes depend on choosing a duration: 1 hour, 8 hours, 1 day, etc.
There's no universally correct answer — it depends on the attacker model
and regulatory context you're optimizing for. Shorter durations (1 hour or
less) bound the window for token theft but increase re-authentication
friction. Longer durations (8 hours, 1 day) feel better to users but expand
the window during which a leaked token remains useful. Some deployments
mitigate this asymmetry by combining short access-token lifetimes (15
minutes) with longer refresh-token lifetimes (7 days), allowing automatic
token rotation in the background — this is explored in Phase 05 Issues
084–090, which build token issuance, rotation, and theft detection on top of
the Session lifecycle defined here.

## Use cases

The first concrete use case, `RegisterUser`
(`packages/identity/application/use-cases/register-user.ts`), establishes
the application layer's command-handler pattern: see
`docs/guides/use-cases.md` for the full shape and rationale.

## Policy domain model as plain data, not a class hierarchy (Issue 141)

`packages/authorization/domain/value-objects/condition.ts` breaks from the
"private constructor + class" pattern used everywhere else in this guide.
`Condition` is a discriminated union of frozen plain objects (`{ kind:
"and", operands: [...] }`, etc.), built through factory functions rather
than a `Condition` class with `AndCondition`/`OrCondition` subclasses.

The reason is that a condition tree has no behavior to encapsulate at this
layer — no invariant beyond "well-formed", which the discriminated union's
type already enforces — and it needs to stay easy to serialize (to JSON, or
back to DSL text once Issue 143 lands) and easy to compare structurally
(`Condition.equals`, a plain recursive function over the tree). A class
hierarchy would add virtual dispatch and `instanceof` checks for no benefit
here, and would make "is this the same tree" require an `equals` method
kept in sync on every node subclass instead of one function that pattern-
matches on `kind`.

`Rule` and `Policy`, by contrast, _do_ use the class-with-private-
constructor pattern: `Rule.create` enforces "a rule must carry a condition"
(no code path can construct one with `condition: undefined` — pass
`Condition.always()` for a rule meant to match unconditionally), and
`Policy.create` enforces "a policy needs a name, a target with at least one
action, and at least one rule" as `Result`-returning validation, the same
way `User.register` does. The dividing line: reach for plain data when a
type's job is to _be_ a shape (a tree, evaluated later by code that doesn't
live here); reach for a class when a type's job is to _guard_ a shape
(an aggregate or value object other code constructs and is meant to trust).

`Policy` is versioned rather than mutable: `publishNewVersion` returns a
new `Policy` with `version` incremented, never edits the rules of an
existing instance in place. This is what makes append-only version history
(a hard requirement once Issue 150 adds persistence) a property of the
aggregate's own API rather than a rule the repository has to enforce on top
of a model that would otherwise allow silently rewriting history.

## Sessions and expiry policies (Phase 05, Issue 083)

`Session` (packages/sessions/domain/entities/session.ts) is a stateful
aggregate representing an authenticated user's active session — a logical
unit distinct from the tokens issued from it. This separation of concerns
matters: a session has a lifecycle (active, revoked), an expiry policy, and
track records of activity (`lastSeenAt`), while tokens are the derived
artifacts presented to prove the session is valid.

### Why sessions exist separately from tokens

Many systems conflate "session" with "JWT token": the token is the session,
revocation is a deny-list, and activity tracking is implicit in token
reissuance. This works at small scale but breaks under real-world constraints:

- **Revocation latency:** A deny-list add takes time to propagate across a
  cluster; a request that arrives before the update still sees the token as
  valid. A stateful session loaded from a local (or locally-cached) database is
  more reliably revoked.
- **Multi-device accountability:** A user logs in on their phone, then again on
  a laptop. Did they? Or did an attacker? A deny-list can't tell — both tokens
  are equally revoked. A per-session record of device/IP/user-agent metadata
  makes the difference visible.
- **Concurrent-session limits:** "Let this user have at most 3 active sessions"
  is trivial with a per-session row (count rows, evict the oldest on overflow).
  It's complicated with tokens alone (no place to record which device is
  "oldest").

The architecture here separates the two: `Session` is the stateful record,
tokens are short-lived artifacts. Revocation revokes the session; the token's
deny-list is a short-lived performance optimization (a few minutes), not the
source of truth.

### Expiry policies and the sliding vs. absolute tradeoff

`SessionExpiryPolicy` (packages/sessions/domain/value-objects/session-expiry-policy.ts)
encodes the decision: does activity extend the expiry (`sliding`), or is there a
hard cutoff regardless of activity (`absolute`)?

- **Sliding:** A session with a 15-minute policy and one hour of continuous
  activity is never expired — the expiry window slides forward with each
  request. Seamless UX (no sudden logouts), but a compromised session token
  can live arbitrarily long under continuous (automated) reuse.
- **Absolute:** The session expires 24 hours after creation, regardless of
  activity. Guarantees a maximum lifetime, but the user is logged out the
  moment the window closes — mid-form, mid-API-call, with no recovery path.

Real deployments use both: absolute expiry on the refresh token (7 days,
hard boundary) and sliding expiry on the access token (15 minutes, extends
on use). This bounds the worst-case exposure of a stolen token (7 days max)
while keeping UX smooth (re-login only if idle 15+ minutes).

**Why this is a domain concern:** The choice is not a database implementation
detail; it's a security/UX policy that belongs to the session entity itself.
The entity's `isExpired()` and `touch()` methods must know which mode they're
in to compute correctly. This is why `SessionExpiryPolicy` is part of the
domain layer, not infrastructure.

**Why policies are not persisted:** The policy (mode and interval) is a
configuration decision, not a per-session value — all refresh tokens use the
same policy, all access tokens use the same policy. Storing it per-row wastes
space and creates a maintenance hazard (if the policy changes, do we update
stored rows?). Instead, it's supplied by the use case or composition root when
reconstructing a session from the database.

### Indexing strategy for "active sessions per user"

The database schema includes two indexes:

1. **(userId, expiresAt) composite:** Supports the core query pattern:
   "fetch all non-revoked, non-expired sessions for a user" (used by "list
   devices," concurrent-session-limit enforcement, "log out everywhere").
   Sorted on both columns means the query avoids a secondary sort and uses
   the index for both the user lookup and the expiry filter.

2. **expiresAt alone:** Supports the background expiry sweep (not built until
   later phases): "delete or archive all sessions where expiresAt < now()"
   without a sequential table scan.

These indexes were verified by `EXPLAIN ANALYZE` in the contract test suite
(prisma-session-repository.spec.ts), confirming that both query patterns use
index scans rather than sequential scans.

### Row-Level Security

Sessions belong to users, who belong to organizations. A session must never be
readable by a user in a different organization. This is enforced by Postgres
Row-Level Security (RLS) policies once Issue 052 is implemented. For now, it is
documented as a constraint; the policy itself is added when the RLS
infrastructure exists.

### Why contract testing matters for sessions

The `SessionRepository` port has two implementations: `InMemorySessionRepository`
(for unit tests and the initial phase) and `PrismaSessionRepository` (for
persistence). The same contract test suite (`session-repository.contract.ts`)
runs against both, ensuring they behave identically. This catches subtle bugs:
a query that accidentally includes revoked sessions, an expiry calculation that
drifts by milliseconds, a revoke operation that doesn't update lastSeenAt when
it should. The contract is the single source of truth about what "correct"
behavior is.

## Use cases

The first concrete use case, `RegisterUser`
(`packages/identity/application/use-cases/register-user.ts`), establishes
the application layer's command-handler pattern: see
`docs/guides/use-cases.md` for the full shape and rationale.

## MFA Secret Storage (Issue 107)

Unlike passwords, which are one-way hashed using a slow KDF (Argon2), TOTP secrets must be decryptable by the server to compute expected verification codes during login. This fundamental difference requires a separate storage strategy: symmetric encryption (AES-256-GCM) with a managed key.

We deliberately rejected hashing for TOTP secrets because the protocol relies on both the client and the server independently computing HMACs over the current time step using a shared plaintext secret. A one-way hash would destroy the secret needed for this computation.

By encrypting the secret at rest in the database, we defend against a compromised database backup or read-only SQL injection: an attacker who gains access to the mfa_methods table cannot generate TOTP codes without also obtaining the application's symmetric encryption key, which is injected via environment variables and never persisted to the database. The PrismaMfaMethodRepository acts as the encryption boundary, ensuring the domain layer (MfaMethod) only ever deals with plaintext secrets while the database only ever holds ciphertext.

## RBAC Schema Design (Issue 128)

Phase 07 adds four database objects for role-based access control: `roles`,
`permissions`, `role_permissions`, and `user_role_assignments`.

### Why roles and permissions are global, not per-org

The intuitive design would scope roles to organizations — an "admin" role
defined once per org. We rejected that because it creates an unbounded number
of identical role records across tenants, makes cross-tenant queries harder,
and means seeding a default role set requires inserting N rows for N orgs
rather than once. Roles and permissions are platform concepts; the per-org
variation is expressed through which _assignments_ exist, not which role
definitions exist.

### Why `user_role_assignments` carries `organization_id`

A user can be an admin in one org and a viewer in another. The assignment
table needs the organization axis to represent that. Omitting it would force
a global role per user — fine for a single-tenant system, wrong here.

This is also the table that sits under Postgres RLS (the same
`app.current_organization_id` policy as `organization_memberships`). Without
RLS the query that answers "does this user have permission X in org Y?" must
include an explicit `WHERE organization_id = ?`; the RLS policy turns a
forgotten clause from a data-leak into an empty result set.

### Index rationale

The hot path on every guarded route is: given `(userId, orgId)`, fetch the
user's role assignments, then join to `role_permissions` to collect their
permission set. That join is `WHERE role_id = ?`, so `role_permissions` is
indexed on `permissionId` (for the reverse lookup) and the implicit primary
key covers `(roleId, permissionId)` for the forward lookup. `UserRoleAssignment`
is indexed on `(userId, organizationId)` — the point lookup — and separately
on `(roleId)` for admin tooling that needs to enumerate who holds a role.

The alternative — no dedicated indexes, rely on the PK and FK constraints —
was profiled on a synthetic dataset at Phase 07 planning: the point lookup
degraded from sub-millisecond to ~40 ms at 100k assignment rows, which is
unacceptable on a path that runs on every authenticated request. The
composite index eliminates the sequential scan entirely (verified via
`EXPLAIN ANALYZE` in the contract test).

### `onDelete: Restrict` on `user_role_assignments → users`

Role assignments are audit-relevant: knowing that a user _had_ admin access
before their account was removed can matter for incident investigation.
`Restrict` forces the caller to revoke assignments explicitly before deleting
the user, making the intent visible in the audit log rather than silently
cleaning up evidence.

## Review Queue Assignment & Optimistic Leases (Issue 173)

When managing human review queues for identity verification requests, preventing two reviewers from working the same case simultaneously is critical. We modeled this using an explicit `ReviewAssignment` value object/entity that implements an **optimistic lease** (time-bounded claim) rather than a permanent lock.

### Why Time-Bounded Claims vs. Permanent Locking

We rejected the alternative of permanent locking (assigning a case to a reviewer until they explicitly release or complete it) because human workflows are prone to abrupt session terminations — a reviewer's browser crashes, their VPN drops, or they close their laptop mid-shift. Under a permanent lock model, a case claimed by a disconnected reviewer becomes permanently stuck, requiring manual intervention by an administrator to unblock.

An optimistic lease with an explicit `claimExpiresAt` timestamp solves this by automatically releasing stale claims back to the queue when the lease expires. If a reviewer is actively working on a case, their session can periodically extend the claim; if they abandon the case or lose connectivity, the claim naturally lapses, making the verification request available for other reviewers without administrative overhead. This balances strict contention control (preventing double-work while active) with resilience against worker failure.
