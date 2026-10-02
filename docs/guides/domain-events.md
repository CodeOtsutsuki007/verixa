# Domain Events

`@verixa/shared-kernel` exports `DomainEvent`, `BaseDomainEvent`, and
`DomainEventPublisher` (`packages/shared-kernel/domain/domain-event.ts`) —
the generic mechanism every bounded context uses to make its aggregates'
state changes observable to the rest of the system.

## What a domain event is

A domain event is a fact about something that already happened to an
aggregate, named in the **past tense** — `UserRegistered`, not
`RegisterUser` — because by the time anything observes it, it's no longer
possible to reject or reverse: the aggregate already transitioned. This is
what separates an event from a command: a command (`RegisterUser`, Issue 030) can fail; an event, once recorded, is simply a statement of what
happened.

```ts
export class UserRegistered extends BaseDomainEvent {
  readonly eventName = "identity.user.registered";
  readonly email: string;

  constructor(userId: UserId, email: string) {
    super(userId); // sets aggregateId + stamps occurredAt
    this.email = email;
  }
}
```

## Domain events vs. integration events

These are easy to conflate but serve different audiences:

- A **domain event** is internal to the bounded context that raised it (or,
  at most, shared in-process with other contexts in the same deployable). It
  can carry rich domain types and change shape freely as the domain model
  evolves, because nothing outside the codebase depends on its exact schema.
- An **integration event** is a deliberately-stable, versioned contract
  published _across_ deployment boundaries (a message queue, a webhook) to
  external consumers who can't be coordinated with a single atomic code
  change. Changing its shape is a breaking-change exercise, not a refactor.

Verixa's current events (`UserRegistered`, `UserStatusChanged`) are domain
events. Nothing in the codebase publishes them across a process boundary
yet — that's a Phase 14 (Notifications & Messaging) concern, and when it
arrives, it will most likely translate select domain events into
purpose-built integration events rather than expose domain events directly,
for exactly the stability reason above.

## Why aggregates emit events instead of calling other contexts directly

`User.register()` records a `UserRegistered` event; it does not, for
example, directly call an audit-logging function or a notification sender.
If it did, the identity context would depend on audit and notifications
directly — the dependency arrow would point the wrong way (a foundational
context depending on peripheral ones), and every new context that cares
about user registration would require another direct call added to `User`,
coupling identity's core logic to an ever-growing set of unrelated
concerns.

Emitting an event instead inverts that dependency: identity only knows that
_something happened_, not who might care. Audit, notifications, or any
future context subscribe to the event instead, each independently, without
identity needing to know they exist.

## The publisher port, and why it's interface-only right now

`DomainEventPublisher` (`publish`/`subscribe`) is defined but has **no
implementation yet** — Issue 026 scoped it as interface-only deliberately.
Aggregates already record events (retrievable via `pullDomainEvents()`, see
below) independently of whether anything publishes them; wiring an actual
in-process dispatcher (or later, something broker-backed) is separable work
that doesn't block anything built so far, and choosing that implementation
prematurely risks coupling the interface's shape to one specific delivery
mechanism's needs.

## `pullDomainEvents()` and Verixa's immutable-entity twist

Classic DDD implementations usually mutate an aggregate in place and buffer
events on a mutable internal list; `pullDomainEvents()` then clears that
list so events are never published twice. Verixa's aggregates
(`packages/identity/domain/entities/`) are immutable instead — every
mutating method returns a **new** instance rather than mutating `this` (see
`docs/guides/domain-modeling.md`) — so the buffering works slightly
differently:

- Each new instance carries only the event(s) produced by the single action
  that created it (registration, or one status transition) — not an
  accumulated history across every prior transition.
- `pullDomainEvents()` is a plain read, not a destructive clear — there's no
  mutable internal state to clear.

This works cleanly because Verixa's use cases follow a load → mutate → save
pattern: a use case loads (or creates) an aggregate, calls exactly one
mutating method, and is done with that instance. Pulling events from the
instance a mutating method returned always gets exactly that action's
events. If a future use case needs to chain multiple mutations on one
aggregate before pulling events, this scheme would need to accumulate
across calls instead — revisit this design if/when that need actually
arises, rather than generalizing for it now.

## Cross-context event handling

Domain events allow bounded contexts to react to each other's state changes
without directly importing each other's code or inverting the dependency
graph.

### UserStatusChanged → Credentials invalidation

When the **Identity** context soft-deletes a user (via `User.delete()`), it
emits a `UserStatusChanged` event with `newStatus === "deleted"`. The
**Credentials** context listens for this event via `HandleUserDeleted`
(Issue 075), which atomically:

1. Invalidates all outstanding email verification tokens (`consumedAt` is set)
2. Invalidates all outstanding password reset tokens (`consumedAt` is set)
3. Clears the credential's failure counter and any lockout state

This ensures a soft-deleted user cannot:

- Authenticate with a retained password
- Use a verification link generated before deletion
- Use a password reset link generated before deletion

The handler is intentionally defensive: if a user has no credential record
(SSO-only or passkey-only accounts), no error is raised — the operation
logically completes because there is nothing to clean up.

**Pattern**: The Identity context knows nothing about Credentials. Credentials
reacts to Identity events. Neither context imports the other directly — they
are decoupled through events and the `CredentialsUnitOfWork` port, which
crosses the boundary.

## Event catalog

| Event                           | Aggregate    | Recorded when                                                                                                 |
| ------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------- |
| `UserRegistered`                | `User`       | `User.register()` — a brand-new user is created                                                               |
| `UserStatusChanged`             | `User`       | Any successful `activate()`/`suspend()`/`delete()` — carries `previousStatus`, `newStatus`, optional `reason` |
| `UserProfileUpdated`            | `User`       | `User.updateProfile()` — display name and/or person name changed                                              |
| `OrganizationInvitationCreated` | `Invitation` | `Invitation.create()` — a new pending organization invitation is issued                                       |

`UserStatusChanged.reason` is `undefined` for self-service transitions
(e.g. activation via email verification) and set for admin-triggered ones
(`SuspendUser`/`ReactivateUser`, Issue 033, which require a reason for the
audit trail — see `docs/guides/use-cases.md`).

This table grows as later issues add events for other aggregates.
