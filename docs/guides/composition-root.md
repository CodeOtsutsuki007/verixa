# Composition Root

`apps/api/src/composition-root.ts` is the only place in the system allowed to
know which concrete implementations exist. Everything else depends on
interfaces: `RegisterUser` knows it needs _a_ `UserRepository` and has no idea
one is backed by Prisma. That inversion is what keeps the application layer
testable without a database, and it only holds while the knowledge of "which
implementation" stays concentrated in one file instead of leaking into the
modules that use it.

The rule to preserve: **nothing outside this file imports a `Prisma*` class.**
The moment a route handler constructs its own repository, the inversion is gone
and that handler can no longer be tested without a database.

Wiring is explicit construction rather than a DI container for the same reason:
a container hides these edges behind runtime resolution, so a missing
dependency becomes a runtime failure instead of a compile error. At this size,
a few lines of boring code buys complete type safety.

```ts
const container = buildContainer(); // production: reads DATABASE_URL
const app = buildApp({ container }); // Fastify routes over that graph
```

`buildContainer` takes an optional `PrismaClient` so tests can inject one
pointed at a throwaway database. A test that writes rows should never be one
environment variable away from a developer's own data.

## Audit

Audit wiring is the part of the composition root with an **ordering**
requirement, which is why it gets its own file and its own section.

### Registering subscribers

```ts
// apps/api/src/composition/register-audit-subscribers.ts
export function registerAuditSubscribers(
  publisher: DomainEventPublisher,
  recordEvent: RecordAuditEvent,
): void {
  publisher.subscribe<SessionCreatedEvent>("sessions.session.created", ...);
  // ...one registration per subscriber, and no other work
}
```

It is called from inside `buildContainer`, immediately after the publisher is
constructed:

```ts
const eventPublisher = new InMemoryEventPublisher();
registerAuditSubscribers(eventPublisher, recordAuditEvent);
```

### Why it happens here, and not later

An event published while nobody is subscribed to it is not queued, delayed or
replayed. It is **dropped, silently and permanently** —
`InMemoryEventPublisher.publish` looks up a handler list and iterates whatever
it finds.

So the ordering rule for auditing is: subscribers must exist before the first
event can be published. There is no way to enforce that at a call site; the
only mechanism is eager registration in the function that builds the object
graph. Three alternatives were considered and rejected:

- **Lazy registration on first publish.** Reads as efficient and is a data-loss
  bug: whatever the very first event of a process is, that event is never
  audited. Worse than not audited, because the log looks complete — a gap at
  the head of a chain is indistinguishable from nothing having happened yet.
- **Registering in `buildApp` instead.** Then a process that publishes before
  the HTTP layer is built loses those events: a scheduled job, a queue
  consumer, or a test that drives use cases directly. Any of them would have to
  remember to call the registration step, which is the same "something to
  remember" this design exists to remove.
- **Registering per request.** Two registrations for one event name means the
  handler runs twice, which means two audit entries for one login. A log that
  duplicates events is not a ledger, and a `sequence` that no longer matches
  the count of real events makes every later report wrong.

`InMemoryEventPublisher` is synchronous by design: handlers run in
subscription order inside the request that published the event, so an audit
record exists before the caller sees a response. The trade is that a slow
handler blocks the request. If that ever becomes a real problem the answer is
an out-of-process event bus, not making this one async.

### The two ways an entry gets written

Both paths exist, and which one is live changes as contexts are built:

- **Directly**, by a route calling `container.audit.recordEvent.execute(...)`.
  This is how registration and login are audited today
  (`apps/api/src/routes/auth.ts`), because those operations are request-driven
  and the route knows exactly what happened.
- **By subscription**, when a context publishes a domain event and an audit
  subscriber maps it to an entry. No context publishes on a code path yet —
  sessions (Phase 05) and RBAC (Phase 07) are still being built — so this wiring
  is deliberately ahead of its publishers. A subscriber registered late loses
  every event before it, silently; a subscriber registered early does nothing
  until the first event arrives. Only one of those is recoverable.

Both write into one hash-chained log through `RecordAuditEvent`, so verification
does not have to know which path produced a row. See
`docs/guides/domain-events.md` for the publisher side of that.

### Adding a subscriber

A subscriber that exists, is fully tested inside `@verixa/audit`, and is never
wired up records nothing — and fails as a missing row six months later rather
than as a red test. That is the failure mode this section is about, so the
whole procedure is four steps with a check at the end:

1. Implement it in `packages/audit/application/subscribers/`, extending
   `AuditEventSubscriber<E>`, and export the class **and its event interface**
   from `packages/audit/index.ts`. The event type is part of the public
   surface: `subscribe` is generic over it, and a publisher in another context
   has to be able to build one.
2. Add one `publisher.subscribe<...>("<event.name>", ...)` line to
   `registerAuditSubscribers`.
3. Add a row to the table in
   `tests/integration/audit-subscriber-registration.spec.ts` asserting that a
   composed container, given that event name, gains an audit entry.
4. Add the event name to `docs/guides/domain-events.md` if it is emitted by an
   aggregate.

Step 3 is what makes an omission visible. The integration spec publishes on a
container that has never had `buildApp` called on it, which is also what makes
_late_ registration visible: registering anywhere other than composition means
the first event of a process is dropped, and publishing against a bare
container is exactly the test that catches it.

### What the container exposes

```ts
export interface Container {
  readonly prisma: PrismaClient;
  readonly eventPublisher: DomainEventPublisher; // subscribers already attached
  readonly audit: {
    readonly recordEvent: RecordAuditEvent;
    readonly queryEvents: QueryAuditEvents;
    readonly verifyChain: VerifyAuditChain;
    readonly anchor: AnchorAuditLog | undefined;
  };
  // ...identity, credentials, dispose
}
```

Two details that are deliberate, both about _absence_:

- **`eventPublisher` is on the container** so anything with the graph can
  publish through the wired publisher rather than constructing its own. A
  second `InMemoryEventPublisher` is a second set of subscribers, which is to
  say no subscribers.
- **`anchor` is `undefined` when no signing key is configured**, rather than a
  no-op stub. A deployment that has not set up anchoring must not be able to
  believe it has: a silent stub would leave an operator thinking their audit
  log is externally verifiable when nothing has ever been committed anywhere.

Recording itself never fails the operation it records. `RecordAuditEvent`
catches, reports to stderr, and returns `undefined` — a login that succeeded
should not be reported as failed because the audit write broke. The residual
risk (an attacker who can reliably break audit writes can act unrecorded) is
mitigated by visibility, not by failing requests: a gap in the sequence is
detectable, and `pnpm audit:verify-chain` is how someone looks. See
`docs/security/audit-log-integrity.md`.
