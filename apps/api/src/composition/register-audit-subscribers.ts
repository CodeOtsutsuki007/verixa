import {
  type PermissionGrantedEvent,
  PermissionGrantedAuditSubscriber,
  type RecordAuditEvent,
  type RoleAssignedEvent,
  RoleAssignedAuditSubscriber,
  type SessionCreatedEvent,
  SessionCreatedAuditSubscriber,
  type SessionRevokedEvent,
  SessionRevokedAuditSubscriber,
} from "@verixa/audit";
import type { DomainEventPublisher } from "@verixa/shared-kernel";

/**
 * Registers every audit subscriber on the process's event publisher.
 *
 * ## Why this happens during composition, not on first use
 *
 * An event that fires with nobody subscribed to it is not delayed, queued or
 * replayed later — it is dropped, silently and permanently. So the one ordering
 * rule that matters for auditing is that subscribers exist *before* the first
 * publisher can run, and there is no way to enforce that at the call site
 * except by registering eagerly, at startup, in the same function that builds
 * the object graph.
 *
 * The tempting alternative is lazy registration on first publish, which reads
 * as more efficient and is a data-loss bug: whatever the very first event of a
 * process is, that event is never audited. Worse than never being audited,
 * because the log looks complete — a gap at the head of the chain is exactly
 * what an operator reviewing it after an incident cannot distinguish from
 * nothing having happened yet.
 *
 * ## What "every subscriber" is held to
 *
 * This function is the whole registry. A new subscriber added to
 * `@verixa/audit` that is not wired here is a subscriber that never runs in
 * production while still passing its own unit tests, which is the failure mode
 * Issue 194 exists to prevent. The smoke test in
 * `tests/integration/audit-subscriber-registration.spec.ts` asserts one event
 * name per subscriber against a composed container, so the omission shows up as
 * a red test rather than as a missing record six months later.
 *
 * ## Why wire subscribers before their publishers exist
 *
 * No context publishes these events on a code path today — sessions (Phase 05)
 * and RBAC (Phase 07) are still being built, and the auth routes record their
 * own audit entries directly. That makes this wiring forward-looking rather
 * than live, which is the correct side to be wrong on: a subscriber registered
 * ahead of its first publisher does nothing until that publisher arrives, and
 * a subscriber registered after it loses every event up to that point, with
 * nothing in the log to show for the gap.
 */
export function registerAuditSubscribers(
  publisher: DomainEventPublisher,
  recordEvent: RecordAuditEvent,
): void {
  const sessionCreated = new SessionCreatedAuditSubscriber(recordEvent);
  const sessionRevoked = new SessionRevokedAuditSubscriber(recordEvent);
  const roleAssigned = new RoleAssignedAuditSubscriber(recordEvent);
  const permissionGranted = new PermissionGrantedAuditSubscriber(recordEvent);

  publisher.subscribe<SessionCreatedEvent>("sessions.session.created", (event) =>
    sessionCreated.handle(event),
  );
  publisher.subscribe<SessionRevokedEvent>("sessions.session.revoked", (event) =>
    sessionRevoked.handle(event),
  );
  publisher.subscribe<RoleAssignedEvent>("rbac.role.assigned", (event) =>
    roleAssigned.handle(event),
  );
  publisher.subscribe<PermissionGrantedEvent>("rbac.permission.granted", (event) =>
    permissionGranted.handle(event),
  );
}
