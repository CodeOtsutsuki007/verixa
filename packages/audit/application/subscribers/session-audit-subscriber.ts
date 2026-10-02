import type { DomainEvent } from "@verixa/shared-kernel";

import type { RecordAuditEventCommand } from "../use-cases/record-audit-event.js";
import { AuditEventSubscriber } from "./audit-event-subscriber.js";

/**
 * Placeholder for SessionCreated event from Phase 05.
 *
 * This interface defines the expected shape of the SessionCreated event.
 * When the sessions package publishes this event, this subscriber will
 * automatically record it in the audit log.
 */
interface SessionCreatedEvent extends DomainEvent {
  readonly eventName: "sessions.session.created";
  readonly userId: string;
  readonly sessionId: string;
  readonly ipAddress?: string;
  readonly userAgent?: string;
}

/**
 * Placeholder for SessionRevoked event from Phase 05.
 *
 * This interface defines the expected shape of the SessionRevoked event.
 * When the sessions package publishes this event, this subscriber will
 * automatically record it in the audit log.
 */
interface SessionRevokedEvent extends DomainEvent {
  readonly eventName: "sessions.session.revoked";
  readonly userId: string;
  readonly sessionId: string;
  readonly reason?: string;
}

/**
 * Subscriber for SessionCreated events (Phase 05).
 *
 * Records each new session creation as an audit event with the user as both
 * actor and subject (someone creates a session for themselves by logging in).
 */
export class SessionCreatedAuditSubscriber extends AuditEventSubscriber<SessionCreatedEvent> {
  protected mapToAuditCommand(event: SessionCreatedEvent): RecordAuditEventCommand {
    const metadata: Record<string, string> = {
      sessionId: event.sessionId,
    };

    if (event.ipAddress) {
      metadata["ipAddress"] = event.ipAddress;
    }

    if (event.userAgent) {
      metadata["userAgent"] = event.userAgent;
    }

    return {
      action: "user.login_succeeded",
      actorId: event.userId,
      subjectId: event.userId,
      metadata,
    };
  }
}

/**
 * Subscriber for SessionRevoked events (Phase 05).
 *
 * Records each session revocation as an audit event. The actor may differ from
 * the subject when an admin revokes someone else's session.
 */
export class SessionRevokedAuditSubscriber extends AuditEventSubscriber<SessionRevokedEvent> {
  protected mapToAuditCommand(event: SessionRevokedEvent): RecordAuditEventCommand {
    const metadata: Record<string, string> = {
      sessionId: event.sessionId,
    };

    if (event.reason) {
      metadata["reason"] = event.reason;
    }

    return {
      action: "user.login_succeeded", // Using existing action; specific "session.revoked" action can be added later
      actorId: event.userId,
      subjectId: event.userId,
      metadata,
    };
  }
}
