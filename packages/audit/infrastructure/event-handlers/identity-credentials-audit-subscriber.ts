import type { DomainEvent, DomainEventHandler, DomainEventPublisher } from "@verixa/shared-kernel";

import { RecordAuditEvent } from "../../application/use-cases/record-audit-event.js";
import type { AuditAction } from "../../domain/entities/audit-log-entry.js";

type EventData = DomainEvent & Readonly<Record<string, unknown>>;

export type AuditSubscriberErrorHandler = (error: unknown, event: DomainEvent) => void;

interface AuditCommand {
  readonly action: AuditAction;
  readonly subjectId: string;
  readonly metadata: Readonly<Record<string, string>>;
}

const CREDENTIAL_EVENT_ACTIONS: Readonly<Record<string, AuditAction>> = {
  "credentials.user.email_verified": "user.email_verified",
  "credentials.user.password_changed": "user.password_changed",
  "credentials.user.account_locked": "user.locked_out",
  "credentials.email_verified": "user.email_verified",
  "credentials.password_changed": "user.password_changed",
  "credentials.account_locked": "user.locked_out",
};

/**
 * Converts an observed identity or credentials event into the small, stable
 * audit vocabulary. Unknown events are deliberately ignored: this subscriber
 * must not become a coupling point that needs changing whenever another
 * bounded context adds an event.
 */
function toAuditCommand(event: DomainEvent): AuditCommand | undefined {
  const data = event as EventData;

  switch (event.eventName) {
    case "identity.user.registered":
      return {
        action: "user.registered",
        subjectId: event.aggregateId,
        metadata: stringMetadata(data, ["email"]),
      };
    case "identity.user.status_changed":
      return {
        action: "user.status_changed",
        subjectId: event.aggregateId,
        metadata: stringMetadata(data, ["previousStatus", "newStatus", "reason"]),
      };
    case "identity.user.profile_updated":
      return {
        action: "user.profile_updated",
        subjectId: event.aggregateId,
        metadata: {},
      };
    case "identity.organization_invitation.created":
      return {
        action: "organization.invitation_created",
        subjectId: event.aggregateId,
        metadata: stringMetadata(data, ["organizationId", "email"]),
      };
    default: {
      const action = CREDENTIAL_EVENT_ACTIONS[event.eventName];
      return action === undefined
        ? undefined
        : {
            action,
            subjectId: event.aggregateId,
            metadata: stringMetadata(data, ["reason", "method"]),
          };
    }
  }
}

function stringMetadata(
  event: Readonly<Record<string, unknown>>,
  keys: readonly string[],
): Readonly<Record<string, string>> {
  const metadata: Record<string, string> = {};
  for (const key of keys) {
    const value = event[key];
    if (typeof value === "string") metadata[key] = value;
  }
  return metadata;
}

/**
 * Subscribes audit recording to identity and credentials domain events.
 *
 * The publisher owns delivery and the producer contexts know nothing about
 * this class. Each handler starts one audit write; failures are contained at
 * this boundary and reported to the supplied logger so a broken audit store
 * cannot reject the business operation that emitted the event.
 */
export class IdentityCredentialsAuditSubscriber {
  private readonly eventNames = [
    "identity.user.registered",
    "identity.user.status_changed",
    "identity.user.profile_updated",
    "identity.organization_invitation.created",
    ...Object.keys(CREDENTIAL_EVENT_ACTIONS),
  ];

  constructor(
    private readonly publisher: DomainEventPublisher,
    private readonly recordAuditEvent: RecordAuditEvent,
    private readonly onError: AuditSubscriberErrorHandler = () => undefined,
  ) {
    this.subscribe();
  }

  private subscribe(): void {
    for (const eventName of this.eventNames) {
      const handler: DomainEventHandler = (event) => {
        void this.handle(event).catch((error: unknown) => this.onError(error, event));
      };
      this.publisher.subscribe(eventName, handler);
    }
  }

  private async handle(event: DomainEvent): Promise<void> {
    const command = toAuditCommand(event);
    if (command === undefined) return;

    await this.recordAuditEvent.execute(command);
  }
}
