import type { DomainEvent } from "@verixa/shared-kernel";

import type { AuditAction } from "../../domain/entities/audit-log-entry.js";
import type { RecordAuditEvent, RecordAuditEventCommand } from "../use-cases/record-audit-event.js";

/**
 * Base class for domain event subscribers that record audit entries.
 *
 * Concrete subscribers extend this and provide the mapping from their specific
 * event type to an `AuditAction` and metadata.
 */
export abstract class AuditEventSubscriber<E extends DomainEvent> {
  constructor(protected readonly recordAuditEvent: RecordAuditEvent) {}

  /**
   * Maps a domain event to an audit command.
   *
   * Subclasses implement this to extract the relevant fields from their
   * specific event type and return the corresponding audit action, actor,
   * subject, and metadata.
   */
  protected abstract mapToAuditCommand(event: E): RecordAuditEventCommand;

  /**
   * The handler registered with the domain event publisher.
   *
   * Delegates to {@link mapToAuditCommand} and records the entry. Failures are
   * swallowed by `RecordAuditEvent` itself — see that class's doc comment for
   * why audit writes never propagate errors to the operation being audited.
   */
  async handle(event: E): Promise<void> {
    const command = this.mapToAuditCommand(event);
    await this.recordAuditEvent.execute(command);
  }
}
