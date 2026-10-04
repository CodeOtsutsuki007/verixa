import type {
  DomainEvent,
  DomainEventHandler,
  DomainEventPublisher,
} from "../domain/domain-event.js";

/**
 * In-process, synchronous domain event publisher.
 *
 * Handlers are invoked in the order they were subscribed, within the same
 * request that published the event. That is deliberate: the audit subscriber
 * (Phase 10) and the MFA subscriber (Phase 16) must record their entries
 * before the request completes, not sometime later after the user has already
 * seen a success response.
 *
 * The trade is that a slow handler blocks the request. If that becomes a
 * problem in practice, the solution is an out-of-process event bus (Phase 21),
 * not making this one async — a fire-and-forget publisher would still block on
 * serialization and network send, and would lose the guarantee that side
 * effects finish before the response goes out.
 */
export class InMemoryEventPublisher implements DomainEventPublisher {
  private readonly handlers = new Map<string, DomainEventHandler[]>();

  subscribe<E extends DomainEvent>(eventName: string, handler: DomainEventHandler<E>): void {
    const existing = this.handlers.get(eventName) ?? [];
    existing.push(handler as DomainEventHandler);
    this.handlers.set(eventName, existing);
  }

  async publish(event: DomainEvent): Promise<void> {
    const handlers = this.handlers.get(event.eventName) ?? [];

    for (const handler of handlers) {
      await handler(event);
    }
  }
}
