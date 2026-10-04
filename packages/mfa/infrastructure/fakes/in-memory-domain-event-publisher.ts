import type { DomainEvent, DomainEventHandler, DomainEventPublisher } from "@verixa/shared-kernel";

export class InMemoryDomainEventPublisher implements DomainEventPublisher {
  readonly publishedEvents: DomainEvent[] = [];

  publish(event: DomainEvent): void {
    this.publishedEvents.push(event);
  }

  subscribe<E extends DomainEvent>(_eventName: string, _handler: DomainEventHandler<E>): void {
    void _eventName;
    void _handler;
  }

  clear(): void {
    this.publishedEvents.length = 0;
  }
}
