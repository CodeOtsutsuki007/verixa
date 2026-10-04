/**
 * A fact about something that already happened to an aggregate, named in the
 * past tense (`UserRegistered`, not `RegisterUser`) because — unlike a
 * command — an event cannot be rejected or undone by the time anything
 * observes it. See `docs/guides/domain-events.md` for the full domain vs.
 * integration event distinction.
 */
export interface DomainEvent {
  readonly eventName: string;
  readonly aggregateId: string;
  readonly occurredAt: Date;
}

/**
 * Convenience base class for concrete domain events: stamps `occurredAt` at
 * construction time and takes `aggregateId` once in the constructor, so a
 * subclass only has to declare its own `eventName` and event-specific data.
 */
export abstract class BaseDomainEvent implements DomainEvent {
  abstract readonly eventName: string;
  readonly aggregateId: string;
  readonly occurredAt: Date;

  protected constructor(aggregateId: string) {
    this.aggregateId = aggregateId;
    this.occurredAt = new Date();
  }
}

export type DomainEventHandler<E extends DomainEvent = DomainEvent> = (
  event: E,
) => void | Promise<void>;

/**
 * The port aggregates' recorded events are eventually delivered through.
 * `InMemoryEventPublisher` is the in-process implementation the composition
 * root wires up; a broker-backed one remains separable future work, and
 * nothing above this interface depends on which is in place — see
 * `docs/guides/domain-events.md`.
 */
export interface DomainEventPublisher {
  publish(event: DomainEvent): void | Promise<void>;
  subscribe<E extends DomainEvent>(eventName: string, handler: DomainEventHandler<E>): void;
}
