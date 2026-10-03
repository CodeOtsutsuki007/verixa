// Curated public surface of @verixa/audit. Deep imports are blocked by the
// boundary rule in eslint.config.mjs — see docs/guides/domain-modeling.md.

// Domain: AuditLogEntry (Phase 01 hash-chained audit log)
export {
  type AuditAction as AuditLogAction,
  AuditLogEntry,
  type AuditLogEntryId,
  type ChainBreak,
  GENESIS_HASH,
  verifyChain,
} from "./domain/entities/audit-log-entry.js";

// Domain: AuditEvent (Phase 10 structured audit events)
export { AuditEvent, type AuditEventId } from "./domain/entities/audit-event.js";
export type { ResourceType, OrganizationId } from "./domain/entities/audit-event.js";
export { type AuditAction as AuditActionType } from "./domain/value-objects/audit-action.js";
export { isAuditAction } from "./domain/value-objects/audit-action.js";

// Application: ports (AuditLogRepository - Phase 01)
export type {
  AnchorFailure,
  AnchorReceiptLike,
  AnchorRecord,
  AnchorRecordRepository,
  AnchorVerifierPort,
  AuditLogFilters,
  AuditLogRepository,
  FindWithFiltersParams,
  HashAnchorPort,
} from "./application/ports/audit-log-repository.js";

// Application: ports (AuditEventRepository - Phase 10)
export type {
  AuditEventRepository,
  AuditEventFilters,
  PaginationParams,
  PaginatedAuditEvents,
  AppendAuditEventError,
} from "./application/ports/audit-event-repository.js";
export {
  databaseUnavailableError,
  constraintViolationError,
  unknownAppendError,
} from "./application/ports/audit-event-repository.js";

// Application: use cases
export {
  AnchorAuditLog,
  type AnchorAuditLogError,
  type AnchorAuditLogResult,
} from "./application/use-cases/anchor-audit-log.js";
export {
  RecordAuditEvent,
  type RecordAuditEventCommand,
} from "./application/use-cases/record-audit-event.js";
export {
  QueryAuditEvents,
  type QueryAuditEventsCommand,
  type QueryAuditEventsFilters,
  type QueryAuditEventsResult,
} from "./application/use-cases/query-audit-events.js";
export {
  DEFAULT_MAX_ANCHOR_CHECKS,
  DEFAULT_VERIFY_BATCH_SIZE,
  MAX_VERIFY_BATCH_SIZE,
  VerifyAuditChain,
  type AnchorChainCheck,
  type VerifyAuditChainCommand,
  type VerifyAuditChainError,
  type VerifyAuditChainResult,
} from "./application/use-cases/verify-audit-chain.js";

// Application: subscribers
export { AuditEventSubscriber } from "./application/subscribers/audit-event-subscriber.js";
// The event shapes a subscriber handles are part of the public surface: a
// publisher in another context has to be able to build one, and the
// composition root's `subscribe` call is generic over it.
export {
  SessionCreatedAuditSubscriber,
  SessionRevokedAuditSubscriber,
  type SessionCreatedEvent,
  type SessionRevokedEvent,
} from "./application/subscribers/session-audit-subscriber.js";
export {
  PermissionGrantedAuditSubscriber,
  RoleAssignedAuditSubscriber,
  type PermissionGrantedEvent,
  type RoleAssignedEvent,
} from "./application/subscribers/rbac-audit-subscriber.js";

// Infrastructure
export {
  AuditLogEntryMapper,
  PrismaAnchorRecordRepository,
  PrismaAuditLogRepository,
} from "./infrastructure/persistence/prisma-audit-repositories.js";
export {
  InMemoryAnchorRecordRepository,
  InMemoryAuditLogRepository,
} from "./infrastructure/testing/in-memory-audit-repositories.js";
