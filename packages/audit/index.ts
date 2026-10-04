// Curated public surface of @verixa/audit. Nothing outside this package should
// import from a deep path (`@verixa/audit/domain/...`,
// `@verixa/audit/application/...`) — see docs/guides/domain-modeling.md
// ("Package encapsulation") for why, and eslint.config.mjs's
// `no-restricted-imports` rule, which enforces it.
//
// What is deliberately *not* here: the hash chain's mechanics. `GENESIS_HASH`,
// the canonical serialization, and `AuditLogEntry`'s factories (`append`,
// `reconstitute`) stay internal. A consumer that could mint an entry could
// append one without going through `RecordAuditEvent`, which is the one place
// that reads the chain tail before linking to it — and the chain is only as
// trustworthy as its least careful writer. Consumers can read entries and
// verify a chain; they cannot build one.

// Domain: the entry as a read-only type, and the chain-verification tool
export type {
  AuditAction,
// Domain: AuditLogEntry (Phase 01 hash-chained audit log)
export {
  type AuditAction as AuditLogAction,
  AuditLogEntry,
  AuditLogEntryId,
  ChainBreak,
} from "./domain/entities/audit-log-entry.js";
export { verifyChain } from "./domain/entities/audit-log-entry.js";

// Application: ports (for the composition root to supply adapters for)
export {
  AUDIT_PERMISSIONS,
  AuditAccessDeniedError,
  type AuditReader,
  type AuditReadOperation,
} from "./domain/policies/audit-access-policy.js";

// Domain: AuditEvent (Phase 10 structured audit events)
export { AuditEvent, type AuditEventId } from "./domain/entities/audit-event.js";
export type { ResourceType, OrganizationId } from "./domain/entities/audit-event.js";
export { type AuditAction as AuditActionType } from "./domain/value-objects/audit-action.js";
export { isAuditAction } from "./domain/value-objects/audit-action.js";

// Domain: AuditMetadata (Issue 196 — the bounds and per-sink encodings that
// keep a crafted metadata value from speaking for the record)
export {
  AuditMetadata,
  escapeForText,
  escapeJsonLineTerminators,
  MAX_METADATA_ENTRIES,
  MAX_METADATA_KEY_LENGTH,
  MAX_METADATA_VALUE_LENGTH,
  METADATA_REJECTED_KEY,
  neutralizeFormulaPrefix,
  rejectionReasonOf,
  utf8ByteLength,
} from "./domain/value-objects/audit-metadata.js";
export type { AuditMetadataRejectionReason } from "./domain/value-objects/audit-metadata.js";

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
export type {
  AuditEventCriteria,
  AuditEventPage,
  AuditEventReader,
} from "./application/ports/audit-event-reader.js";

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
  type AuditRecorder,
  RecordAuditEvent,
  type RecordAuditEventCommand,
  recordAuditEventBatch,
} from "./application/use-cases/record-audit-event.js";
export {
  MAX_AUDIT_QUERY_PAGE_SIZE,
  QueryAuditEvents,
  type QueryAuditEventsCommand,
} from "./application/use-cases/query-audit-events.js";
export {
  ExportAuditEvents,
  type ExportAuditEventsCommand,
} from "./application/use-cases/export-audit-events.js";
export { type AuditReadError, AuditReadNotRecordedError } from "./application/audit-read-access.js";
  AUDIT_EXPORT_HEADER,
  DEFAULT_EXPORT_MAX_RECORDS,
  ExportAuditEvents,
  type AuditExportFormat,
  type AuditExportLogger,
  type ExportAuditEventsCommand,
  type ExportAuditEventsResult,
} from "./application/use-cases/export-audit-events.js";
export {
  AgeRetentionPolicy,
  DEFAULT_RETENTION_POLICY,
  DEFAULT_RETENTION_WINDOW_DAYS,
  type RetentionPolicy,
  type RetentionWindow,
} from "./application/ports/retention-policy.js";
export {
  ApplyAuditRetentionPolicy,
  type ApplyRetentionPolicyCommand,
  type RetentionCandidate,
  type RetentionReview,
} from "./application/use-cases/apply-audit-retention-policy.js";
export {
  QueryAuditEvents,
  type QueryAuditEventsCommand,
  type QueryAuditEventsFilters,
  type QueryAuditEventsResult,
} from "./application/use-cases/query-audit-events.js";
export {
  ExportAuditEvents,
  escapeCsvField,
  type ExportAuditEventsCommand,
  type ExportAuditEventsError,
  type ExportAuditEventsFormat,
} from "./application/use-cases/export-audit-events.js";
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

// Infrastructure: Prisma-backed adapters. Exported so the composition root
// (apps/api) can construct them — it is the one place allowed to know which
// concrete implementation is in use. The row mapper they use is internal.
export {
  AuditQueueFullError,
  type AuditBatchFailureReport,
  type AuditOverflowReport,
  type AuditWriterStats,
  BatchedAuditWriter,
  type BatchedAuditWriterOptions,
} from "./infrastructure/persistence/batched-audit-writer.js";
export {
  type AuditDelegate,
  AuditLogEntryMapper,
  type AuditTransaction,
  PrismaAnchorRecordRepository,
  PrismaAuditLogRepository,
} from "./infrastructure/persistence/prisma-audit-repositories.js";

// Testing fakes. Exported so contexts that record audit events can test their
// own use cases against the same fake, rather than each writing one that
// drifts from the append-only contract.
export {
  InMemoryAnchorRecordRepository,
  InMemoryAuditEventReader,
  InMemoryAuditLogRepository,
} from "./infrastructure/testing/in-memory-audit-repositories.js";
export {
  IdentityCredentialsAuditSubscriber,
  type AuditSubscriberErrorHandler,
} from "./infrastructure/event-handlers/identity-credentials-audit-subscriber.js";
