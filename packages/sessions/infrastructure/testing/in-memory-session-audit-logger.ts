import type { SessionAuditLogger } from "../../application/ports/session-audit-logger.js";

/** One recorded call to `SessionAuditLogger.record`, kept for test assertions. */
export interface RecordedSessionAuditEntry {
  readonly action: string;
  readonly actorId: string;
  readonly metadata: Readonly<Record<string, string>> | undefined;
}

/**
 * A `SessionAuditLogger` that keeps every call in memory instead of writing
 * it anywhere, so tests (notably Issue 094's "eviction is logged" acceptance
 * criterion) can assert on what was recorded.
 */
export class InMemorySessionAuditLogger implements SessionAuditLogger {
  readonly entries: RecordedSessionAuditEntry[] = [];

  record(action: string, actorId: string, metadata?: Record<string, string>): Promise<void> {
    this.entries.push({ action, actorId, metadata });
    return Promise.resolve();
  }
}
