/**
 * Records session-lifecycle events that need to be visible outside a
 * debugger — most notably eviction, per Issue 094's acceptance criterion
 * that eviction is logged. Deliberately the same shape as
 * `@verixa/mfa`'s `AuditLogger`: each bounded context defines its own copy
 * of this port rather than sharing one, per the package-encapsulation rule
 * in `docs/guides/domain-modeling.md` — sessions must not depend on mfa (or
 * vice versa) just to log a string.
 */
export interface SessionAuditLogger {
  record(action: string, actorId: string, metadata?: Record<string, string>): Promise<void>;
}
