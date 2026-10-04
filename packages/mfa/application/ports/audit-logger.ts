export interface AuditLogger {
  record(action: string, actorId: string, metadata?: Record<string, string>): Promise<void>;
}
