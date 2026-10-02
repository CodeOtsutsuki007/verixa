import type {
  AnchorRecord,
  AnchorRecordRepository,
  AuditLogRepository,
  FindWithFiltersParams,
} from "../../application/ports/audit-log-repository.js";
import type { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";

/**
 * In-memory `AuditLogRepository` for testing without a database.
 *
 * Enforces the sequence uniqueness the real table enforces with an index.
 * That matters more than usual here: the whole append protocol depends on a
 * duplicate sequence being rejected, and a fake that accepted one would let
 * tests pass against a forked chain that production would have refused.
 */
export class InMemoryAuditLogRepository implements AuditLogRepository {
  private readonly entries: AuditLogEntry[] = [];

  findLatest(): Promise<AuditLogEntry | undefined> {
    return Promise.resolve(this.entries.at(-1));
  }

  append(entry: AuditLogEntry): Promise<void> {
    if (this.entries.some((existing) => existing.sequence === entry.sequence)) {
      return Promise.reject(
        new Error(`An audit entry with sequence ${String(entry.sequence)} already exists.`),
      );
    }
    this.entries.push(entry);
    return Promise.resolve();
  }

  findFrom(fromSequence: number, limit: number): Promise<readonly AuditLogEntry[]> {
    return Promise.resolve(
      this.entries.filter((entry) => entry.sequence >= fromSequence).slice(0, limit),
    );
  }

  findWithFilters(params: FindWithFiltersParams): Promise<readonly AuditLogEntry[]> {
    let filtered = this.entries.filter((entry) => entry.sequence >= params.fromSequence);

    if (params.filters.actorId) {
      filtered = filtered.filter((entry) => entry.actorId === params.filters.actorId);
    }

    if (params.filters.subjectId) {
      filtered = filtered.filter((entry) => entry.subjectId === params.filters.subjectId);
    }

    if (params.filters.action) {
      filtered = filtered.filter((entry) => entry.action === params.filters.action);
    }

    if (params.filters.organizationId) {
      filtered = filtered.filter(
        (entry) => entry.metadata["organizationId"] === params.filters.organizationId,
      );
    }

    if (params.filters.fromDate) {
      filtered = filtered.filter((entry) => entry.occurredAt >= params.filters.fromDate!);
    }

    if (params.filters.toDate) {
      filtered = filtered.filter((entry) => entry.occurredAt <= params.filters.toDate!);
    }

    return Promise.resolve(filtered.slice(0, params.limit));
  }

  count(): Promise<number> {
    return Promise.resolve(this.entries.length);
  }

  /**
   * Test-only: replaces an entry, simulating tampering.
   *
   * Deliberately absent from `AuditLogRepository`, because the port must not
   * offer a way to break append-only. It exists here so verification tests can
   * prove the chain actually detects a rewrite — a guarantee nothing else
   * could demonstrate.
   */
  tamper(sequence: number, replacement: AuditLogEntry): void {
    const index = this.entries.findIndex((entry) => entry.sequence === sequence);
    if (index >= 0) this.entries[index] = replacement;
  }

  /** Test-only: removes an entry, simulating deletion. */
  remove(sequence: number): void {
    const index = this.entries.findIndex((entry) => entry.sequence === sequence);
    if (index >= 0) this.entries.splice(index, 1);
  }

  /** Test-only: every entry, in order. */
  all(): readonly AuditLogEntry[] {
    return [...this.entries];
  }
}

/** In-memory `AnchorRecordRepository` for testing without a database. */
export class InMemoryAnchorRecordRepository implements AnchorRecordRepository {
  private readonly records: AnchorRecord[] = [];

  save(record: AnchorRecord): Promise<void> {
    this.records.push(record);
    return Promise.resolve();
  }

  findLatest(): Promise<AnchorRecord | undefined> {
    return Promise.resolve(this.records.at(-1));
  }

  findAll(limit: number): Promise<readonly AnchorRecord[]> {
    return Promise.resolve([...this.records].reverse().slice(0, limit));
  }
}
