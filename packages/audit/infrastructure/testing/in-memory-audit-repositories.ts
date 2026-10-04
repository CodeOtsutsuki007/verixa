import { Result } from "@verixa/shared-kernel";

import type {
  AuditEventCriteria,
  AuditEventPage,
  AuditEventReader,
} from "../../application/ports/audit-event-reader.js";
import type {
  AnchorRecord,
  AnchorRecordRepository,
  AuditLogRepository,
  FindWithFiltersParams,
} from "../../application/ports/audit-log-repository.js";
import { ChainConflictError } from "../../application/ports/audit-log-repository.js";
import { type AuditLogEntry, GENESIS_HASH } from "../../domain/entities/audit-log-entry.js";

/**
 * In-memory `AuditLogRepository` for testing without a database.
 *
 * Enforces the append protocol the real table enforces with an index. That
 * matters more than usual here: the whole append protocol depends on a
 * compare-and-set losing, and a fake that accepted a stale `previousHash`
 * would let tests pass against a forked chain that production would have
 * refused. The `PrismaAuditLogRepository` and this class are held to the same
 * behaviour by `auditLogRepositoryContract`.
 */
export class InMemoryAuditLogRepository implements AuditLogRepository {
  private readonly entries: AuditLogEntry[] = [];

  findLatest(): Promise<AuditLogEntry | undefined> {
    return Promise.resolve(this.entries.at(-1));
  }

  append(
    entry: AuditLogEntry,
    expectedPreviousHash: string,
  ): Promise<Result<void, ChainConflictError>> {
    return this.appendMany([entry], expectedPreviousHash);
  }

  /**
   * Appends atomically: either the whole batch lands or none of it does, and
   * the head is checked exactly once.
   *
   * The synchronous body is deliberate — there is no `await` between the check
   * and the push, so no interleaving can slip between them. JavaScript's
   * run-to-completion semantics give this fake the serialisation the real
   * adapter gets from a unique index, which is the closest honest equivalent:
   * it reproduces the *guarantee*, not the mechanism.
   */
  appendMany(
    entries: readonly AuditLogEntry[],
    expectedPreviousHash: string,
  ): Promise<Result<void, ChainConflictError>> {
    if (entries.length === 0) {
      return Promise.resolve(Result.ok(undefined));
    }

    const headHash = this.entries.at(-1)?.hash ?? GENESIS_HASH;
    if (headHash !== expectedPreviousHash) {
      return Promise.resolve(Result.err(new ChainConflictError(expectedPreviousHash, headHash)));
    }

    // A duplicate sequence is the same failure the unique index raises in
    // Postgres, and it must surface as the same conflict here rather than as a
    // thrown error, so tests against the fake exercise the real retry path.
    for (const entry of entries) {
      if (this.entries.some((existing) => existing.sequence === entry.sequence)) {
        return Promise.resolve(
          Result.err(
            new ChainConflictError(entry.previousHash, this.entries.at(-1)?.hash ?? GENESIS_HASH),
          ),
        );
      }
    }

    let expected = expectedPreviousHash;
    for (const entry of entries) {
      if (entry.previousHash !== expected) {
        return Promise.resolve(Result.err(new ChainConflictError(expected, entry.previousHash)));
      }
      expected = entry.hash;
    }

    this.entries.push(...entries);
    return Promise.resolve(Result.ok(undefined));
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

/**
 * In-memory `AuditEventReader` for testing without a database.
 *
 * Entries are filed under an organization explicitly with {@link seed}, since
 * `AuditLogEntry` does not carry one yet (Issue 181). Every read is recorded in
 * {@link reads}, so a test can prove a refused request never reached storage
 * at all — "returned an error" and "returned an error without looking" are
 * different guarantees, and only the second one is the point.
 */
export class InMemoryAuditEventReader implements AuditEventReader {
  private readonly entries: { organizationId: string; entry: AuditLogEntry }[] = [];
  readonly reads: AuditEventCriteria[] = [];

  seed(organizationId: string, ...entries: AuditLogEntry[]): void {
    for (const entry of entries) this.entries.push({ organizationId, entry });
  }

  query(criteria: AuditEventCriteria, page: AuditEventPage): Promise<readonly AuditLogEntry[]> {
    this.reads.push(criteria);
    return Promise.resolve(
      this.matching(criteria)
        .filter((entry) => entry.sequence > (page.afterSequence ?? 0))
        .slice(0, page.limit),
    );
  }

  async *stream(criteria: AuditEventCriteria): AsyncIterable<AuditLogEntry> {
    this.reads.push(criteria);
    for (const entry of this.matching(criteria)) {
      await Promise.resolve();
      yield entry;
    }
  }

  private matching(criteria: AuditEventCriteria): AuditLogEntry[] {
    return this.entries
      .filter(({ organizationId }) => organizationId === criteria.organizationId)
      .map(({ entry }) => entry)
      .filter(
        (entry) =>
          (criteria.actorId === undefined || entry.actorId === criteria.actorId) &&
          (criteria.subjectId === undefined || entry.subjectId === criteria.subjectId) &&
          (criteria.from === undefined || entry.occurredAt >= criteria.from) &&
          (criteria.to === undefined || entry.occurredAt <= criteria.to),
      )
      .sort((a, b) => a.sequence - b.sequence);
  }
}
