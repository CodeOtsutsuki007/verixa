import type { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";

export interface AuditLogFilters {
  readonly actorId?: string | undefined;
  readonly subjectId?: string | undefined;
  readonly organizationId?: string | undefined;
  readonly action?: string | undefined;
  readonly fromDate?: Date | undefined;
  readonly toDate?: Date | undefined;
}

export interface FindWithFiltersParams {
  readonly filters: AuditLogFilters;
  readonly fromSequence: number;
  readonly limit: number;
}

/**
 * Persistence for the audit log.
 *
 * Deliberately has no `update` and no `delete`. Append-only is the guarantee
 * the whole design rests on, and a port offering a way to break it would make
 * the hash chain decorative — the first person in a hurry would reach for it.
 * Retention and erasure (Phase 24) are a different problem with different
 * rules, and will arrive as an explicit, auditable operation rather than as a
 * method that was quietly always there.
 */
export interface AuditLogRepository {
  /**
   * The most recent entry, or `undefined` when the log is empty.
   *
   * Callers need this to append: a new entry commits to its predecessor's
   * hash, so writing one requires having read the tail.
   */
  findLatest(): Promise<AuditLogEntry | undefined>;

  /** Appends an entry. Fails if `sequence` is already taken. */
  append(entry: AuditLogEntry): Promise<void>;

  /** Entries from `fromSequence` onward, in order. Used by verification. */
  findFrom(fromSequence: number, limit: number): Promise<readonly AuditLogEntry[]>;

  /** Queries entries with filters and cursor-based pagination. */
  findWithFilters(params: FindWithFiltersParams): Promise<readonly AuditLogEntry[]>;

  /** Total entries in the log. */
  count(): Promise<number>;
}

/** A commitment of the chain head to an external ledger. */
export interface AnchorRecord {
  readonly sequence: number;
  readonly chainHash: string;
  readonly anchorRef: string;
  readonly network: string;
  readonly anchoredAt: Date;
}

/** Persistence for anchoring receipts. */
export interface AnchorRecordRepository {
  save(record: AnchorRecord): Promise<void>;
  findLatest(): Promise<AnchorRecord | undefined>;
  findAll(limit: number): Promise<readonly AnchorRecord[]>;
}

/**
 * The anchoring capability this package needs, declared locally.
 *
 * Structurally identical to `HashAnchor` in `@verixa/stellar-anchor`, and
 * deliberately not imported from it. The audit log's requirement is "something
 * can commit a hash somewhere append-only"; naming a specific ledger package
 * in its dependency graph would invert that — the whole reason `HashAnchor`
 * exists is so nothing above the adapter mentions Stellar.
 *
 * The composition root supplies the concrete implementation, exactly as it
 * does for every repository here. Any `HashAnchor` satisfies this by shape, so
 * the two stay compatible without a dependency edge.
 */
export interface HashAnchorPort {
  anchor(
    hash: string,
  ): Promise<
    | { readonly kind: "ok"; readonly value: AnchorReceiptLike }
    | { readonly kind: "err"; readonly error: AnchorFailure }
  >;
}

/**
 * The read half of an anchoring ledger: confirming that a commitment really
 * exists somewhere the operator does not control.
 *
 * Declared separately from {@link HashAnchorPort} because verification needs
 * *no credentials at all* — it reads public ledger data. Coupling the two into
 * one port would mean a deployment that wants nothing more than to check its
 * own anchors against the ledger has to hold a funded account's secret key to
 * do it, which is precisely the trust boundary anchoring exists to remove.
 *
 * Structurally the second half of `HashAnchor` in `@verixa/stellar-anchor`,
 * and — as with that port — deliberately not imported from it, so nothing above
 * the adapter mentions a specific ledger.
 */
export interface AnchorVerifierPort {
  verify(
    hash: string,
    anchorRef: string,
  ): Promise<
    | { readonly kind: "ok"; readonly value: boolean }
    | { readonly kind: "err"; readonly error: AnchorFailure }
  >;
}

/** The minimum an anchoring failure must carry. */
export interface AnchorFailure {
  readonly message: string;
}

/** The receipt shape {@link HashAnchorPort.anchor} resolves with. */
export interface AnchorReceiptLike {
  readonly hash: string;
  readonly anchorRef: string;
  readonly anchoredAt: Date;
  readonly network: string;
}
