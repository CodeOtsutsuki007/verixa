import { DomainError, type Result } from "@verixa/shared-kernel";

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
 * The append protocol's failure mode: someone else extended the chain first.
 *
 * Returned rather than thrown because it is *expected* under load — the whole
 * point of a compare-and-set is that losing the race is a normal outcome with
 * a defined response (re-read the head, relink, try again). A caller that has
 * to wrap every audit write in a `try` to discover this either swallows it or
 * crashes, and neither is what you want from the security-relevant log.
 *
 * Carries both hashes, because the difference between them is the diagnosis:
 * `expected` is what the writer thought it was appending to, `actual` is what
 * the chain head really is. If they differ, a concurrent writer won; if
 * `actual` is a hash the caller has never seen, something else is wrong and
 * worth a look.
 */
export class ChainConflictError extends DomainError {
  readonly code = "AUDIT_CHAIN_CONFLICT";
  // 409: the request is well-formed and conflicts with current state, which is
  // precisely what "the chain moved underneath you" is.
  readonly httpStatusHint = 409;

  constructor(
    readonly expectedPreviousHash: string,
    readonly actualPreviousHash: string,
  ) {
    super(
      `Audit append expected the chain head to be ${expectedPreviousHash} but found ${actualPreviousHash}.`,
    );
  }
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
 *
 * ## Why every append carries `expectedPreviousHash`
 *
 * A new entry commits to its predecessor's hash, so writing one is only safe
 * if you know what the predecessor is. The naive sequence — read the head,
 * build an entry, insert it — has a window between the read and the insert in
 * which another writer can extend the chain, producing two entries that claim
 * the same predecessor and a forked chain in which one branch is silently
 * unreachable.
 *
 * So the read is not trusted: the insert re-checks it and reports
 * {@link ChainConflictError} when the head has moved. Callers react by
 * re-reading and retrying, and the chain can only ever extend linearly.
 */
export interface AuditLogRepository {
  /**
   * The most recent entry, or `undefined` when the log is empty.
   *
   * Callers need this to append: a new entry commits to its predecessor's
   * hash, so writing one requires having read the tail. Note that the value
   * read here is a *proposal*, not a guarantee — the guarantee is the
   * `expectedPreviousHash` check inside `append`.
   */
  findLatest(): Promise<AuditLogEntry | undefined>;

  /**
   * Appends `entry` iff the chain still ends at `expectedPreviousHash`.
   *
   * The check and the insert must be one indivisible operation. Passing the
   * genesis hash appends to an empty chain, which is what makes a fresh
   * install and a raced append the same code path rather than two.
   */
  append(
    entry: AuditLogEntry,
    expectedPreviousHash: string,
  ): Promise<Result<void, ChainConflictError>>;

  /**
   * Appends `entries` as one atomic unit, iff the chain ends at
   * `expectedPreviousHash`.
   *
   * All-or-nothing by contract: a partial batch would leave the chain ending
   * at an entry whose successors were rejected, which is a gap — the one thing
   * verification is supposed to be able to detect. Callers hold each entry's
   * `previousHash` link to its predecessor in this batch; validating that the
   * batch is internally consistent before inserting is the adapter's job, not
   * the caller's reward.
   */
  appendMany(
    entries: readonly AuditLogEntry[],
    expectedPreviousHash: string,
  ): Promise<Result<void, ChainConflictError>>;

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
