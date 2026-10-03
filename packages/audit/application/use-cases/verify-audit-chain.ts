import { Result, ValidationError } from "@verixa/shared-kernel";

import {
  type AuditLogEntry,
  type ChainBreak,
  verifyChainFrom,
} from "../../domain/entities/audit-log-entry.js";
import type {
  AnchorFailure,
  AnchorRecord,
  AnchorRecordRepository,
  AnchorVerifierPort,
  AuditLogRepository,
} from "../ports/audit-log-repository.js";

/** Entries loaded per round trip when walking the chain. */
export const DEFAULT_VERIFY_BATCH_SIZE = 500;

/**
 * Upper bound on a batch. A caller asking for more is asking to load a large
 * slice of the log into memory in one query, which is the thing batching
 * exists to prevent; the ceiling is generous enough that no real operator
 * hits it by accident.
 */
export const MAX_VERIFY_BATCH_SIZE = 5_000;

/** How many anchor receipts one verification consults by default. */
export const DEFAULT_MAX_ANCHOR_CHECKS = 20;

export interface VerifyAuditChainCommand {
  /**
   * First sequence to verify. Defaults to 1 — the whole chain.
   *
   * A window is legitimate for a log too large to re-hash on every run, or for
   * re-checking just the range touched since the last verification. Its cost is
   * that a break *before* the window is invisible from inside it, which is why
   * the result reports `seededFromWindowStart`: whoever reads the answer needs
   * to know the check began mid-chain rather than at genesis.
   */
  readonly fromSequence?: number;
  /** Last sequence to verify (inclusive). Defaults to the current chain head. */
  readonly toSequence?: number;
  /**
   * Reports how many verified entries belong to this organization.
   *
   * The walk is still the whole chain — see the class comment for why an
   * organization-only walk would be unsound.
   */
  readonly organizationId?: string;
  /** Round-trip size for the walk. */
  readonly batchSize?: number;
  /**
   * Also check anchored ranges against the external ledger. Needs the use case
   * to have been constructed with an anchor repository and a verifier; without
   * them `anchorsSkipped` says so rather than pretending the check ran.
   */
  readonly checkAnchors?: boolean;
  readonly maxAnchorChecks?: number;
}

/** One anchor receipt and what the two independent checks said about it. */
export interface AnchorChainCheck {
  readonly sequence: number;
  readonly chainHash: string;
  readonly anchorRef: string;
  readonly network: string;
  /**
   * Whether this database recomputes the same hash at that sequence.
   * `undefined` when the sequence fell outside the verified range — that is an
   * absence of evidence, not a mismatch, and reporting it as one would turn a
   * narrow verification run into a false tampering alarm.
   */
  readonly matchesDatabaseChain: boolean | undefined;
  /** Whether the public ledger holds that hash under that reference. */
  readonly matchesLedger: boolean | undefined;
  /** Set when the ledger lookup itself could not complete. */
  readonly ledgerError: string | undefined;
}

export interface VerifyAuditChainResult {
  /** Whether the verified range is intact. False exactly when `firstBreak` is set. */
  readonly valid: boolean;
  readonly fromSequence: number;
  /** Last sequence actually verified; `undefined` when the range was empty. */
  readonly toSequence: number | undefined;
  /** Entries walked. */
  readonly checkedEntries: number;
  /** Entries walked that carry this organization's id; 0 when unscoped. */
  readonly organizationEntryCount: number;
  /** Head hash of the verified range — the value an anchor commits to. */
  readonly headHash: string | undefined;
  readonly firstBreak: ChainBreak | undefined;
  /** True when verification began partway into the chain. */
  readonly seededFromWindowStart: boolean;
  readonly organizationId: string | undefined;
  readonly anchorChecks: readonly AnchorChainCheck[];
  /** True when `checkAnchors` was asked for but no ledger is wired. */
  readonly anchorsSkipped: boolean;
}

export type VerifyAuditChainError = ValidationError | AnchorFailure;

/**
 * Walks the audit log re-deriving every hash, and reports the first divergence.
 *
 * ## Why this exists as a runnable check
 *
 * `verifyChain` is a property of the domain model, and a property nobody can
 * invoke is not a security control. Tamper-evidence only bites when someone
 * actually looks — an operator, an auditor, or a scheduled job re-hashing the
 * log and comparing. This use case is that action, and
 * `infrastructure/cli/verify-chain.ts` is its operator-facing form.
 *
 * Detection, not prevention. The append-only constraints mean Verixa itself
 * cannot edit these rows, but nothing here stops an attacker holding database
 * credentials, and no check can. What this produces is proof that they did.
 *
 * ## Why the walk is batched, and outside any transaction
 *
 * Hashing a million entries is CPU work. Doing it with a transaction open — or
 * a pooled connection parked on it — turns a verification into an outage for
 * everything else sharing that database. Each batch is one independent read, so
 * the connection returns to the pool between them and a verification running
 * alongside live traffic is just another reader. Expensive work stays outside
 * transaction boundaries, as every use case here requires.
 *
 * The consequence is that a verification is a snapshot taken over time: the
 * chain may grow while it runs, which is harmless, since new entries link to
 * the old head and cannot invalidate what was already checked.
 *
 * ## Organization scoping, and the alternative that was rejected
 *
 * There is one chain and `organizationId` is a field inside it, so filtering to
 * one tenant's entries and re-deriving hashes over that filtered list reports a
 * break on every entry after the first — a subsequence of a chain is not a
 * chain, because each entry commits to its *global* predecessor. Per-organization
 * chains would need a per-organization `sequence`, and `sequence` is globally
 * unique precisely because that is what makes a forked append impossible.
 *
 * So an organization-scoped run verifies the entire range and reports which
 * entries inside it belong to the tenant. That answers the question an operator
 * actually has — "are this organization's records, and the links running
 * through everyone else's records between them, intact?" — at the same cost as
 * an unscoped run.
 *
 * ## Anchored ranges
 *
 * When `checkAnchors` is set, each receipt is checked two ways, and the two
 * answers mean different things:
 * - `matchesDatabaseChain` — the hash this database recomputes at that sequence
 *   equals the hash the receipt claims was anchored. Fails when the local log
 *   was rewritten after anchoring.
 * - `matchesLedger` — the public ledger really holds that hash under that
 *   reference, which is independent of Verixa entirely: it is what an auditor
 *   with no access to our systems would find.
 *
 * Ledger matches but database mismatch is the tampering signal. Database
 * matches but ledger mismatch means the receipt is fabricated.
 */
export class VerifyAuditChain {
  constructor(
    private readonly repository: AuditLogRepository,
    private readonly anchorRecords?: AnchorRecordRepository,
    private readonly anchorVerifier?: AnchorVerifierPort,
  ) {}

  async execute(
    command: VerifyAuditChainCommand = {},
  ): Promise<Result<VerifyAuditChainResult, VerifyAuditChainError>> {
    const invalid = validateCommand(command);
    if (invalid !== undefined) return Result.err(invalid);

    const fromSequence = command.fromSequence ?? 1;
    const batchSize = command.batchSize ?? DEFAULT_VERIFY_BATCH_SIZE;
    const toSequence = command.toSequence;
    const organizationId = command.organizationId;

    const records =
      command.checkAnchors === true && this.anchorRecords !== undefined
        ? await this.anchorRecords.findAll(command.maxAnchorChecks ?? DEFAULT_MAX_ANCHOR_CHECKS)
        : [];

    const walk = await this.walk(fromSequence, toSequence, batchSize, organizationId, records);

    const anchorChecks =
      command.checkAnchors === true ? await this.checkAnchors(records, walk) : [];

    return Result.ok({
      valid: walk.firstBreak === undefined,
      fromSequence,
      toSequence: walk.lastSequence,
      checkedEntries: walk.checkedEntries,
      organizationEntryCount: walk.organizationEntryCount,
      headHash: walk.headHash,
      firstBreak: walk.firstBreak,
      seededFromWindowStart: fromSequence > 1,
      organizationId,
      anchorChecks,
      anchorsSkipped: command.checkAnchors === true && !this.hasAnchorWiring(),
    });
  }

  private hasAnchorWiring(): boolean {
    return this.anchorRecords !== undefined && this.anchorVerifier !== undefined;
  }

  /**
   * Streams the chain in batches, checking each page against the entry that
   * preceded it, and stops at the first break.
   *
   * Only the hashes at anchored sequences are retained, so memory stays
   * proportional to the number of receipts rather than to the size of the log.
   */
  private async walk(
    fromSequence: number,
    toSequence: number | undefined,
    batchSize: number,
    organizationId: string | undefined,
    records: readonly AnchorRecord[],
  ): Promise<{
    readonly checkedEntries: number;
    readonly organizationEntryCount: number;
    readonly lastSequence: number | undefined;
    readonly headHash: string | undefined;
    readonly firstBreak: ChainBreak | undefined;
    readonly hashesBySequence: ReadonlyMap<number, string>;
  }> {
    const wantedSequences = new Set(records.map((record) => record.sequence));

    let previous: AuditLogEntry | undefined;
    // A window that starts mid-chain must be seeded with its predecessor, or
    // the first entry's link check compares against the genesis hash and
    // reports a break in a chain that is perfectly intact.
    if (fromSequence > 1) {
      const [seed] = await this.repository.findFrom(fromSequence - 1, 1);
      previous = seed;
    }

    const hashesBySequence = new Map<number, string>();
    let checkedEntries = 0;
    let organizationEntryCount = 0;
    let cursor = fromSequence;
    let firstBreak: ChainBreak | undefined;

    while (firstBreak === undefined) {
      const remaining = toSequence === undefined ? undefined : toSequence - cursor + 1;
      if (remaining !== undefined && remaining < 1) break;
      const limit = remaining === undefined ? batchSize : Math.min(batchSize, remaining);

      const page = await this.repository.findFrom(cursor, limit);
      if (page.length === 0) break;

      firstBreak = verifyChainFrom(previous, page);

      // Inspected, not merely fetched: once a break is found the entries behind
      // it are noise, and counting them would make a log broken at sequence 2
      // look like a log of which 10,000 entries were examined.
      const inspected =
        firstBreak === undefined
          ? page
          : page.filter((entry) => entry.sequence <= firstBreak!.sequence);

      for (const entry of inspected) {
        checkedEntries += 1;
        if (organizationId !== undefined && entry.metadata["organizationId"] === organizationId) {
          organizationEntryCount += 1;
        }
        if (wantedSequences.has(entry.sequence)) {
          hashesBySequence.set(entry.sequence, entry.hash);
        }
      }

      const last = page.at(-1);
      if (last === undefined) break;
      previous = last;
      cursor = last.sequence + 1;

      // A short page means the log ended; the sequence after the final entry
      // would return nothing, so stop rather than issue a pointless query.
      if (page.length < limit) break;
    }

    return {
      checkedEntries,
      organizationEntryCount,
      lastSequence: previous?.sequence,
      headHash: previous?.hash,
      firstBreak,
      hashesBySequence,
    };
  }

  private async checkAnchors(
    records: readonly AnchorRecord[],
    walk: { readonly hashesBySequence: ReadonlyMap<number, string> },
  ): Promise<readonly AnchorChainCheck[]> {
    const checks: AnchorChainCheck[] = [];

    for (const record of records) {
      const databaseHash = walk.hashesBySequence.get(record.sequence);

      let matchesLedger: boolean | undefined;
      let ledgerError: string | undefined;

      // Skipped when the sequence is outside the verified range: there is no
      // recomputed hash to compare with, and asking the ledger about a hash we
      // cannot confirm we still produce would report a clean bill of health for
      // a receipt this run knows nothing about.
      if (this.anchorVerifier !== undefined && databaseHash !== undefined) {
        const verified = await this.anchorVerifier.verify(record.chainHash, record.anchorRef);
        if (Result.isErr(verified)) {
          ledgerError = verified.error.message;
        } else {
          matchesLedger = verified.value;
        }
      }

      checks.push({
        sequence: record.sequence,
        chainHash: record.chainHash,
        anchorRef: record.anchorRef,
        network: record.network,
        matchesDatabaseChain:
          databaseHash === undefined ? undefined : databaseHash === record.chainHash,
        matchesLedger,
        ledgerError,
      });
    }

    return checks;
  }
}

function validateCommand(command: VerifyAuditChainCommand): ValidationError | undefined {
  const fromSequence = command.fromSequence ?? 1;

  if (fromSequence < 1) {
    return new ValidationError("fromSequence must be at least 1.", {
      fromSequence: ["must be >= 1"],
    });
  }

  if (command.toSequence !== undefined && command.toSequence < fromSequence) {
    return new ValidationError("toSequence must not precede fromSequence.", {
      toSequence: ["must be >= fromSequence"],
    });
  }

  const batchSize = command.batchSize ?? DEFAULT_VERIFY_BATCH_SIZE;
  if (batchSize < 1 || batchSize > MAX_VERIFY_BATCH_SIZE) {
    return new ValidationError(
      `batchSize must be between 1 and ${String(MAX_VERIFY_BATCH_SIZE)}.`,
      { batchSize: [`must be between 1 and ${String(MAX_VERIFY_BATCH_SIZE)}`] },
    );
  }

  return undefined;
}
