import { Result } from "@verixa/shared-kernel";

import type { AuditAction, AuditLogEntry } from "../../domain/entities/audit-log-entry.js";
import { AuditLogEntry as Entry, GENESIS_HASH } from "../../domain/entities/audit-log-entry.js";
import { AuditLogEntry as Entry } from "../../domain/entities/audit-log-entry.js";
import { AuditMetadata, rejectionReasonOf } from "../../domain/value-objects/audit-metadata.js";
import type { AuditLogRepository } from "../ports/audit-log-repository.js";

export interface RecordAuditEventCommand {
  readonly action: AuditAction;
  readonly actorId?: string | undefined;
  readonly subjectId?: string | undefined;
  readonly metadata?: Readonly<Record<string, string>>;
  /** Fixed timestamp, for callers recording an event that already happened. */
  readonly occurredAt?: Date | undefined;
}

/** Default ceiling on compare-and-set retries per `execute` call. */
const DEFAULT_MAX_ATTEMPTS = 3;

/**
 * Anything that takes an audit record for a domain event that happened.
 *
 * ## Why this is a port when one implementation already existed
 *
 * `RecordAuditEvent` writes synchronously: it returns once the entry is in the
 * log. `BatchedAuditWriter` returns once the entry is *queued*, which is the
 * whole point of it under load. Those are different latencies with the same
 * meaning to the caller -- "this event was offered for recording" -- and no route
 * in `apps/api` should have to know which one was wired. Without the port,
 * turning batching on means editing every call site.
 *
 * ## What implementations owe the caller
 *
 * `execute` resolves with the entry that was written, or `undefined` when nothing
 * was written. It must never reject: the operation being audited already
 * succeeded, and an audit failure reported as a thrown error converts a
 * bookkeeping problem into a user-facing outage.
 *
 * `undefined` therefore covers three different situations -- a transient write
 * failure, a lost race, and a full queue -- and they are not distinguishable from
 * the return value by design. Anything that needs to tell them apart is a metrics
 * consumer and should read the writer's overflow and failure reports instead of
 * inferring them from a route.
 */
export interface AuditRecorder {
  execute(command: RecordAuditEventCommand): Promise<AuditLogEntry | undefined>;
}

/**
 * Appends one entry to the audit log.
 *
 * ## Why this returns nothing and throws nothing
 *
 * Audit recording sits alongside the operation being audited, not in front of
 * it. A login that succeeded should not be reported as failed because the
 * audit write failed, and a caller should not have to decide what to do about
 * it — so failures are swallowed here and reported through the logger.
 *
 * That is a real trade and worth being explicit about: it means an attacker
 * who can reliably break audit writes can act unrecorded. The mitigation is
 * not to fail the user's request, which mostly produces an outage; it is that
 * a gap in the sequence is *visible* — `verifyChain` reports `sequence_gap`,
 * and the anchored chain head will not match what the operator expects.
 *
 * ## Serialization
 *
 * Appends must not run concurrently. Two entries built from the same
 * predecessor produce two chains claiming the same sequence, and the second
 * insert fails on the unique index — which is the correct outcome, but only
 * because the index is there. This is why `sequence` is unique in the schema
 * rather than merely indexed.
 *
 * The repository turns that failure into a `ChainConflictError` rather than
 * leaving it as a database error, and this class is where the *response* lives:
 * re-read the head, relink onto it, try again. Retrying is safe precisely
 * because the losing append never landed — the retry is not writing a second
 * entry, it is completing the one the caller asked for.
 *
 * Bounded, because an unbounded retry loop under sustained contention is a
 * memory and CPU leak that turns a throughput problem into an outage. Giving
 * up and reporting through `onError` is the right endpoint: a missing audit
 * entry is bad, a wedged process is worse, and the gap is detectable either
 * way.
 * ## Metadata bounds are checked here; content is not
 *
 * Metadata is the one part of an entry that usually comes from outside the
 * process, so this is where `AuditMetadata` puts its limits: how many fields,
 * how long each key and value, and that every value is a string. Those are
 * checked on the way in because a bound cannot be imposed later — by the time
 * an exporter is writing a cell, the oversized bag is already the record.
 *
 * What is *not* done here is escaping newlines, commas, or control characters.
 * That is the encoder's job, at each boundary where text could be misread (see
 * `AuditMetadata.toLogFields` and `ExportAuditEvents`), and rewriting values on
 * the way in would mean the digest commits to something other than what was
 * supplied. The distinction is deliberate and worth keeping: **bounds on input,
 * escaping on output.**
 *
 * When the bounds are exceeded the entry is still appended, with the bag
 * replaced by a marker naming the reason. Refusing to record would let anyone
 * who can trigger a rejected write act unrecorded, which is the worse failure;
 * the marker means the attempt is visible in the log rather than silently
 * dropped.
 */
export class RecordAuditEvent implements AuditRecorder {
  constructor(
    private readonly repository: AuditLogRepository,
    private readonly onError: (error: unknown) => void = () => undefined,
    private readonly maxAttempts: number = DEFAULT_MAX_ATTEMPTS,
  ) {}

  async execute(command: RecordAuditEventCommand): Promise<AuditLogEntry | undefined> {
    try {
      for (let attempt = 0; attempt < this.maxAttempts; attempt += 1) {
        const previous = await this.repository.findLatest();
        const expectedPreviousHash = previous?.hash ?? GENESIS_HASH;

        const entry = Entry.append({
          action: command.action,
          actorId: command.actorId,
          subjectId: command.subjectId,
          metadata: command.metadata ?? {},
          occurredAt: command.occurredAt,
          previous,
        });

        const outcome = await this.repository.append(entry, expectedPreviousHash);
        if (Result.isOk(outcome)) {
          return entry;
        }

        // Lost the race. Loop re-reads the head, so the next attempt links
        // onto whatever the winning writer put there.
      }
      const entry = Entry.append({
        action: command.action,
        actorId: command.actorId,
        subjectId: command.subjectId,
        metadata: metadataFor(command),
        previous,
      });

      this.onError(
        new Error(
          `Audit append lost ${String(this.maxAttempts)} consecutive chain races and was abandoned.`,
        ),
      );
      return undefined;
    } catch (error) {
      // Never propagates. See the class comment: the audited operation
      // already happened, and failing it now would be reporting a false
      // negative to the user.
      this.onError(error);
      return undefined;
    }
  }
}

/**
 * Records a burst of events as one atomic chain extension.
 *
 * The batch counterpart to {@link RecordAuditEvent}, and the reason the
 * `AuditLogRepository` port has `appendMany`. Entries are linked in the order
 * given, so a caller recording N events gets one chain of N new entries rather
 * than N independent compare-and-sets — which matters both for throughput (one
 * transaction) and for evidence (a batch that cannot be partially applied is a
 * batch whose ordering is guaranteed).
 */
export async function recordAuditEventBatch(
  repository: AuditLogRepository,
  commands: readonly RecordAuditEventCommand[],
  onError: (error: unknown) => void = () => undefined,
): Promise<readonly AuditLogEntry[]> {
  if (commands.length === 0) {
    return [];
  }

  try {
    const previous = await repository.findLatest();
    // The hash of the head *before* this batch — that is what `appendMany`
    // compare-and-sets against. The entries' own links are checked by the
    // repository walking the batch, not by this argument.
    const expectedPreviousHash = previous?.hash ?? GENESIS_HASH;

    let tail = previous;
    const entries: AuditLogEntry[] = [];
    for (const command of commands) {
      const entry = Entry.append({
        action: command.action,
        actorId: command.actorId,
        subjectId: command.subjectId,
        metadata: command.metadata ?? {},
        occurredAt: command.occurredAt,
        previous: tail,
      });
      entries.push(entry);
      tail = entry;
    }

    const outcome = await repository.appendMany(entries, expectedPreviousHash);
    if (Result.isErr(outcome)) {
      onError(outcome.error);
      return [];
    }

    return entries;
  } catch (error) {
    onError(error);
    return [];
  }
function metadataFor(command: RecordAuditEventCommand): Readonly<Record<string, string>> {
  const created = AuditMetadata.create(command.metadata ?? {});

  if (Result.isOk(created)) return created.value.values;

  return AuditMetadata.rejected(rejectionReasonOf(created.error)).values;
}
