import { DomainError, Result } from "@verixa/shared-kernel";

import type { AuditLogRepository } from "../../application/ports/audit-log-repository.js";
import type {
  AuditRecorder,
  RecordAuditEventCommand,
} from "../../application/use-cases/record-audit-event.js";
import { AuditLogEntry, GENESIS_HASH } from "../../domain/entities/audit-log-entry.js";

/**
 * The queue was full, so this entry was refused.
 *
 * A `DomainError` rather than a plain throw because refusing is the *correct*
 * behaviour being reported: the queue did its job and applied backpressure. The
 * caller needs to be able to tell "audit is saturated" apart from "audit is
 * broken", which is what a stable `code` is for.
 */
export class AuditQueueFullError extends DomainError {
  readonly code = "AUDIT_QUEUE_FULL";
  // 429: the request is legitimate but the system is deliberately not accepting
  // more of it right now — which is exactly what a bounded queue is.
  readonly httpStatusHint = 429;

  constructor(
    readonly queueLimit: number,
    readonly action: string,
  ) {
    super(
      `Audit write queue is full (${String(queueLimit)} entries pending); refused a "${action}" event.`,
    );
  }
}

/** Emitted once per refused record, so overflow is measurable rather than inferred. */
export interface AuditOverflowReport {
  readonly reason: "queue_full";
  /** The entry that will not be written. Kept so an operator can replay it. */
  readonly dropped: RecordAuditEventCommand;
  readonly queueLength: number;
  readonly queueLimit: number;
  /** Running total for this writer's lifetime — the number to alert on. */
  readonly overflowedTotal: number;
  /** Running total written — overflow divided by this is the loss rate. */
  readonly writtenTotal: number;
}

/** Emitted when a whole batch failed, carrying the entries so nothing vanishes. */
export interface AuditBatchFailureReport {
  readonly reason: "flush_failed" | "write_rejected";
  readonly commands: readonly RecordAuditEventCommand[];
  readonly attempts: number;
  readonly error: unknown;
}

/** Counters a caller can scrape into a metrics endpoint. */
export interface AuditWriterStats {
  readonly pending: number;
  readonly enqueued: number;
  readonly written: number;
  readonly batches: number;
  /** Batches the compare-and-set refused because the head had moved. */
  readonly conflicts: number;
  readonly overflowed: number;
  readonly largestBatch: number;
  readonly failedBatches: number;
}

export interface BatchedAuditWriterOptions {
  /** Flush once this many entries are pending. */
  readonly maxBatchSize?: number;
  /** Flush pending entries at least this often, so a quiet period does not strand them. */
  readonly flushIntervalMs?: number;
  /** Hard ceiling on pending entries. The queue never grows past this. */
  readonly maxQueueSize?: number;
  /** Compare-and-set attempts per batch before it is failed. */
  readonly maxFlushAttempts?: number;
  /** Called for every refused entry. This is the overflow *metric* sink. */
  readonly onOverflow?: (report: AuditOverflowReport) => void;
  /** Called when a batch could not be written at all — a real audit gap. */
  readonly onBatchFailure?: (report: AuditBatchFailureReport) => void;
  /** Injected scheduler, so tests do not wait on real timers. */
  readonly setInterval?: (callback: () => void, ms: number) => { clear(): void };
}

const DEFAULT_MAX_BATCH_SIZE = 100;
const DEFAULT_FLUSH_INTERVAL_MS = 250;
const DEFAULT_MAX_QUEUE_SIZE = 10_000;
const DEFAULT_MAX_FLUSH_ATTEMPTS = 3;

/**
 * Batches audit writes behind a bounded in-memory queue.
 *
 * ## Why batching is available at all
 *
 * Every other context publishes events through this path, so the audit
 * subscriber sits downstream of all traffic the system generates. A per-event
 * write is a round trip and a transaction; at any meaningful request rate, those
 * costs are what make auditing the bottleneck — and a bottleneck here is
 * invisible to users, which is the kind of problem that goes unfixed until the
 * log is needed.
 *
 * Inserting a batch of N in one statement rather than N statements is the
 * obvious fix. The less obvious part is that a hash chain is *not* naturally
 * batch-shaped: each entry's hash depends on its predecessor, so a chain cannot
 * be computed in parallel and flushed afterwards. This writer therefore queues
 * pending **commands** — unhashed intents — and builds the chain at flush time,
 * link by link from a head read immediately beforehand. The chain stays strictly
 * serial where it has to be, and the writes batch together where batching is
 * what actually costs.
 *
 * ## The trade being paid for
 *
 * A queued entry is not yet durable. A process that dies with 10,000 entries
 * pending loses all of them, whereas a per-event writer loses at most the one in
 * flight. That is a genuine regression in durability, and the interval flush is
 * what bounds it: with `flushIntervalMs` at 250 the worst case is a quarter
 * second of audit trail rather than the whole queue. Anyone raising
 * `maxBatchSize` for throughput should lower the interval to match, because
 * otherwise the batch window silently becomes the data-loss window.
 *
 * ## Why the queue is bounded, and why overflow refuses the *newest* entry
 *
 * An unbounded queue under sustained overload is not backpressure — it is a
 * memory leak with a delay before the crash, and the crash then takes the whole
 * queue's contents with it. So `maxQueueSize` is a hard ceiling, and it is the
 * *incoming* entry that gets refused rather than the oldest queued one.
 *
 * Evicting oldest was the alternative considered and rejected. A caller whose
 * `record()` returned success has been told that entry will be written; evicting
 * it later makes that promise false and turns log reliability into a function of
 * load, which is precisely when auditing matters most. Refusing newest keeps
 * `record()`'s answer honest: it reports at the moment of the call whether the
 * entry was accepted, and everything accepted will be written.
 *
 * Refused entries are never silently discarded. Every one is reported through
 * `onOverflow` with a running total, which is what makes the gap visible in
 * metrics rather than discovered during an incident review.
 */
export class BatchedAuditWriter implements AuditRecorder {
  private readonly queue: RecordAuditEventCommand[] = [];
  private readonly maxBatchSize: number;
  private readonly flushIntervalMs: number;
  private readonly maxQueueSize: number;
  private readonly maxFlushAttempts: number;
  private readonly onOverflow: (report: AuditOverflowReport) => void;
  private readonly onBatchFailure: (report: AuditBatchFailureReport) => void;
  private readonly scheduler: (callback: () => void, ms: number) => { clear(): void };

  private timer: { clear(): void } | undefined;
  private flushing: Promise<void> | undefined;
  private stopped = false;

  private enqueuedTotal = 0;
  private writtenTotal = 0;
  private batchesTotal = 0;
  private conflictsTotal = 0;
  private overflowedTotal = 0;
  private largestBatchTotal = 0;
  private failedBatchesTotal = 0;

  constructor(
    private readonly repository: AuditLogRepository,
    options: BatchedAuditWriterOptions = {},
  ) {
    this.maxBatchSize = options.maxBatchSize ?? DEFAULT_MAX_BATCH_SIZE;
    this.flushIntervalMs = options.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS;
    this.maxQueueSize = options.maxQueueSize ?? DEFAULT_MAX_QUEUE_SIZE;
    this.maxFlushAttempts = options.maxFlushAttempts ?? DEFAULT_MAX_FLUSH_ATTEMPTS;
    this.onOverflow = options.onOverflow ?? (() => undefined);
    this.onBatchFailure = options.onBatchFailure ?? (() => undefined);
    this.scheduler = options.setInterval ?? defaultSetInterval;
  }

  /** Number of entries waiting to be written. */
  get pending(): number {
    return this.queue.length;
  }

  /** Lifetime counters, suitable for export as metrics. */
  stats(): AuditWriterStats {
    return {
      pending: this.queue.length,
      enqueued: this.enqueuedTotal,
      written: this.writtenTotal,
      batches: this.batchesTotal,
      conflicts: this.conflictsTotal,
      overflowed: this.overflowedTotal,
      largestBatch: this.largestBatchTotal,
      failedBatches: this.failedBatchesTotal,
    };
  }

  /**
   * The `AuditRecorder` face of this writer, so a route or event handler can be
   * wired to either strategy without knowing which.
   *
   * Always resolves `undefined`: the entry does not exist yet -- it is linked and
   * hashed at flush time -- so there is no entry to hand back. A refused entry is
   * reported through `onOverflow` with a metric rather than through the return
   * value, which is why the port documents `undefined` as "not written" rather
   * than as "failed".
   */
  execute(command: RecordAuditEventCommand): Promise<AuditLogEntry | undefined> {
    this.record(command);
    return Promise.resolve(undefined);
  }

  /**
   * Starts the periodic flush. Safe to call twice, and a no-op after `stop()`.
   *
   * Separate from the constructor because an object whose constructor starts a
   * timer cannot be built in a test without leaking it — and the interval is the
   * thing bounding the durability loss, so a writer built and never started is
   * one that only flushes when its batch is full.
   */
  start(): this {
    if (this.timer !== undefined || this.stopped) {
      return this;
    }
    this.timer = this.scheduler(() => {
      // Deliberately not awaited. The callback cannot be async without
      // permitting overlapping flushes, and `flush()` already coalesces.
      void this.flush();
    }, this.flushIntervalMs);
    return this;
  }

  /**
   * Stops the timer and writes whatever is still pending.
   *
   * Call this on shutdown. Skipping it during a graceful shutdown is the one way
   * to turn the bounded-queue trade-off into actual data loss.
   */
  async stop(): Promise<void> {
    this.stopped = true;
    this.timer?.clear();
    this.timer = undefined;
    await this.settle();
  }

  /**
   * Offers one entry to the queue.
   *
   * Synchronous and never awaiting, deliberately: taking an audit record in a
   * request path must not make that path depend on the database's latency. The
   * caller's only signal is whether the entry was accepted.
   */
  record(command: RecordAuditEventCommand): Result<void, AuditQueueFullError> {
    if (this.queue.length >= this.maxQueueSize) {
      this.overflowedTotal += 1;
      this.onOverflow({
        reason: "queue_full",
        dropped: command,
        queueLength: this.queue.length,
        queueLimit: this.maxQueueSize,
        overflowedTotal: this.overflowedTotal,
        writtenTotal: this.writtenTotal,
      });
      return Result.err(new AuditQueueFullError(this.maxQueueSize, command.action));
    }

    this.queue.push(command);
    this.enqueuedTotal += 1;

    // Flush opportunistically once a full batch is waiting, so throughput does
    // not depend on traffic happening to line up with the interval.
    if (this.queue.length >= this.maxBatchSize) {
      void this.flush();
    }

    return Result.ok(undefined);
  }

  /**
   * Writes pending entries as one atomic batch.
   *
   * Concurrent calls share the in-flight flush rather than starting a second:
   * two overlapping flushes would each read a head, and one would lose the
   * compare-and-set and redo work the other had already done.
   */
  flush(): Promise<void> {
    if (this.flushing !== undefined) {
      return this.flushing;
    }
    const run = this.drainOnce();
    const tracked = run.catch(() => undefined);
    this.flushing = tracked;
    return tracked.finally(() => {
      if (this.flushing === tracked) {
        this.flushing = undefined;
      }
    });
  }

  /** Repeatedly flushes until the queue is empty or a batch fails. */
  async settle(): Promise<void> {
    while (this.queue.length > 0) {
      const before = this.queue.length;
      await this.flush();
      // A pass that removed nothing means the batch failed and has already been
      // reported; spinning on it would hang shutdown.
      if (this.queue.length >= before) {
        break;
      }
    }
    // Wait out a flush that started after we began settling.
    await this.flushing;
  }

  private async drainOnce(): Promise<void> {
    if (this.queue.length === 0) {
      return;
    }

    const batch = this.queue.slice(0, this.maxBatchSize);
    let lastError: unknown;

    for (let attempt = 0; attempt < this.maxFlushAttempts; attempt += 1) {
      try {
        const previous = await this.repository.findLatest();
        const expectedPreviousHash = previous?.hash ?? GENESIS_HASH;

        // Chain built here, from the head just read — as late as possible. This
        // is what lets a batch be one insert statement without the entries
        // having been linked to a head that may have moved since they were
        // queued.
        const entries: AuditLogEntry[] = [];
        let tail = previous;
        for (const command of batch) {
          const entry = AuditLogEntry.append({
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

        const outcome = await this.repository.appendMany(entries, expectedPreviousHash);
        if (Result.isOk(outcome)) {
          this.queue.splice(0, batch.length);
          this.writtenTotal += entries.length;
          this.batchesTotal += 1;
          this.largestBatchTotal = Math.max(this.largestBatchTotal, entries.length);
          return;
        }

        // The head moved under us — a competing writer, or a direct
        // `RecordAuditEvent` call that bypassed this queue. Nothing was written
        // and nothing left the queue, so retrying re-links onto the new head.
        lastError = outcome.error;
        this.conflictsTotal += 1;
      } catch (error) {
        // Not counted as a conflict: `conflicts` means "someone else moved the
        // head first", and a connection error is not that. Counting both would
        // send an operator chasing a fork that never happened, so a genuine
        // failure shows up only where it belongs -- `failedBatches`, and the
        // report below.
        lastError = error;
      }
    }

    this.queue.splice(0, batch.length);
    this.failedBatchesTotal += 1;
    this.onBatchFailure({
      reason: "flush_failed",
      commands: batch,
      attempts: this.maxFlushAttempts,
      error: lastError,
    });
  }
}

function defaultSetInterval(callback: () => void, ms: number): { clear(): void } {
  const handle = setInterval(callback, ms);
  return { clear: (): void => void clearInterval(handle) };
}
