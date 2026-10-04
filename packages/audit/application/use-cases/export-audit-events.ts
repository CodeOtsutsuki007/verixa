import { Result, ValidationError } from "@verixa/shared-kernel";

import type { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";
import type { AuditLogFilters, AuditLogRepository } from "../ports/audit-log-repository.js";

/** The portable formats a compliance export can be produced in. */
export type ExportAuditEventsFormat = "csv" | "json";

export interface ExportAuditEventsCommand {
  readonly format: ExportAuditEventsFormat;
  /**
   * The same filters `QueryAuditEvents` accepts (Issue 187). Reused rather
   * than redefined so the export and the in-app query can never drift apart:
   * an export that filtered differently from the query it is meant to mirror
   * would be a compliance bug that tests would have to catch twice.
   */
  readonly filters?: AuditLogFilters;
  /**
   * Entries fetched per repository round-trip. Bounds peak memory: only one
   * page is ever held at a time, regardless of how large the log is.
   */
  readonly batchSize?: number;
}

export type ExportAuditEventsError = ValidationError;

/** One row of the export, flattened from {@link AuditLogEntry}. */
interface AuditExportRecord {
  readonly sequence: number;
  readonly id: string;
  readonly action: string;
  readonly actorId: string | null;
  readonly subjectId: string | null;
  readonly occurredAt: string;
  readonly metadata: Readonly<Record<string, string>>;
  readonly previousHash: string;
  readonly hash: string;
}

const DEFAULT_BATCH_SIZE = 500;

const CSV_COLUMNS = [
  "sequence",
  "id",
  "action",
  "actorId",
  "subjectId",
  "occurredAt",
  "metadata",
  "previousHash",
  "hash",
] as const;

/**
 * Exports the audit log as a stream of CSV or JSON text.
 *
 * ## Streaming, not buffering
 *
 * The obvious implementation — query every matching entry, build one big
 * string, return it — works beautifully until it doesn't. A compliance
 * export is exactly the kind of operation that runs against a log that has
 * been accumulating for years, and buffering it means peak memory grows with
 * the size of the history being exported. A few hundred thousand entries is
 * enough to exhaust a small container, and the failure is an out-of-memory
 * kill in the middle of an audited export, which is the worst possible time
 * to discover it.
 *
 * So this returns an async iterable and fetches the log one bounded page at
 * a time. Callers write each chunk straight to the response body (or a file
 * stream, or object storage), and peak memory stays flat no matter how many
 * entries match. The cost is that the caller *must* consume the iterable:
 * there is no "give me the whole thing" convenience, because that is the
 * behaviour this design exists to prevent.
 *
 * ## JSON is newline-delimited, not an array
 *
 * Both formats were allowed "per a documented choice". NDJSON (one JSON
 * object per line) is the choice, because it is the one that composes with
 * streaming: an array would require holding the opening bracket, writing a
 * comma before every element after the first, and closing the bracket at the
 * end — bookkeeping that only exists to satisfy a format, not to convey
 * anything. NDJSON is also what downstream tools actually want: `jq`,
 * `grep`, and log pipelines all consume it line by line. The one thing an
 * array buys is being a single valid JSON document, which is a real
 * difference and worth knowing; if a consumer needs that, wrapping the
 * stream is a one-line transformation at the edge.
 *
 * ## CSV escaping
 *
 * Metadata is the attacker-controlled field. It is serialised to JSON first
 * (so a value containing a comma, quote or newline cannot break out of its
 * cell) and then the whole JSON string is quoted and its quotes doubled per
 * RFC 4180. Two layers, because "just join with commas" is precisely the
 * injection the audit-log metadata issue warns about.
 */
export class ExportAuditEvents {
  constructor(private readonly repository: AuditLogRepository) {}

  execute(
    command: ExportAuditEventsCommand,
  ): Result<AsyncIterable<string>, ExportAuditEventsError> {
    const batchSize = command.batchSize ?? DEFAULT_BATCH_SIZE;

    if (!Number.isInteger(batchSize) || batchSize <= 0) {
      return Result.err(
        new ValidationError("batchSize must be a positive integer.", {
          batchSize: ["must be a positive integer"],
        }),
      );
    }

    if (command.format !== "csv" && command.format !== "json") {
      return Result.err(
        new ValidationError(`Unsupported export format "${String(command.format)}".`, {
          format: ["must be one of: csv, json"],
        }),
      );
    }

    const filters = command.filters ?? {};

    return Result.ok(
      command.format === "csv"
        ? this.streamCsv(filters, batchSize)
        : this.streamJson(filters, batchSize),
    );
  }

  private async *streamCsv(
    filters: AuditLogFilters,
    batchSize: number,
  ): AsyncGenerator<string, void, undefined> {
    yield `${CSV_COLUMNS.join(",")}\n`;

    for await (const entry of this.streamEntries(filters, batchSize)) {
      yield `${toCsvRow(entry)}\n`;
    }
  }

  private async *streamJson(
    filters: AuditLogFilters,
    batchSize: number,
  ): AsyncGenerator<string, void, undefined> {
    for await (const entry of this.streamEntries(filters, batchSize)) {
      yield `${JSON.stringify(toExportRecord(entry))}\n`;
    }
  }

  /**
   * Walks the filtered log in keyset order, one bounded page at a time.
   *
   * The page size is the memory ceiling: nothing above this ever holds more
   * than `batchSize` entries. A short page means the filter is exhausted, so
   * the loop stops; a full page means "there may be more" and the cursor
   * advances past the last sequence seen. Filtering happens inside the
   * repository, before the page limit, which is what makes "short page =
   * done" true even when many entries between cursor positions are excluded.
   */
  private async *streamEntries(
    filters: AuditLogFilters,
    batchSize: number,
  ): AsyncGenerator<AuditLogEntry, void, undefined> {
    let cursor = 0;

    for (;;) {
      const page = await this.repository.findWithFilters({
        filters,
        fromSequence: cursor + 1,
        limit: batchSize,
      });

      for (const entry of page) {
        yield entry;
      }

      if (page.length < batchSize) {
        return;
      }

      cursor = page[page.length - 1]!.sequence;
    }
  }
}

function toExportRecord(entry: AuditLogEntry): AuditExportRecord {
  return {
    sequence: entry.sequence,
    id: String(entry.id),
import { Result } from "@verixa/shared-kernel";

import type { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";
import type { AuditReader } from "../../domain/policies/audit-access-policy.js";
import { type AuditReadError, authorizeAndRecordAuditRead } from "../audit-read-access.js";
import type { AuditEventReader } from "../ports/audit-event-reader.js";

import type { RecordAuditEvent } from "./record-audit-event.js";

export interface ExportAuditEventsCommand {
  /** The authenticated caller, built by the interface layer — see {@link AuditReader}. */
  readonly reader: AuditReader;
  /** Whose audit log to export. Must be the reader's own organization. */
  readonly organizationId: string;
  readonly actorId?: string | undefined;
  readonly subjectId?: string | undefined;
  readonly from?: Date | undefined;
  readonly to?: Date | undefined;
}

/**
 * Streams every matching entry of an organization's audit log, for a
 * compliance export, and records that the export happened.
 *
 * Requires `audit:export`, a separate permission from `audit:query` — see
 * `AUDIT_PERMISSIONS` for why bulk disclosure is its own grant.
 *
 * ## Recorded when it starts, not when it finishes
 *
 * The `audit.exported` entry is written before the stream is handed back, so
 * it exists even if the export is abandoned halfway. Recording on completion
 * reads more naturally ("a successful export is logged") but gets the
 * security property backwards: rows leave the system from the first chunk,
 * and a client that disconnects one row before the end would have taken
 * almost everything while leaving no trace. What is audited is the disclosure,
 * and the disclosure starts immediately.
 *
 * Serialization to CSV or JSON is not this use case's concern — it yields
 * entries, and the interface layer (Issue 189) encodes them as it streams.
 */
export class ExportAuditEvents {
  constructor(
    private readonly events: AuditEventReader,
    private readonly recordAuditEvent: RecordAuditEvent,
  ) {}

  async execute(
    command: ExportAuditEventsCommand,
  ): Promise<Result<AsyncIterable<AuditLogEntry>, AuditReadError>> {
    const criteria = {
      organizationId: command.organizationId,
      actorId: command.actorId,
      subjectId: command.subjectId,
      from: command.from,
      to: command.to,
    };

    const access = await authorizeAndRecordAuditRead(
      this.recordAuditEvent,
      command.reader,
      "export",
      criteria,
    );
    if (Result.isErr(access)) return access;

    return Result.ok(this.events.stream(criteria));
  }
import type { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";
import {
  escapeJsonLineTerminators,
  neutralizeFormulaPrefix,
} from "../../domain/value-objects/audit-metadata.js";
import type { AuditLogFilters, AuditLogRepository } from "../ports/audit-log-repository.js";

/**
 * What an export is written as.
 *
 * `jsonl` is the faithful one: one JSON document per line, values exactly as
 * they were recorded. It is what a program should read, what a re-verification
 * should be run against, and what an archive should contain. It is safe by
 * construction because JSON escapes the control characters that would otherwise
 * end a line early.
 *
 * `csv` is the hostile one. It has no escaping rules for anything but quotes,
 * no types, and it is opened in software that executes cell contents. So the
 * CSV writer here is defensive at three separate boundaries — control
 * characters are escaped so one entry is one line, cells containing the
 * delimiters are quoted, and cells that would be read as a formula are
 * neutralized. Every one of the three is needed; each alone is not.
 */
export type AuditExportFormat = "csv" | "jsonl";

/** The columns of a CSV export, in order. */
export const AUDIT_EXPORT_HEADER =
  "sequence,action,actor_id,subject_id,occurred_at,previous_hash,hash,metadata";

/**
 * How many entries one export may produce.
 *
 * An export of an unbounded log is a memory-exhaustion request with an
 * authorization header on it, so the cap is explicit and `truncated` says when
 * it applied. Silently returning a partial file would be worse than the outage:
 * an auditor counting rows would have no way to know the count was a limit
 * rather than a fact.
 */
export const DEFAULT_EXPORT_MAX_RECORDS = 10_000;

const PAGE_SIZE = 500;

export interface ExportAuditEventsCommand {
  readonly format: AuditExportFormat;
  readonly filters?: AuditLogFilters | undefined;
  readonly maxRecords?: number | undefined;
}

export interface ExportAuditEventsResult {
  readonly format: AuditExportFormat;
  readonly body: string;
  readonly recordCount: number;
  readonly truncated: boolean;
}

/**
 * The logging capability an export needs, declared as the minimum shape.
 *
 * pino's `Logger` satisfies this structurally. The use case takes a port
 * rather than importing pino so the domain and application layers stay free of
 * the logging implementation, and so a test can capture what would have been
 * written.
 */
export interface AuditExportLogger {
  info(fields: Readonly<Record<string, string | number | boolean | null>>): void;
}

/**
 * Writes the audit log out as CSV or JSON lines.
 *
 * ## The guarantee the encoders exist to keep
 *
 * One entry, one line. Everything else in this file follows from that: an
 * export whose line count is not its record count cannot be checked by counting
 * it, and a format whose structure an exported value can override is not a
 * container at all. `AuditLogEntry.toLogFields` provides values that cannot
 * contain a raw newline; `csvCell` then quotes and neutralizes what remains.
 *
 * ## What this does not do
 *
 * It does not decide who may export. Authorization for exports is its own
 * roadmap issue, and the export use case deliberately has no notion of a
 * requesting principal — the composition root enforces the policy before
 * calling, and this file stays a serializer with a paging loop attached.
 */
export class ExportAuditEvents {
  readonly #repository: AuditLogRepository;
  readonly #logger: AuditExportLogger | undefined;

  constructor(repository: AuditLogRepository, logger?: AuditExportLogger) {
    this.#repository = repository;
    this.#logger = logger;
  }

  async execute(command: ExportAuditEventsCommand): Promise<ExportAuditEventsResult> {
    const maxRecords = command.maxRecords ?? DEFAULT_EXPORT_MAX_RECORDS;
    const filters = command.filters ?? {};
    const rows: string[] = [];
    let truncated = false;
    let cursor = 0;

    for (;;) {
      const remaining = maxRecords - rows.length;
      if (remaining <= 0) {
        truncated = true;
        break;
      }

      const wanted = Math.min(PAGE_SIZE, remaining);
      // One extra row, so "are there more?" is answered without a second query
      // and without counting rows that will not be used.
      const page = await this.#repository.findWithFilters({
        filters,
        fromSequence: cursor + 1,
        limit: wanted + 1,
      });

      const hasMore = page.length > wanted;
      const entries = hasMore ? page.slice(0, wanted) : page;

      for (const entry of entries) {
        rows.push(command.format === "csv" ? csvRow(entry) : jsonlRow(entry));
      }

      if (!hasMore) break;
      if (entries.length === 0) break;

      cursor = entries[entries.length - 1]?.sequence ?? cursor;
      if (rows.length >= maxRecords) {
        truncated = true;
        break;
      }
    }

    const body =
      command.format === "csv"
        ? `${AUDIT_EXPORT_HEADER}\r\n${rows.map((row) => `${row}\r\n`).join("")}`
        : `${rows.map((row) => `${row}\n`).join("")}`;

    this.#logExport(command.format, rows.length, truncated, filters);

    return {
      format: command.format,
      body,
      recordCount: rows.length,
      truncated,
    };
  }

  /**
   * Records that an export happened.
   *
   * The filter values are attacker-adjacent — they come from whoever asked for
   * the export — and a log line is exactly the sink where a newline is worth
   * something to an attacker. So the record carries the filters as one JSON
   * document in a *field*, with the line terminators JSON leaves raw escaped
   * into their `\u` form, and never in the message.
   *
   * The rejected alternative was `logger.info(\`exported ${count} rows for ${JSON.stringify(filters)}\`)`.
   * It reads more naturally, and it is the bug: pino escapes its fields, but a
   * message is a message, so a `\n` inside a filter value would land in the
   * output verbatim and start a line the application never logged.
   */
  #logExport(
    format: AuditExportFormat,
    recordCount: number,
    truncated: boolean,
    filters: AuditLogFilters,
  ): void {
    this.#logger?.info({
      type: "audit.log.exported",
      format,
      recordCount,
      truncated,
      filters: escapeJsonLineTerminators(JSON.stringify(filters) ?? "{}"),
    });
  }
}

/** A CSV row: every field escaped by the entry, quoted and neutralized here. */
function csvRow(entry: AuditLogEntry): string {
  const fields = entry.toLogFields();

  return [
    fields.sequence,
    fields.action,
    fields.actorId,
    fields.subjectId,
    fields.occurredAt,
    fields.previousHash,
    fields.hash,
    fields.metadata,
  ]
    .map((field) => csvCell(field ?? ""))
    .join(",");
}

/**
 * Encodes one cell.
 *
 * Quoting is per RFC 4180: wrap in double quotes when the value contains a
 * quote, a comma, or a line break, and double the quotes inside. The line
 * breaks cannot be there by the time this runs — `toLogFields` escaped them —
 * and checking anyway keeps the function honest if a caller ever hands it a
 * raw value.
 *
 * Formula neutralization runs on the already-escaped text, which is the order
 * that leaves nothing to miss: a payload hiding its formula character behind a
 * tab has that tab turned into the two characters `\t`, so the cell starts with
 * text a spreadsheet will not evaluate, and one that arrives with `=` first is
 * caught by the prefix check.
 */
function csvCell(value: string): string {
  const neutralized = neutralizeFormulaPrefix(value);

  return /[",\r\n]/u.test(neutralized) ? `"${neutralized.replace(/"/gu, '""')}"` : neutralized;
}

/**
 * Encodes one entry as a JSON document.
 *
 * Values go out verbatim: JSON's own escapes cover the characters that would
 * break the line structure, and an audit export that silently rewrites what was
 * recorded is worth less than one that cannot be opened.
 */
function jsonlRow(entry: AuditLogEntry): string {
  return JSON.stringify({
    sequence: entry.sequence,
    action: entry.action,
    actorId: entry.actorId ?? null,
    subjectId: entry.subjectId ?? null,
    occurredAt: entry.occurredAt.toISOString(),
    metadata: entry.metadata,
    previousHash: entry.previousHash,
    hash: entry.hash,
  };
}

function toCsvRow(entry: AuditLogEntry): string {
  const fields = [
    String(entry.sequence),
    String(entry.id),
    entry.action,
    entry.actorId ?? "",
    entry.subjectId ?? "",
    entry.occurredAt.toISOString(),
    JSON.stringify(entry.metadata),
    entry.previousHash,
    entry.hash,
  ];

  return fields.map(escapeCsvField).join(",");
}

/**
 * RFC 4180 field escaping: wrap in double quotes and double any quotes
 * inside when the value contains a delimiter, quote or line break; leave it
 * bare otherwise.
 */
export function escapeCsvField(value: string): string {
  if (value.includes('"') || value.includes(",") || value.includes("\n") || value.includes("\r")) {
    return `"${value.replace(/"/g, '""')}"`;
  }

  return value;
    previousHash: entry.previousHash,
    hash: entry.hash,
    metadata: { ...entry.metadata },
  });
}
