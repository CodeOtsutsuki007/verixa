import { Result } from "@verixa/shared-kernel";
import { describe, expect, it, vi } from "vitest";

import { AuditLogEntry, type AuditAction } from "../../domain/entities/audit-log-entry.js";
import { InMemoryAuditLogRepository } from "../../infrastructure/testing/in-memory-audit-repositories.js";
import type { AuditLogRepository, FindWithFiltersParams } from "../ports/audit-log-repository.js";

import {
  ExportAuditEvents,
  escapeCsvField,
  type ExportAuditEventsFormat,
} from "./export-audit-events.js";

interface EntryOverrides {
  readonly action?: AuditAction;
  readonly actorId?: string;
  readonly subjectId?: string;
  readonly metadata?: Readonly<Record<string, string>>;
  readonly occurredAt?: Date;
}

function makeEntry(
  previous: AuditLogEntry | undefined,
  overrides: EntryOverrides = {},
): AuditLogEntry {
  return AuditLogEntry.append({
    action: overrides.action ?? "user.login_succeeded",
    actorId: overrides.actorId,
    subjectId: overrides.subjectId,
    metadata: overrides.metadata ?? {},
    occurredAt: overrides.occurredAt ?? new Date("2026-01-01T00:00:00.000Z"),
    previous,
  });
}

async function seed(
  repository: InMemoryAuditLogRepository,
  count: number,
  overrides: (index: number) => EntryOverrides = () => ({}),
): Promise<AuditLogEntry[]> {
  const entries: AuditLogEntry[] = [];
  let previous: AuditLogEntry | undefined;

  for (let index = 0; index < count; index += 1) {
    previous = makeEntry(previous, overrides(index));
    await repository.append(previous);
    entries.push(previous);
  }

  return entries;
}

async function collect(iterable: AsyncIterable<string>): Promise<string> {
  let output = "";
  for await (const chunk of iterable) {
    output += chunk;
  }
  return output;
}

/** Minimal RFC 4180 reader, sufficient to prove the writer round-trips. */
function parseCsv(input: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;

  for (let index = 0; index < input.length; index += 1) {
    const char = input.charAt(index);

    if (inQuotes) {
      if (char === '"') {
        if (input.charAt(index + 1) === '"') {
          field += '"';
          index += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += char;
import { beforeEach, describe, expect, it } from "vitest";

import { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";
import { AUDIT_PERMISSIONS, type AuditReader } from "../../domain/policies/audit-access-policy.js";
import {
  InMemoryAuditEventReader,
  InMemoryAuditLogRepository,
} from "../../infrastructure/testing/in-memory-audit-repositories.js";
import { AuditReadNotRecordedError } from "../audit-read-access.js";

import { ExportAuditEvents } from "./export-audit-events.js";
import { RecordAuditEvent } from "./record-audit-event.js";

const exporter: AuditReader = {
  actorId: "auditor-1",
  organizationId: "org-a",
  permissions: new Set([AUDIT_PERMISSIONS.export]),
};

async function collect(stream: AsyncIterable<AuditLogEntry>): Promise<AuditLogEntry[]> {
  const collected: AuditLogEntry[] = [];
  for await (const entry of stream) collected.push(entry);
  return collected;
}

class UnavailableAuditLogRepository extends InMemoryAuditLogRepository {
  override append(): Promise<void> {
    return Promise.reject(new Error("connection refused"));
  }
}

describe("ExportAuditEvents", () => {
  let auditLog: InMemoryAuditLogRepository;
  let events: InMemoryAuditEventReader;
  let exportAuditEvents: ExportAuditEvents;

  beforeEach(() => {
    auditLog = new InMemoryAuditLogRepository();
    events = new InMemoryAuditEventReader();
    exportAuditEvents = new ExportAuditEvents(events, new RecordAuditEvent(auditLog));
  });

  it("streams the reader's own organization's entries", async () => {
    const first = AuditLogEntry.append({ action: "user.registered", actorId: "user-1" });
    const second = AuditLogEntry.append({ action: "user.login_failed", previous: first });
    events.seed("org-a", first, second);
    events.seed("org-b", AuditLogEntry.append({ action: "user.registered" }));

    const result = await exportAuditEvents.execute({ reader: exporter, organizationId: "org-a" });

    if (!Result.isOk(result)) throw new Error("expected the export to be authorized");
    await expect(collect(result.value)).resolves.toEqual([first, second]);
  });

  it("records a successful export as an audit event before any entry is released", async () => {
    events.seed("org-a", AuditLogEntry.append({ action: "user.registered" }));

    const result = await exportAuditEvents.execute({
      reader: exporter,
      organizationId: "org-a",
      subjectId: "user-7",
    });

    // Nothing has been consumed from the stream yet, and the record already
    // exists: an export abandoned after the first row still leaves a trace.
    expect(Result.isOk(result)).toBe(true);
    const [recorded] = auditLog.all();
    expect(recorded?.action).toBe("audit.exported");
    expect(recorded?.actorId).toBe("auditor-1");
    expect(recorded?.subjectId).toBe("org-a");
    expect(recorded?.metadata).toEqual({ organizationId: "org-a", "filter.subjectId": "user-7" });
  });

  it("rejects a cross-organization export and records the attempt", async () => {
    events.seed("org-b", AuditLogEntry.append({ action: "user.registered" }));

    const result = await exportAuditEvents.execute({ reader: exporter, organizationId: "org-b" });

    expect(Result.isErr(result) && result.error.code).toBe("AUDIT_ACCESS_DENIED");
    expect(auditLog.all().map((entry) => entry.action)).toEqual(["audit.access_denied"]);
    expect(auditLog.all()[0]?.metadata).toMatchObject({
      operation: "export",
      reason: "cross_organization",
    });
  });

  it("rejects a reader who may query but not export", async () => {
    const result = await exportAuditEvents.execute({
      reader: { ...exporter, permissions: new Set([AUDIT_PERMISSIONS.query]) },
      organizationId: "org-a",
    });

    expect(Result.isErr(result) && result.error.code).toBe("AUDIT_ACCESS_DENIED");
    expect(auditLog.all().map((entry) => entry.action)).toEqual(["audit.access_denied"]);
  });

  it("does not hand out a stream when the export cannot be recorded", async () => {
    const unrecorded = new ExportAuditEvents(
      events,
      new RecordAuditEvent(new UnavailableAuditLogRepository()),
    );

    const result = await unrecorded.execute({ reader: exporter, organizationId: "org-a" });

    expect(Result.isErr(result) && result.error).toBeInstanceOf(AuditReadNotRecordedError);
import { describe, expect, it } from "vitest";

import { AuditLogEntry, verifyChain } from "../../domain/entities/audit-log-entry.js";
import {
  METADATA_REJECTED_KEY,
  neutralizeFormulaPrefix,
} from "../../domain/value-objects/audit-metadata.js";
import { InMemoryAuditLogRepository } from "../../infrastructure/testing/in-memory-audit-repositories.js";

import { AUDIT_EXPORT_HEADER, ExportAuditEvents } from "./export-audit-events.js";
import type { AuditExportLogger } from "./export-audit-events.js";
import { QueryAuditEvents } from "./query-audit-events.js";
import { RecordAuditEvent } from "./record-audit-event.js";

/**
 * The payloads this file exists to defeat.
 *
 * Each is a value an attacker could place in a request field that eventually
 * reaches audit metadata: a forged log line, a fabricated CSV row, a spreadsheet
 * formula, and a hash pre-image boundary shift.
 */
const PAYLOADS = {
  forgedLogLine: "failed password\n[2026-10-02T00:00:00.000Z] INFO audit: admin login granted",
  fabricatedRow: 'normal,"injected",row\r\nsecond,physical,line',
  formula: "=cmd|'/c calc'!A1",
  arithmeticFormula: "-2+3+4",
  boundaryShift: "a;b=c\nd",
  tabSeparated: '\t\t=HYPERLINK("http://example.invalid")',
  controlChars: "value\u007fwith\u0085control\u0000chars",
  // Not ASCII control characters, and not escaped by JSON.stringify, but line
  // endings to `str.splitlines` in Python — the reader an auditor brings.
  lineSeparators: "a\u0085b\u2028c\u2029d",
  unicode: "café 👍 日本語",
} as const;

const ALL_PAYLOADS: Record<string, string> = { ...PAYLOADS };

function captureLogger(): { logger: AuditExportLogger; records: Record<string, unknown>[] } {
  const records: Record<string, unknown>[] = [];

  return {
    logger: {
      info: (fields) => {
        records.push({ ...fields });
      },
    },
    records,
  };
}

/**
 * An independent RFC 4180 reader.
 *
 * Deliberately not shared with the writer. A test that decodes its own encoder
 * using that encoder's assumptions proves only that the two agree with
 * themselves; what matters is that an ordinary parser sees the rows the export
 * intended.
 */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  let started = false;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];

    if (quoted) {
      if (character === '"') {
        if (text[index + 1] === '"') {
          cell += '"';
          index += 1;
        } else {
          quoted = false;
        }
      } else {
        cell += character;
      }
      continue;
    }

    if (char === '"') {
      inQuotes = true;
    } else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n") {
      row.push(field);
      field = "";
      rows.push(row);
      row = [];
    } else if (char !== "\r") {
      field += char;
    }
  }

  if (field !== "" || row.length > 0) {
    row.push(field);
    started = true;

    if (character === '"') {
      quoted = true;
    } else if (character === ",") {
      row.push(cell);
      cell = "";
    } else if (character === "\n") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
      started = false;
    } else if (character !== "\r") {
      cell += character;
    }
  }

  if (started) {
    row.push(cell);
    rows.push(row);
  }

  return rows;
}

function execute(
  useCase: ExportAuditEvents,
  command: {
    format: ExportAuditEventsFormat;
    batchSize?: number;
    filters?: FindWithFiltersParams["filters"];
  },
): AsyncIterable<string> {
  const result = useCase.execute(command);
  if (Result.isErr(result)) throw new Error(`expected ok, got ${result.error.message}`);
  return result.value;
}

/**
 * A repository that never runs out of entries. If the export buffered the
 * whole log before yielding, consuming it would hang forever — which is
 * exactly the property the streaming design must rule out.
 */
class EndlessAuditLogRepository implements AuditLogRepository {
  calls = 0;

  findLatest(): Promise<AuditLogEntry | undefined> {
    return Promise.resolve(undefined);
  }

  append(): Promise<void> {
    return Promise.resolve();
  }

  findFrom(): Promise<readonly AuditLogEntry[]> {
    return Promise.resolve([]);
  }

  findWithFilters(params: FindWithFiltersParams): Promise<readonly AuditLogEntry[]> {
    this.calls += 1;
    const page = Array.from({ length: params.limit }, (_unused, offset) =>
      makeEntry(undefined, { actorId: `actor-${String(params.fromSequence + offset)}` }),
    );
    return Promise.resolve(page);
  }

  count(): Promise<number> {
    return Promise.resolve(Number.MAX_SAFE_INTEGER);
  }
}

describe("ExportAuditEvents", () => {
  describe("validation", () => {
    it("rejects an unsupported format without touching the repository", () => {
      const repository = new InMemoryAuditLogRepository();
      const result = new ExportAuditEvents(repository).execute({
        format: "xml" as ExportAuditEventsFormat,
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.code).toBe("VALIDATION_ERROR");
      }
    });

    it.each([0, -1, 1.5])("rejects a non-positive batchSize (%s)", (batchSize) => {
      const result = new ExportAuditEvents(new InMemoryAuditLogRepository()).execute({
        format: "csv",
        batchSize,
      });

      expect(Result.isErr(result)).toBe(true);
    });
  });

  describe("CSV", () => {
    it("writes a header followed by one row per entry", async () => {
      const repository = new InMemoryAuditLogRepository();
      const entries = await seed(repository, 2, (index) => ({
        actorId: `actor-${String(index)}`,
        subjectId: `subject-${String(index)}`,
      }));

      const csv = await collect(execute(new ExportAuditEvents(repository), { format: "csv" }));
      const rows = parseCsv(csv);

      expect(rows[0]).toEqual([
        "sequence",
        "id",
        "action",
        "actorId",
        "subjectId",
        "occurredAt",
        "metadata",
        "previousHash",
        "hash",
      ]);
      expect(rows).toHaveLength(3);
      expect(rows[1]![0]).toBe("1");
      expect(rows[1]![1]).toBe(String(entries[0]!.id));
      expect(rows[1]![2]).toBe("user.login_succeeded");
      expect(rows[1]![3]).toBe("actor-0");
      expect(rows[1]![5]).toBe("2026-01-01T00:00:00.000Z");
      expect(rows[1]![8]).toBe(entries[0]!.hash);
    });

    it("round-trips metadata containing delimiters, quotes and newlines", async () => {
      const repository = new InMemoryAuditLogRepository();
      const metadata = {
        note: 'a,b"c\nd',
        quote: 'say "hi"',
        carriage: "line\rbreak",
        plain: "ok",
      };
      await seed(repository, 1, () => ({ metadata }));

      const csv = await collect(execute(new ExportAuditEvents(repository), { format: "csv" }));
      const rows = parseCsv(csv);

      expect(rows).toHaveLength(2);
      expect(JSON.parse(rows[1]![6]!)).toEqual(metadata);
    });
  });

  describe("JSON", () => {
    it("writes newline-delimited JSON, one valid object per line", async () => {
      const repository = new InMemoryAuditLogRepository();
      const entries = await seed(repository, 2, (index) => ({
        metadata: { index: String(index) },
      }));

      const json = await collect(execute(new ExportAuditEvents(repository), { format: "json" }));
      const lines = json.split("\n").filter((line) => line.length > 0);

      expect(lines).toHaveLength(2);
      expect(lines[0]![0]).toBe("{");

      const first = JSON.parse(lines[0]!) as Record<string, unknown>;
      expect(first["sequence"]).toBe(1);
      expect(first["id"]).toBe(String(entries[0]!.id));
      expect(first["action"]).toBe("user.login_succeeded");
      expect(first["metadata"]).toEqual({ index: "0" });
      expect(first["occurredAt"]).toBe("2026-01-01T00:00:00.000Z");
    });

    it("represents an absent actor as null rather than dropping the field", async () => {
      const repository = new InMemoryAuditLogRepository();
      await seed(repository, 1);

      const json = await collect(execute(new ExportAuditEvents(repository), { format: "json" }));
      const record = JSON.parse(json.trim()) as Record<string, unknown>;

      expect(record["actorId"]).toBeNull();
      expect(record["subjectId"]).toBeNull();
    });
  });

  describe("filtering", () => {
    it("reuses the query filters so an export mirrors the in-app query", async () => {
      const repository = new InMemoryAuditLogRepository();
      await seed(repository, 3, (index) => ({
        actorId: index === 1 ? "bob" : "alice",
        action: index === 0 ? "user.login_succeeded" : "user.login_failed",
        occurredAt: new Date(`2026-01-0${String(index + 1)}T00:00:00.000Z`),
      }));

      const byActor = await collect(
        execute(new ExportAuditEvents(repository), {
          format: "csv",
          filters: { actorId: "alice" },
        }),
      );
      expect(parseCsv(byActor)).toHaveLength(3);

      const byDate = await collect(
        execute(new ExportAuditEvents(repository), {
          format: "json",
          filters: { fromDate: new Date("2026-01-02T00:00:00.000Z") },
        }),
      );
      expect(byDate.split("\n").filter((line) => line.length > 0)).toHaveLength(2);
    });
  });

  describe("streaming", () => {
    it("yields the first row without draining the rest of the log", async () => {
      const repository = new EndlessAuditLogRepository();
      const stream = execute(new ExportAuditEvents(repository), { format: "csv", batchSize: 10 })[
        Symbol.asyncIterator
      ]();

      const header = await stream.next();
      expect(repository.calls).toBe(0);
      expect(header.value).toContain("sequence");

      const timeout = new Promise<never>((_resolve, reject) => {
        setTimeout(() => {
          reject(new Error("export buffered an endless log before yielding"));
        }, 1_000);
      });

      const first = await Promise.race([stream.next(), timeout]);
      expect(repository.calls).toBe(1);
      expect(first.value).toContain("actor-1");

      await stream.return?.(undefined);
    });

    it("pages through a large log in bounded batches", async () => {
      const repository = new InMemoryAuditLogRepository();
      const total = 1_000;
      await seed(repository, total);
      const spy = vi.spyOn(repository, "findWithFilters");

      const json = await collect(
        execute(new ExportAuditEvents(repository), { format: "json", batchSize: 100 }),
      );

      expect(json.split("\n").filter((line) => line.length > 0)).toHaveLength(total);

      const batchSizes = spy.mock.calls.map(([params]) => params.limit);
      expect(Math.max(...batchSizes)).toBe(100);
      expect(spy).toHaveBeenCalledTimes(total / 100 + 1);
    });
  });
});

describe("escapeCsvField", () => {
  it("leaves an ordinary value untouched", () => {
    expect(escapeCsvField("plain")).toBe("plain");
  });

  it.each([
    ["a,b", '"a,b"'],
    ['a"b', '"a""b"'],
    ["a\nb", '"a\nb"'],
    ["a\rb", '"a\rb"'],
  ])("quotes and escapes %j", (value, expected) => {
    expect(escapeCsvField(value)).toBe(expected);
async function logWith(...bags: Readonly<Record<string, string>>[]): Promise<{
  repository: InMemoryAuditLogRepository;
  entries: AuditLogEntry[];
}> {
  const repository = new InMemoryAuditLogRepository();
  const record = new RecordAuditEvent(repository);
  const entries: AuditLogEntry[] = [];

  for (const metadata of bags) {
    const entry = await record.execute({
      action: "user.login_failed",
      actorId: "actor-1",
      subjectId: "subject-1",
      metadata,
    });

    if (entry !== undefined) entries.push(entry);
  }

  return { repository, entries };
}

describe("ExportAuditEvents", () => {
  it("writes exactly one CSV line per entry, whatever the entries contain", async () => {
    const { repository } = await logWith(ALL_PAYLOADS, { reason: PAYLOADS.forgedLogLine }, {});

    const result = await new ExportAuditEvents(repository).execute({ format: "csv" });

    expect(result.recordCount).toBe(3);
    expect(result.truncated).toBe(false);
    // `split` on the raw newline is the counter an auditor would use, so it is
    // the counter this test uses: header, three rows, one trailing fragment.
    const physicalLines = result.body.split("\n");
    expect(physicalLines).toHaveLength(5);
    expect(physicalLines[4]).toBe("");
    expect(physicalLines.slice(0, 4).every((line) => line.endsWith("\r"))).toBe(true);
    // The terminators JSON does not escape are counted as line endings by some
    // readers, so they cannot appear raw either.
    expect(result.body).not.toMatch(/[\u0085\u2028\u2029]/u);

    const rows = parseCsv(result.body);
    expect(rows[0]).toEqual(AUDIT_EXPORT_HEADER.split(","));
    expect(rows.slice(1)).toHaveLength(3);
    for (const row of rows.slice(1)) {
      expect(row).toHaveLength(8);
    }
  });

  it("keeps a quoted comma and quote inside a cell as content", async () => {
    const { repository } = await logWith(
      { note: 'a,b "c", d' },
      { note: PAYLOADS.fabricatedRow },
      { note: "back\\slash and \n newline" },
    );

    const result = await new ExportAuditEvents(repository).execute({ format: "csv" });
    const cells = parseCsv(result.body)
      .slice(1)
      .map((row) => row[7]);

    // The metadata column is a JSON document, so a reader that parses it gets
    // the recorded values back unchanged — including the line breaks, which
    // travel as JSON's own two-character escapes rather than as raw newlines.
    expect(JSON.parse(cells[0] ?? "{}")).toEqual({ note: 'a,b "c", d' });
    expect(JSON.parse(cells[1] ?? "{}")).toEqual({ note: PAYLOADS.fabricatedRow });
    expect(JSON.parse(cells[2] ?? "{}")).toEqual({ note: "back\\slash and \n newline" });
  });

  it("never emits a cell a spreadsheet would evaluate", async () => {
    const { repository } = await logWith(...Object.values(PAYLOADS).map((attack) => ({ attack })));

    const result = await new ExportAuditEvents(repository).execute({ format: "csv" });
    const cells = parseCsv(result.body).slice(1).flat();

    expect(cells.length).toBe(Object.keys(PAYLOADS).length * 8);
    for (const cell of cells) {
      expect(/^[=+\-@]/u.test(cell)).toBe(false);
    }
  });

  it("exports JSON lines whose metadata is the metadata that was recorded", async () => {
    const { repository, entries } = await logWith(ALL_PAYLOADS);

    const result = await new ExportAuditEvents(repository).execute({ format: "jsonl" });
    const lines = result.body.trimEnd().split("\n");
    const parsed = lines.map((line) => JSON.parse(line) as { metadata: Record<string, string> });

    expect(lines).toHaveLength(1);
    // Verbatim. JSON escapes what it encodes, so nothing has to be rewritten to
    // keep a value inside its own line.
    expect(parsed[0]?.metadata).toEqual(entries[0]?.metadata);
    expect(parsed[0]?.metadata.controlChars).toBe(PAYLOADS.controlChars);
    expect(parsed[0]?.metadata.unicode).toBe(PAYLOADS.unicode);
  });

  it("exports the hashes an auditor needs to re-verify the chain", async () => {
    const { repository, entries } = await logWith(
      ...Object.values(PAYLOADS).map((attack) => ({ attack })),
    );

    const result = await new ExportAuditEvents(repository).execute({ format: "jsonl" });
    const exported = result.body
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line) as { hash: string; sequence: number });

    expect(exported.map((entry) => entry.hash)).toEqual(entries.map((entry) => entry.hash));
    expect(verifyChain(repository.all())).toBeUndefined();
    expect(entries.every((entry) => entry.hasValidHash)).toBe(true);
  });

  it("paginates through a log larger than one page", async () => {
    const repository = new InMemoryAuditLogRepository();
    const record = new RecordAuditEvent(repository);

    for (let index = 0; index < 600; index += 1) {
      await record.execute({
        action: "user.login_failed",
        actorId: "actor-1",
        metadata: { index: String(index) },
      });
    }

    const result = await new ExportAuditEvents(repository).execute({ format: "jsonl" });

    expect(result.recordCount).toBe(600);
    expect(result.truncated).toBe(false);
    expect(result.body.trimEnd().split("\n")[599]).toContain('"index":"599"');
  });

  it("says so when a cap cut the export short", async () => {
    const { repository } = await logWith(
      ...Array.from({ length: 10 }, (_unused, index) => ({ index: String(index) })),
    );

    const capped = await new ExportAuditEvents(repository).execute({
      format: "csv",
      maxRecords: 4,
    });

    expect(capped.recordCount).toBe(4);
    expect(capped.truncated).toBe(true);
    expect(parseCsv(capped.body).slice(1)).toHaveLength(4);

    const exact = await new ExportAuditEvents(repository).execute({
      format: "csv",
      maxRecords: 10,
    });
    // Exactly at the cap is not truncation: nothing was left behind.
    expect(exact.recordCount).toBe(10);
    expect(exact.truncated).toBe(false);
  });

  it("honours the filters it was given", async () => {
    const repository = new InMemoryAuditLogRepository();
    const record = new RecordAuditEvent(repository);

    for (const actorId of ["target", "other"]) {
      await record.execute({ action: "user.login_failed", actorId, metadata: {} });
    }

    const result = await new ExportAuditEvents(repository).execute({
      format: "jsonl",
      filters: { actorId: "target" },
    });

    expect(result.recordCount).toBe(1);
    expect(result.body).toContain('"actorId":"target"');
    expect(result.body).not.toContain("other");
  });

  it("writes a header row for an empty log", async () => {
    const result = await new ExportAuditEvents(new InMemoryAuditLogRepository()).execute({
      format: "csv",
    });

    expect(result.body).toBe(`${AUDIT_EXPORT_HEADER}\r\n`);
    expect(result.recordCount).toBe(0);
    expect(result.truncated).toBe(false);
  });

  it("logs the export as structured fields rather than as a sentence", async () => {
    const { logger, records } = captureLogger();
    const { repository } = await logWith({ reason: "ok" });

    const forged = "actor\n[2026-10-02] INFO audit: forged";
    const result = await new ExportAuditEvents(repository, logger).execute({
      format: "csv",
      filters: { actorId: forged },
    });

    // The forged filter matches nothing, which is the right outcome and also
    // what makes the next assertion meaningful: the value reached the log.
    expect(result.recordCount).toBe(0);
    expect(records).toHaveLength(1);
    const record = records[0] ?? {};
    expect(record.type).toBe("audit.log.exported");
    expect(record.format).toBe("csv");
    expect(record.truncated).toBe(false);

    // The filter came from whoever asked for the export, and it is the one place
    // in this path where an attacker picks the log content. It travels as a
    // field, with its newline reduced to two characters, so it cannot start a
    // record of its own — and the document still parses back to what was sent.
    const filters = String(record.filters);
    expect(filters).not.toContain("\n");
    expect(filters).toContain("\\n");
    expect(JSON.parse(filters)).toEqual({ actorId: forged });
  });

  it("records an over-large metadata bag instead of dropping the entry", async () => {
    const repository = new InMemoryAuditLogRepository();
    const failures: unknown[] = [];
    const record = new RecordAuditEvent(repository, (error) => {
      failures.push(error);
    });

    const entry = await record.execute({
      action: "user.login_failed",
      actorId: "actor-1",
      metadata: { note: "x".repeat(2000) },
    });

    expect(entry).toBeDefined();
    expect(failures).toHaveLength(0);
    expect(entry?.metadata).toEqual({ [METADATA_REJECTED_KEY]: "value_too_long" });
    expect(entry?.hasValidHash).toBe(true);

    const result = await new ExportAuditEvents(repository).execute({ format: "jsonl" });
    expect(result.recordCount).toBe(1);
  });

  it("agrees with the query view of the same log", async () => {
    const { repository, entries } = await logWith(
      { reason: PAYLOADS.boundaryShift },
      { reason: PAYLOADS.tabSeparated },
    );

    const page = await new QueryAuditEvents(repository).execute({ limit: 50 });
    const exported = await new ExportAuditEvents(repository).execute({ format: "jsonl" });
    const hashes = exported.body
      .trimEnd()
      .split("\n")
      .map((line) => (JSON.parse(line) as { hash: string }).hash);

    expect(page.entries.map((entry) => entry.hash)).toEqual(hashes);
    expect(page.entries).toHaveLength(entries.length);
  });

  it("neutralizes a formula only where a formula would be evaluated", async () => {
    // Guards the boundary between the two encoders. A CSV *cell* that begins
    // `-2+3+4` is a formula to Excel and gets the marker prefix; the same value
    // inside a JSON document in another cell is data, and rewriting it there
    // would corrupt the record for no benefit.
    const repository = new InMemoryAuditLogRepository();
    await new RecordAuditEvent(repository).execute({
      action: "user.login_failed",
      actorId: PAYLOADS.arithmeticFormula,
      metadata: { delta: PAYLOADS.arithmeticFormula },
    });

    const csv = await new ExportAuditEvents(repository).execute({ format: "csv" });
    const jsonl = await new ExportAuditEvents(repository).execute({ format: "jsonl" });

    const row = parseCsv(csv.body)[1] ?? [];
    expect(row[2]).toBe(`'${PAYLOADS.arithmeticFormula}`);
    expect(JSON.parse(row[7] ?? "{}")).toEqual({ delta: PAYLOADS.arithmeticFormula });
    expect(JSON.parse(jsonl.body.trimEnd())).toMatchObject({
      actorId: PAYLOADS.arithmeticFormula,
      metadata: { delta: PAYLOADS.arithmeticFormula },
    });
    expect(neutralizeFormulaPrefix(PAYLOADS.arithmeticFormula)).toBe(
      `'${PAYLOADS.arithmeticFormula}`,
    );
  });
});
