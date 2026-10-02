import { asId } from "@verixa/shared-kernel";

import type {
  AnchorRecord,
  AnchorRecordRepository,
  AuditLogRepository,
  FindWithFiltersParams,
} from "../../application/ports/audit-log-repository.js";
import { type AuditAction, AuditLogEntry } from "../../domain/entities/audit-log-entry.js";

/**
 * What comes *out* of the database.
 *
 * `metadata` is `unknown` because a `Json` column can hold anything — the
 * shape is a convention this code maintains, not one Postgres enforces.
 * Treating it as already-correct on read is how a hand-edited row becomes a
 * crash inside the verification routine, at the exact moment verification is
 * what you are relying on.
 */
interface AuditRow {
  id: string;
  sequence: number;
  action: string;
  actorId: string | null;
  subjectId: string | null;
  metadata: unknown;
  occurredAt: Date;
  previousHash: string;
  hash: string;
}

/**
 * What goes *in*. Distinct from {@link AuditRow} only in `metadata`, which
 * must be a concrete JSON value rather than `unknown` — the read and write
 * directions genuinely differ here, and collapsing them would mean casting.
 */
interface AuditRowInput extends Omit<AuditRow, "metadata"> {
  metadata: Record<string, string>;
}

interface AnchorRow {
  id: string;
  sequence: number;
  chainHash: string;
  anchorRef: string;
  network: string;
  anchoredAt: Date;
}

/**
 * The slice of the Prisma client these repositories need.
 *
 * Structural, so a transaction client satisfies it as readily as the root
 * one — the same convention every other repository here follows.
 */
interface AuditDelegate {
  findFirst(args: { orderBy: { sequence: "desc" } }): Promise<AuditRow | null>;
  findMany(args: {
    where?: {
      sequence?: { gte: number };
      actorId?: string;
      subjectId?: string;
      action?: string;
      occurredAt?: { gte?: Date; lte?: Date };
      metadata?: { path: string[]; equals: string };
    };
    orderBy: { sequence: "asc" | "desc" };
    take: number;
  }): Promise<AuditRow[]>;
  create(args: { data: AuditRowInput }): Promise<AuditRow>;
  count(): Promise<number>;
}

interface AnchorDelegate {
  findFirst(args: { orderBy: { sequence: "desc" } }): Promise<AnchorRow | null>;
  findMany(args: { orderBy: { sequence: "desc" }; take: number }): Promise<AnchorRow[]>;
  create(args: { data: AnchorRow }): Promise<AnchorRow>;
}

/**
 * Reads `metadata` back as the flat string map the domain expects.
 *
 * `Json` comes out of Prisma as `unknown`, and the hash was computed over a
 * specific shape. Coercing defensively rather than casting means a row
 * corrupted by hand produces an entry whose hash does not verify — which is
 * exactly what should happen — instead of a runtime crash during
 * verification, when verification is the thing being relied upon.
 */
function toMetadata(value: unknown): Readonly<Record<string, string>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return {};
  }

  const result: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === "string") {
      result[key] = entry;
    }
  }
  return result;
}

/** Maps between audit rows and the domain entity. */
export const AuditLogEntryMapper = {
  toDomain(row: AuditRow): AuditLogEntry {
    return AuditLogEntry.reconstitute({
      id: asId<"AuditLogEntryId">(row.id),
      sequence: row.sequence,
      action: row.action as AuditAction,
      actorId: row.actorId ?? undefined,
      subjectId: row.subjectId ?? undefined,
      metadata: toMetadata(row.metadata),
      occurredAt: row.occurredAt,
      previousHash: row.previousHash,
      hash: row.hash,
    });
  },

  toRow(entry: AuditLogEntry): AuditRowInput {
    return {
      id: entry.id,
      sequence: entry.sequence,
      action: entry.action,
      actorId: entry.actorId ?? null,
      subjectId: entry.subjectId ?? null,
      metadata: { ...entry.metadata },
      occurredAt: entry.occurredAt,
      previousHash: entry.previousHash,
      hash: entry.hash,
    };
  },
};

/** Prisma-backed, append-only `AuditLogRepository`. */
export class PrismaAuditLogRepository implements AuditLogRepository {
  constructor(private readonly entries: AuditDelegate) {}

  async findLatest(): Promise<AuditLogEntry | undefined> {
    const row = await this.entries.findFirst({ orderBy: { sequence: "desc" } });
    return row === null ? undefined : AuditLogEntryMapper.toDomain(row);
  }

  async append(entry: AuditLogEntry): Promise<void> {
    // `create`, never `upsert`. An upsert would quietly overwrite an existing
    // entry at the same sequence, which is the one operation this table must
    // not permit — the unique index exists so a concurrent append *fails*, and
    // reaching for upsert to make that failure go away would remove the
    // guarantee rather than handle the race.
    await this.entries.create({ data: AuditLogEntryMapper.toRow(entry) });
  }

  async findFrom(fromSequence: number, limit: number): Promise<readonly AuditLogEntry[]> {
    const rows = await this.entries.findMany({
      where: { sequence: { gte: fromSequence } },
      orderBy: { sequence: "asc" },
      take: limit,
    });
    return rows.map((row) => AuditLogEntryMapper.toDomain(row));
  }

  async findWithFilters(params: FindWithFiltersParams): Promise<readonly AuditLogEntry[]> {
    const where: {
      sequence?: { gte: number };
      actorId?: string;
      subjectId?: string;
      action?: string;
      occurredAt?: { gte?: Date; lte?: Date };
      metadata?: { path: string[]; equals: string };
    } = {
      sequence: { gte: params.fromSequence },
    };

    if (params.filters.actorId) {
      where.actorId = params.filters.actorId;
    }

    if (params.filters.subjectId) {
      where.subjectId = params.filters.subjectId;
    }

    if (params.filters.action) {
      where.action = params.filters.action;
    }

    if (params.filters.organizationId) {
      // organizationId is stored in metadata as a JSON field
      where.metadata = { path: ["organizationId"], equals: params.filters.organizationId };
    }

    if (params.filters.fromDate || params.filters.toDate) {
      where.occurredAt = {};
      if (params.filters.fromDate) {
        where.occurredAt.gte = params.filters.fromDate;
      }
      if (params.filters.toDate) {
        where.occurredAt.lte = params.filters.toDate;
      }
    }

    const rows = await this.entries.findMany({
      where,
      orderBy: { sequence: "asc" },
      take: params.limit,
    });

    return rows.map((row) => AuditLogEntryMapper.toDomain(row));
  }

  count(): Promise<number> {
    return this.entries.count();
  }
}

/** Prisma-backed `AnchorRecordRepository`. */
export class PrismaAnchorRecordRepository implements AnchorRecordRepository {
  constructor(
    private readonly records: AnchorDelegate,
    private readonly generateId: () => string,
  ) {}

  async save(record: AnchorRecord): Promise<void> {
    await this.records.create({ data: { id: this.generateId(), ...record } });
  }

  async findLatest(): Promise<AnchorRecord | undefined> {
    const row = await this.records.findFirst({ orderBy: { sequence: "desc" } });
    return row === null ? undefined : toAnchorRecord(row);
  }

  async findAll(limit: number): Promise<readonly AnchorRecord[]> {
    const rows = await this.records.findMany({ orderBy: { sequence: "desc" }, take: limit });
    return rows.map(toAnchorRecord);
  }
}

function toAnchorRecord(row: AnchorRow): AnchorRecord {
  return {
    sequence: row.sequence,
    chainHash: row.chainHash,
    anchorRef: row.anchorRef,
    network: row.network,
    anchoredAt: row.anchoredAt,
  };
}
