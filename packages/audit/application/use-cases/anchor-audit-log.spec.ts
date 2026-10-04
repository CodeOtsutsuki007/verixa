import { Result, ValidationError } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";
import {
  InMemoryAnchorRecordRepository,
  InMemoryAuditLogRepository,
} from "../../infrastructure/testing/in-memory-audit-repositories.js";
import type {
  AnchorReceiptLike,
  AnchorRecordRepository,
  HashAnchorPort,
} from "../ports/audit-log-repository.js";

import { AnchorAuditLog } from "./anchor-audit-log.js";

/** Appends `count` honest entries after whatever the log already holds. */
async function seed(repository: InMemoryAuditLogRepository, count: number): Promise<AuditLogEntry> {
  let previous = await repository.findLatest();
  for (let index = 0; index < count; index += 1) {
    const entry = AuditLogEntry.append({
      action: "user.login_succeeded",
      actorId: "user-1",
      previous,
      occurredAt: new Date(1_700_000_000_000 + (previous?.sequence ?? 0) * 1000),
    });
    await repository.append(entry);
    previous = entry;
  }
  return previous!;
}

/**
 * Ledger stand-in that records what it was asked to anchor. Anchoring is the
 * half of this use case that has an external side effect and a cost, so the
 * tests need to be able to say "and nothing was submitted".
 */
class FakeHashAnchor implements HashAnchorPort {
  readonly anchored: string[] = [];

  constructor(private readonly outcome: "ok" | "unreachable" = "ok") {}

  anchor(hash: string): Promise<Result<AnchorReceiptLike, { message: string }>> {
    if (this.outcome === "unreachable") {
      return Promise.resolve(Result.err({ message: "Horizon is unreachable" }));
    }
    this.anchored.push(hash);
    return Promise.resolve(
      Result.ok({
        hash,
        anchorRef: `tx-${hash.slice(0, 8)}`,
        anchoredAt: new Date(1_700_001_000_000),
        network: "stellar:testnet",
      }),
    );
  }
}

function underTest(
  auditLog: InMemoryAuditLogRepository,
  anchors: InMemoryAnchorRecordRepository,
  hashAnchor: HashAnchorPort,
): AnchorAuditLog {
  return new AnchorAuditLog(auditLog, anchors, hashAnchor);
}

describe("AnchorAuditLog", () => {
  it("commits the current head and stores the receipt", async () => {
    const auditLog = new InMemoryAuditLogRepository();
    const anchors = new InMemoryAnchorRecordRepository();
    const head = await seed(auditLog, 3);
    const ledger = new FakeHashAnchor();

    const result = await underTest(auditLog, anchors, ledger).execute();

    if (Result.isErr(result)) throw new Error(result.error.message);
    expect(ledger.anchored).toEqual([head.hash]);
    expect(result.value.record).toEqual({
      sequence: 3,
      chainHash: head.hash,
      anchorRef: `tx-${head.hash.slice(0, 8)}`,
      network: "stellar:testnet",
      anchoredAt: new Date(1_700_001_000_000),
    });
    expect(result.value.newlyCovered).toBe(3);
    expect(await anchors.findLatest()).toEqual(result.value.record);
  });

  it("counts only the entries since the previous anchor", async () => {
    const auditLog = new InMemoryAuditLogRepository();
    const anchors = new InMemoryAnchorRecordRepository();
    await seed(auditLog, 2);
    await underTest(auditLog, anchors, new FakeHashAnchor()).execute();

    await seed(auditLog, 2);
    const result = await underTest(auditLog, anchors, new FakeHashAnchor()).execute();

    if (Result.isErr(result)) throw new Error(result.error.message);
    expect(result.value.newlyCovered).toBe(2);
    expect(result.value.record.sequence).toBe(4);
  });

  it("refuses to anchor an empty log", async () => {
    const ledger = new FakeHashAnchor();

    const result = await underTest(
      new InMemoryAuditLogRepository(),
      new InMemoryAnchorRecordRepository(),
      ledger,
    ).execute();

    expect(Result.isErr(result)).toBe(true);
    if (Result.isOk(result)) return;
    expect(result.error).toBeInstanceOf(ValidationError);
    expect(result.error.message).toContain("audit log is empty");
    expect(ledger.anchored).toEqual([]);
  });

  it("refuses to pay to re-anchor a head that is already on the ledger", async () => {
    const auditLog = new InMemoryAuditLogRepository();
    const anchors = new InMemoryAnchorRecordRepository();
    await seed(auditLog, 2);
    const ledger = new FakeHashAnchor();
    await underTest(auditLog, anchors, ledger).execute();

    const result = await underTest(auditLog, anchors, ledger).execute();

    expect(Result.isErr(result)).toBe(true);
    if (Result.isOk(result)) return;
    expect(result.error).toBeInstanceOf(ValidationError);
    expect(result.error.message).toContain("already anchored");
    expect(ledger.anchored).toHaveLength(1);
  });

  it("anchors again when the head moved even though an earlier anchor exists", async () => {
    const auditLog = new InMemoryAuditLogRepository();
    const anchors = new InMemoryAnchorRecordRepository();
    await seed(auditLog, 2);
    await underTest(auditLog, anchors, new FakeHashAnchor()).execute();

    // Same head, different content: sequence 2 again after a rewrite would be
    // rejected by the log, so grow the chain and check the guard is on the
    // hash, not merely on "some anchor exists".
    await seed(auditLog, 3);
    const result = await underTest(auditLog, anchors, new FakeHashAnchor()).execute();

    expect(Result.isOk(result)).toBe(true);
  });

  it("returns a ledger failure rather than throwing at the scheduler", async () => {
    const auditLog = new InMemoryAuditLogRepository();
    await seed(auditLog, 2);

    const result = await underTest(
      auditLog,
      new InMemoryAnchorRecordRepository(),
      new FakeHashAnchor("unreachable"),
    ).execute();

    expect(Result.isErr(result)).toBe(true);
    if (Result.isOk(result)) return;
    expect(result.error.message).toBe("Horizon is unreachable");
  });

  it("persists no receipt when the ledger did not accept the hash", async () => {
    const auditLog = new InMemoryAuditLogRepository();
    const anchors = new InMemoryAnchorRecordRepository();
    await seed(auditLog, 2);

    await underTest(auditLog, anchors, new FakeHashAnchor("unreachable")).execute();

    // A stored record claiming an anchor that is not on the ledger would be a
    // false proof, which is why the write happens after the submission.
    expect(await anchors.findLatest()).toBeUndefined();
  });

  it("stores the receipt for the entry that was head when anchoring started", async () => {
    const auditLog = new InMemoryAuditLogRepository();
    const anchors = new InMemoryAnchorRecordRepository();
    const head = await seed(auditLog, 5);

    const result = await underTest(auditLog, anchors, new FakeHashAnchor()).execute();

    if (Result.isErr(result)) throw new Error(result.error.message);
    expect(result.value.record.chainHash).toBe(head.hash);
  });

  it("keeps anchors in insertion order so the latest is the most recent head", async () => {
    const repository: AnchorRecordRepository = new InMemoryAnchorRecordRepository();
    const first = {
      sequence: 1,
      chainHash: "a",
      anchorRef: "tx-1",
      network: "stellar:testnet",
      anchoredAt: new Date(1_700_000_000_000),
    };
    const second = { ...first, sequence: 2, chainHash: "b", anchorRef: "tx-2" };
    await repository.save(first);
    await repository.save(second);

    expect(await repository.findLatest()).toEqual(second);
    expect(await repository.findAll(1)).toEqual([second]);
  });
});
