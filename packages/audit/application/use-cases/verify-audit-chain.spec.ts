import { Result, ValidationError } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";
import { InMemoryAuditLogRepository } from "../../infrastructure/testing/in-memory-audit-repositories.js";
import type {
  AnchorFailure,
  AnchorRecord,
  AnchorRecordRepository,
} from "../ports/audit-log-repository.js";

import { DEFAULT_MAX_ANCHOR_CHECKS, VerifyAuditChain } from "./verify-audit-chain.js";

function appendAfter(
  previous: AuditLogEntry | undefined,
  metadata: Record<string, string> = {},
  action: Parameters<typeof AuditLogEntry.append>[0]["action"] = "user.login_succeeded",
): AuditLogEntry {
  return AuditLogEntry.append({
    action,
    actorId: "actor-1",
    subjectId: "subject-1",
    metadata,
    previous,
    occurredAt: new Date(1_700_000_000_000 + (previous?.sequence ?? 0) * 1000),
  });
}

/** Builds an honest chain of `length` entries into the repository. */
async function seedChain(
  repository: InMemoryAuditLogRepository,
  length: number,
  metadata: Record<string, string> = {},
): Promise<AuditLogEntry[]> {
  const entries: AuditLogEntry[] = [];
  let previous: AuditLogEntry | undefined;

  for (let index = 0; index < length; index += 1) {
    previous = appendAfter(previous, metadata);
    await repository.append(previous);
    entries.push(previous);
  }

  return entries;
}

/**
 * A row whose content was edited without touching its digest — what a tamperer
 * who intends to go unnoticed must *not* do, and the reason the hash is
 * recomputed rather than read back.
 */
function alteredContent(original: AuditLogEntry): AuditLogEntry {
  return AuditLogEntry.reconstitute({ ...original, action: "user.locked_out" });
}

/** A receipt for a chain head, as `AnchorAuditLog` would have written one. */
function anchorRecordFor(head: AuditLogEntry): AnchorRecord {
  return {
    sequence: head.sequence,
    chainHash: head.hash,
    anchorRef: "abc123ledgertransactionhash",
    network: "stellar:testnet",
    anchoredAt: new Date(1_700_000_999_000),
  };
}

class FakeAnchorRecordRepository implements AnchorRecordRepository {
  private readonly records: AnchorRecord[];

  constructor(records: readonly AnchorRecord[] = []) {
    this.records = [...records];
  }

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
 * Ledger stand-in: `answers` maps a hash to what the public record says about
 * it, so a test can state "the ledger holds this one and not that one" without
 * modelling Horizon. `unreachable` reproduces a lookup that could not complete,
 * which is a third answer and must not be reported as either of the other two.
 */
class FakeLedger {
  readonly requested: string[] = [];

  constructor(
    private readonly answers: Readonly<Record<string, boolean>> = {},
    private readonly unreachable: string | undefined = undefined,
  ) {}

  verify(hash: string): Promise<Result<boolean, AnchorFailure>> {
    this.requested.push(hash);
    if (this.unreachable !== undefined)
      return Promise.resolve(Result.err({ message: this.unreachable }));
    return Promise.resolve(Result.ok(this.answers[hash] ?? false));
  }
}

async function succeed(
  verify: VerifyAuditChain,
  command: Parameters<VerifyAuditChain["execute"]>[0] = {},
) {
  const result = await verify.execute(command);
  if (Result.isErr(result))
    throw new Error(`verification unexpectedly failed: ${result.error.message}`);
  return result.value;
}

/**
 * Unwraps a rejected command as a validation failure. `VerifyAuditChainError`
 * is a union with `AnchorFailure`, so the narrowing has to happen somewhere,
 * and doing it here keeps it out of every assertion in the test.
 */
function validationErrorFor(
  result: Awaited<ReturnType<VerifyAuditChain["execute"]>>,
): ValidationError {
  if (!Result.isErr(result)) throw new Error("expected the command to be rejected");
  if (!(result.error instanceof ValidationError)) {
    throw new Error(`expected a ValidationError, got ${result.error.message}`);
  }
  return result.error;
}

describe("VerifyAuditChain", () => {
  it("passes on an untampered chain", async () => {
    const repository = new InMemoryAuditLogRepository();
    const entries = await seedChain(repository, 5);

    const result = await succeed(new VerifyAuditChain(repository));

    expect(result.valid).toBe(true);
    expect(result.firstBreak).toBeUndefined();
    expect(result.checkedEntries).toBe(5);
    expect(result.fromSequence).toBe(1);
    expect(result.toSequence).toBe(5);
    expect(result.headHash).toBe(entries[4]?.hash);
    expect(result.seededFromWindowStart).toBe(false);
  });

  it("passes on an empty log rather than reporting a break at the genesis link", async () => {
    const repository = new InMemoryAuditLogRepository();

    const result = await succeed(new VerifyAuditChain(repository));

    expect(result.valid).toBe(true);
    expect(result.checkedEntries).toBe(0);
    expect(result.toSequence).toBeUndefined();
    expect(result.headHash).toBeUndefined();
  });

  it("detects a corrupted record and reports its position", async () => {
    const repository = new InMemoryAuditLogRepository();
    const entries = await seedChain(repository, 4);

    repository.tamper(2, alteredContent(entries[1]!));

    const result = await succeed(new VerifyAuditChain(repository));

    expect(result.valid).toBe(false);
    expect(result.firstBreak).toEqual({ sequence: 2, reason: "content_altered" });
  });

  it("reports a deletion as a broken link rather than an altered record", async () => {
    const repository = new InMemoryAuditLogRepository();
    await seedChain(repository, 4);

    // Row removed, nothing else touched: the survivor at sequence 4 still
    // commits to a row that no longer exists, which is exactly what
    // `link_broken` names. Its own digest is fine, so a content check alone
    // would have called this log clean.
    repository.remove(3);

    const result = await succeed(new VerifyAuditChain(repository));

    expect(result.valid).toBe(false);
    expect(result.firstBreak).toEqual({ sequence: 4, reason: "link_broken" });
  });

  it("stops at the first break rather than listing the cascade it caused", async () => {
    const repository = new InMemoryAuditLogRepository();
    const entries = await seedChain(repository, 6);

    repository.tamper(2, alteredContent(entries[1]!));

    const result = await succeed(new VerifyAuditChain(repository));

    expect(result.firstBreak?.sequence).toBe(2);
    // One `firstBreak`, not five: everything after a break is unreliable, and
    // listing the cascade would bury the origin under noise it caused. The walk
    // also stops — it does not keep re-hashing a log already known to be wrong.
    expect(result.checkedEntries).toBe(2);
  });

  it("walks the chain in batches without mistaking a page boundary for a break", async () => {
    const repository = new InMemoryAuditLogRepository();
    await seedChain(repository, 7);

    expect((await succeed(new VerifyAuditChain(repository), { batchSize: 2 })).valid).toBe(true);
  });

  it("counts every entry when batching divides the log unevenly", async () => {
    const repository = new InMemoryAuditLogRepository();
    await seedChain(repository, 10);

    const result = await succeed(new VerifyAuditChain(repository), { batchSize: 3 });

    expect(result.checkedEntries).toBe(10);
    expect(result.toSequence).toBe(10);
  });

  it("seeds a window that starts mid-chain so an intact window verifies", async () => {
    const repository = new InMemoryAuditLogRepository();
    await seedChain(repository, 6);

    const result = await succeed(new VerifyAuditChain(repository), {
      fromSequence: 4,
      toSequence: 6,
    });

    expect(result.valid).toBe(true);
    expect(result.checkedEntries).toBe(3);
    // Reported rather than left for the reader to infer: a window cannot see a
    // break earlier in the log, and "the chain is fine" is a misreading the
    // output should make hard.
    expect(result.seededFromWindowStart).toBe(true);
  });

  it("still finds a break inside a window that starts mid-chain", async () => {
    const repository = new InMemoryAuditLogRepository();
    const entries = await seedChain(repository, 6);

    repository.tamper(5, alteredContent(entries[4]!));

    const result = await succeed(new VerifyAuditChain(repository), {
      fromSequence: 3,
      toSequence: 6,
    });

    expect(result.valid).toBe(false);
    expect(result.firstBreak).toEqual({ sequence: 5, reason: "content_altered" });
  });

  it("returns nothing when the requested window is past the end of the log", async () => {
    const repository = new InMemoryAuditLogRepository();
    await seedChain(repository, 3);

    const result = await succeed(new VerifyAuditChain(repository), { fromSequence: 9 });

    expect(result.checkedEntries).toBe(0);
    expect(result.valid).toBe(true);
  });

  describe("organization scope", () => {
    const tenant = "11111111-1111-4111-8111-111111111111";

    async function sharedLog(
      repository: InMemoryAuditLogRepository,
      owners: readonly (string | undefined)[],
    ): Promise<AuditLogEntry[]> {
      const entries: AuditLogEntry[] = [];
      let previous: AuditLogEntry | undefined;

      for (const organizationId of owners) {
        previous = appendAfter(previous, organizationId === undefined ? {} : { organizationId });
        await repository.append(previous);
        entries.push(previous);
      }

      return entries;
    }

    it("counts the tenant's entries while verifying every link between them", async () => {
      const repository = new InMemoryAuditLogRepository();
      await sharedLog(repository, [tenant, undefined, tenant, undefined]);

      const result = await succeed(new VerifyAuditChain(repository), { organizationId: tenant });

      expect(result.valid).toBe(true);
      expect(result.organizationEntryCount).toBe(2);
      // The whole chain is walked even for one tenant: sequences 2 and 4 sit
      // inside the links between the tenant's records, and skipping them would
      // certify a chain that was never checked.
      expect(result.checkedEntries).toBe(4);
      expect(result.organizationId).toBe(tenant);
    });

    it("reports a break in another tenant's entry as a failure of this range", async () => {
      const repository = new InMemoryAuditLogRepository();
      const entries = await sharedLog(repository, [tenant, undefined, tenant]);

      repository.tamper(2, alteredContent(entries[1]!));

      const result = await succeed(new VerifyAuditChain(repository), { organizationId: tenant });

      expect(result.valid).toBe(false);
      expect(result.firstBreak).toEqual({ sequence: 2, reason: "content_altered" });
      // 1 rather than the tenant's 2 entries: the walk stopped at the break, so
      // the tenant's later record was never reached. A count that kept going
      // would imply those entries had been checked.
      expect(result.organizationEntryCount).toBe(1);
    });

    it("reports zero for a tenant with no entries without failing the check", async () => {
      const repository = new InMemoryAuditLogRepository();
      await seedChain(repository, 3);

      const result = await succeed(new VerifyAuditChain(repository), {
        organizationId: "no-such-organization",
      });

      expect(result.valid).toBe(true);
      expect(result.organizationEntryCount).toBe(0);
      expect(result.checkedEntries).toBe(3);
    });
  });

  describe("rejected input", () => {
    it("refuses a window that starts before the chain does", async () => {
      const error = validationErrorFor(
        await new VerifyAuditChain(new InMemoryAuditLogRepository()).execute({
          fromSequence: 0,
        }),
      );

      expect(error.message).toBe("fromSequence must be at least 1.");
      expect(error.fieldErrors["fromSequence"]).toEqual(["must be >= 1"]);
    });

    it("refuses a window whose end precedes its start", async () => {
      const error = validationErrorFor(
        await new VerifyAuditChain(new InMemoryAuditLogRepository()).execute({
          fromSequence: 5,
          toSequence: 4,
        }),
      );

      expect(error.fieldErrors["toSequence"]).toEqual(["must be >= fromSequence"]);
    });

    it("refuses a batch size that would load the log into memory in one query", async () => {
      const verify = new VerifyAuditChain(new InMemoryAuditLogRepository());

      expect(
        validationErrorFor(await verify.execute({ batchSize: 5_001 })).fieldErrors["batchSize"],
      ).toEqual(["must be between 1 and 5000"]);
      expect(
        validationErrorFor(await verify.execute({ batchSize: 0 })).fieldErrors["batchSize"],
      ).toEqual(["must be between 1 and 5000"]);
    });
  });

  describe("anchored ranges", () => {
    it("confirms a receipt against the ledger without trusting the local database", async () => {
      const repository = new InMemoryAuditLogRepository();
      const entries = await seedChain(repository, 3);
      const head = entries[2]!;

      const result = await succeed(
        new VerifyAuditChain(
          repository,
          new FakeAnchorRecordRepository([anchorRecordFor(head)]),
          new FakeLedger({ [head.hash]: true }),
        ),
        { checkAnchors: true },
      );

      expect(result.anchorsSkipped).toBe(false);
      expect(result.anchorChecks).toHaveLength(1);
      expect(result.anchorChecks[0]).toEqual({
        sequence: 3,
        chainHash: head.hash,
        anchorRef: "abc123ledgertransactionhash",
        network: "stellar:testnet",
        matchesDatabaseChain: true,
        matchesLedger: true,
        ledgerError: undefined,
      });
    });

    it("flags a log rewritten after it was anchored", async () => {
      const repository = new InMemoryAuditLogRepository();
      const entries = await seedChain(repository, 3);
      const receipt = anchorRecordFor(entries[2]!);

      // Replace every row with a *different* internally consistent chain built
      // from genesis. Verification alone cannot tell: the rewritten log has
      // valid hashes and valid links. Only the anchored digest can, and that is
      // the gap anchoring closes.
      const rival = new InMemoryAuditLogRepository();
      await seedChain(rival, 3, { rewritten: "true" });
      for (const entry of rival.all()) repository.tamper(entry.sequence, entry);

      const result = await succeed(
        new VerifyAuditChain(
          repository,
          new FakeAnchorRecordRepository([receipt]),
          new FakeLedger({ [receipt.chainHash]: true }),
        ),
        { checkAnchors: true },
      );

      expect(result.valid).toBe(true);
      expect(result.anchorChecks[0]?.matchesDatabaseChain).toBe(false);
      expect(result.anchorChecks[0]?.matchesLedger).toBe(true);
    });

    it("flags a fabricated receipt whose hash never reached the ledger", async () => {
      const repository = new InMemoryAuditLogRepository();
      const entries = await seedChain(repository, 2);
      const head = entries[1]!;

      const forged = { ...anchorRecordFor(head), chainHash: "f".repeat(64) };
      const result = await succeed(
        new VerifyAuditChain(
          repository,
          new FakeAnchorRecordRepository([forged]),
          new FakeLedger({ [head.hash]: true }),
        ),
        { checkAnchors: true },
      );

      expect(result.anchorChecks[0]?.matchesDatabaseChain).toBe(false);
      expect(result.anchorChecks[0]?.matchesLedger).toBe(false);
    });

    it("leaves the ledger unchecked for a receipt outside the verified range", async () => {
      const repository = new InMemoryAuditLogRepository();
      const entries = await seedChain(repository, 4);
      const ledger = new FakeLedger({ [entries[3]!.hash]: true });

      const result = await succeed(
        new VerifyAuditChain(
          repository,
          new FakeAnchorRecordRepository([anchorRecordFor(entries[3]!)]),
          ledger,
        ),
        { checkAnchors: true, toSequence: 2 },
      );

      // A hash that was never recomputed cannot match or mismatch. Calling the
      // absence a failure would make every short run look like tampering;
      // calling it a match would ask the ledger about a value this run knows
      // nothing about.
      expect(result.anchorChecks[0]?.matchesDatabaseChain).toBeUndefined();
      expect(result.anchorChecks[0]?.matchesLedger).toBeUndefined();
      expect(ledger.requested).toEqual([]);
    });

    it("reports a ledger that could not be reached rather than guessing", async () => {
      const repository = new InMemoryAuditLogRepository();
      const entries = await seedChain(repository, 2);
      const head = entries[1]!;

      const result = await succeed(
        new VerifyAuditChain(
          repository,
          new FakeAnchorRecordRepository([anchorRecordFor(head)]),
          new FakeLedger({}, "Horizon is unreachable"),
        ),
        { checkAnchors: true },
      );

      expect(result.anchorChecks[0]?.matchesLedger).toBeUndefined();
      expect(result.anchorChecks[0]?.ledgerError).toBe("Horizon is unreachable");
      // The local half of the check still completed, and saying so is what lets
      // an operator distinguish "our log looks fine" from "we could not tell".
      expect(result.anchorChecks[0]?.matchesDatabaseChain).toBe(true);
    });

    it("says so when anchoring was asked for but no ledger is wired", async () => {
      const repository = new InMemoryAuditLogRepository();
      await seedChain(repository, 2);

      const result = await succeed(
        new VerifyAuditChain(repository, new FakeAnchorRecordRepository()),
        { checkAnchors: true },
      );

      expect(result.anchorsSkipped).toBe(true);
      expect(result.anchorChecks).toHaveLength(0);
    });

    it("consults only the most recent receipts up to the requested limit", async () => {
      const repository = new InMemoryAuditLogRepository();
      const entries = await seedChain(repository, 6);
      const records = [entries[3]!, entries[4]!, entries[5]!].map(anchorRecordFor);

      const result = await succeed(
        new VerifyAuditChain(
          repository,
          new FakeAnchorRecordRepository(records),
          new FakeLedger(Object.fromEntries(entries.map((entry) => [entry.hash, true]))),
        ),
        { checkAnchors: true, maxAnchorChecks: 2 },
      );

      expect(result.anchorChecks.map((check) => check.sequence)).toEqual([6, 5]);
    });

    it("defaults to the documented receipt limit", async () => {
      const repository = new InMemoryAuditLogRepository();
      const entries = await seedChain(repository, DEFAULT_MAX_ANCHOR_CHECKS + 2);

      const result = await succeed(
        new VerifyAuditChain(
          repository,
          new FakeAnchorRecordRepository(entries.map(anchorRecordFor)),
          new FakeLedger(Object.fromEntries(entries.map((entry) => [entry.hash, true]))),
        ),
        { checkAnchors: true },
      );

      expect(result.anchorChecks).toHaveLength(DEFAULT_MAX_ANCHOR_CHECKS);
    });
  });
});
