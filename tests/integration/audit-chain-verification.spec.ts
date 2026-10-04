import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  type AnchorVerifierPort,
  PrismaAnchorRecordRepository,
  PrismaAuditLogRepository,
  RecordAuditEvent,
  VerifyAuditChain,
  type VerifyAuditChainCommand,
  type VerifyAuditChainResult,
} from "@verixa/audit";
import type { PrismaClient } from "@verixa/database";
import { Result } from "@verixa/shared-kernel";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  createTestPrismaClient,
  databaseAvailability,
  testDatabaseUrl,
} from "./helpers/database.js";

/**
 * Chain verification against a real Postgres (Issue 132).
 *
 * The use case's own spec runs against an in-memory fake, which proves the
 * walk is correct but proves nothing about the thing this check exists for:
 * that a hash re-derived from *columns read out of a database* matches the
 * digest computed from the values that went in. That round trip is where the
 * design could actually fail — a `timestamptz` that rounds, a JSON `metadata`
 * map that comes back with keys in a different shape, a nullable column
 * reading as `null` instead of `undefined` — and every one of those would make
 * an honest log report itself as tampered. A verification routine that cries
 * wolf is not a control; it is noise an operator learns to ignore.
 *
 * Tampering is simulated the way an attacker with database access would do
 * it: raw `UPDATE` and `DELETE`, bypassing every layer of the application.
 *
 * ## What is not covered here
 *
 * The `--check-anchors` path is exercised against a stand-in ledger, not
 * against Stellar. Reaching a real testnet from CI would make the suite depend
 * on a public network and on funded accounts, and the assertion that matters
 * — that the ledger and the database are compared rather than trusted — holds
 * either way. The live check is what an operator runs by hand.
 */

const available = await databaseAvailability();

const auditPackageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../packages/audit");

describe.skipIf(!available)("audit chain verification", () => {
  const prisma: PrismaClient = createTestPrismaClient();

  /**
   * emptied before each test rather than after.
   *
   * Verification walks the *global* chain, so unlike every other suite here
   * this one cannot tolerate a row it did not write: an entry left behind by
   * another file's login would sit at sequence 1 and change what "the whole
   * chain" means. The integration suite runs spec files serially for exactly
   * this reason (see tests/vitest.config.ts), which makes owning the table for
   * the duration of a test sound rather than merely convenient.
   */
  async function emptyLog(): Promise<void> {
    await prisma.anchorRecord.deleteMany({});
    await prisma.auditLogEntry.deleteMany({});
  }

  beforeAll(async () => {
    await emptyLog();
  });

  beforeEach(async () => {
    await emptyLog();
  });

  afterAll(async () => {
    await emptyLog();
    await prisma.$disconnect();
  });

  function repository(): PrismaAuditLogRepository {
    return new PrismaAuditLogRepository(prisma.auditLogEntry);
  }

  /** Writes `count` entries through the production append path. */
  async function recordChain(
    count: number,
    metadata: Record<string, string> = {},
  ): Promise<string[]> {
    const record = new RecordAuditEvent(repository());
    const hashes: string[] = [];

    for (let index = 0; index < count; index += 1) {
      const entry = await record.execute({
        action: index % 2 === 0 ? "user.login_succeeded" : "user.login_failed",
        actorId: randomUUID(),
        subjectId: randomUUID(),
        metadata: { ...metadata, client: `batch-${String(index)}` },
      });
      if (entry === undefined) throw new Error("audit write failed during fixture setup");
      hashes.push(entry.hash);
    }

    return hashes;
  }

  async function verify(command: VerifyAuditChainCommand = {}): Promise<VerifyAuditChainResult> {
    const result = await new VerifyAuditChain(repository()).execute(command);
    if (Result.isErr(result)) throw new Error(result.error.message);
    return result.value;
  }

  it("re-derives the same hashes from the rows that were written", async () => {
    const hashes = await recordChain(4);

    const result = await verify();

    // The core round-trip guarantee: content stored as columns, read back, and
    // hashed again produces the digest the writer computed. If the mapper, the
    // JSON column or the timestamp precision disagreed anywhere along that
    // path, this would report a break in a log nothing touched.
    expect(result.valid).toBe(true);
    expect(result.firstBreak).toBeUndefined();
    expect(result.checkedEntries).toBe(4);
    expect(result.toSequence).toBe(4);
    expect(result.headHash).toBe(hashes[3]);
  });

  it("reports an intact chain for a log with no entries at all", async () => {
    const result = await verify();

    expect(result.valid).toBe(true);
    expect(result.checkedEntries).toBe(0);
    expect(result.headHash).toBeUndefined();
  });

  describe("tampering with raw SQL", () => {
    it("detects an edited row and names its position", async () => {
      await recordChain(5);

      // The attack the design is against: someone with write access rewrites
      // the record of what they did, leaving the stored digest alone.
      await prisma.auditLogEntry.update({
        where: { sequence: 3 },
        data: { action: "user.registered" },
      });

      const result = await verify();

      expect(result.valid).toBe(false);
      expect(result.firstBreak).toEqual({ sequence: 3, reason: "content_altered" });
      expect(result.checkedEntries).toBe(3);
    });

    it("detects a deleted row, which edits no hash but breaks the link", async () => {
      await recordChain(5);

      await prisma.auditLogEntry.delete({ where: { sequence: 3 } });

      const result = await verify();

      expect(result.valid).toBe(false);
      expect(result.firstBreak).toEqual({ sequence: 4, reason: "link_broken" });
    });

    it("detects a truncated log that still links correctly", async () => {
      const hashes = await recordChain(6);

      // Removing the tail leaves an internally consistent chain — the
      // documented limit of hash chaining on its own. The count is what gives
      // it away here, so this asserts the tool reports where it stopped rather
      // than claiming the log is whole.
      await prisma.auditLogEntry.deleteMany({ where: { sequence: { gte: 4 } } });

      const result = await verify();

      expect(result.valid).toBe(true);
      expect(result.checkedEntries).toBe(3);
      expect(result.headHash).not.toBe(hashes[5]);
    });

    it("treats a hand-edited metadata column as tampering, not as a crash", async () => {
      await recordChain(3);

      // The adapter reads `metadata` defensively precisely so this path
      // produces a verification failure rather than an exception in the middle
      // of the check someone is running during an incident.
      await prisma.auditLogEntry.update({
        where: { sequence: 2 },
        data: { metadata: { client: 42, extra: "injected" } },
      });

      const result = await verify();

      expect(result.firstBreak).toEqual({ sequence: 2, reason: "content_altered" });
    });

    it("stops at the first divergence and does not cascade the alarm", async () => {
      await recordChain(5);

      await prisma.auditLogEntry.update({
        where: { sequence: 2 },
        data: { action: "user.locked_out" },
      });
      await prisma.auditLogEntry.update({
        where: { sequence: 4 },
        data: { action: "user.locked_out" },
      });

      const result = await verify();

      expect(result.firstBreak?.sequence).toBe(2);
      expect(result.checkedEntries).toBe(2);
    });
  });

  describe("windows and batching", () => {
    it("reaches the same verdict one entry at a time as in one page", async () => {
      await recordChain(5);

      const batched = await verify({ batchSize: 1 });
      const single = await verify({ batchSize: 5_000 });

      expect(batched.valid).toBe(true);
      expect(batched.checkedEntries).toBe(single.checkedEntries);
      expect(batched.headHash).toBe(single.headHash);
    });

    it("seeds a mid-chain window from its predecessor instead of calling it a broken link", async () => {
      await recordChain(5);

      const result = await verify({ fromSequence: 3, toSequence: 4 });

      // Without the seed, entry 3's `previous_hash` would be compared against
      // the genesis value and reported as tampering in a log that is intact.
      expect(result.valid).toBe(true);
      expect(result.seededFromWindowStart).toBe(true);
      expect(result.checkedEntries).toBe(2);
      expect(result.toSequence).toBe(4);
    });

    it("cannot see a break that lies before the window it was given", async () => {
      // The cost of a window, stated as a test rather than left in a comment:
      // a range check is not proof of integrity, and whoever schedules it needs
      // to know that from the result rather than from the documentation.
      await recordChain(5);
      await prisma.auditLogEntry.update({
        where: { sequence: 1 },
        data: { action: "user.registered" },
      });

      const whole = await verify();
      const windowed = await verify({ fromSequence: 3 });

      expect(whole.firstBreak?.sequence).toBe(1);
      expect(windowed.valid).toBe(true);
      expect(windowed.seededFromWindowStart).toBe(true);
    });

    it("refuses a window that starts before the chain does", async () => {
      const result = await new VerifyAuditChain(repository()).execute({ fromSequence: 0 });

      expect(Result.isErr(result)).toBe(true);
    });
  });

  describe("organization scope", () => {
    it("counts the tenant's entries while still verifying the whole chain", async () => {
      await recordChain(2, { organizationId: "org-a" });
      await recordChain(1);
      await recordChain(2, { organizationId: "org-a" });

      const result = await verify({ organizationId: "org-a" });

      // An organization-filtered walk would not be a chain at all: the links
      // run through every tenant's entries, so skipping foreign rows breaks
      // the link check on a perfectly honest log. The walk is global; the
      // tenant count is reported alongside it.
      expect(result.valid).toBe(true);
      expect(result.checkedEntries).toBe(5);
      expect(result.organizationEntryCount).toBe(4);
      expect(result.organizationId).toBe("org-a");
    });

    it("reports zero for a tenant that has no entries in the range", async () => {
      await recordChain(3);

      const result = await verify({ organizationId: "org-none" });

      expect(result.valid).toBe(true);
      expect(result.organizationEntryCount).toBe(0);
    });
  });

  describe("anchored ranges", () => {
    /**
     * The ledger, as this suite can reach it: a set of the hashes that were
     * committed. The real adapter asks Horizon for a transaction and looks for
     * the same memo; what is under test is that the two sides are compared to
     * each other rather than either being trusted alone.
     */
    function ledger(commitments: readonly string[]): AnchorVerifierPort {
      return {
        verify: (hash: string) => Promise.resolve(Result.ok(commitments.includes(hash))),
      };
    }

    async function anchorHead(): Promise<{ chainHash: string; sequence: number }> {
      const head = await prisma.auditLogEntry.findFirst({ orderBy: { sequence: "desc" } });
      if (head === null) throw new Error("fixture setup failed: log is empty");

      const record = {
        sequence: head.sequence,
        chainHash: head.hash,
        anchorRef: randomUUID(),
        network: "stellar:testnet",
        anchoredAt: new Date(),
      };
      await new PrismaAnchorRecordRepository(prisma.anchorRecord, randomUUID).save(record);
      return record;
    }

    function verifyWithLedger(commitments: readonly string[]) {
      const anchors = new PrismaAnchorRecordRepository(prisma.anchorRecord, randomUUID);
      return new VerifyAuditChain(repository(), anchors, ledger(commitments)).execute({
        checkAnchors: true,
      });
    }

    it("confirms an anchored head against both the database and the ledger", async () => {
      await recordChain(3);
      const record = await anchorHead();

      const result = await verifyWithLedger([record.chainHash]);
      if (Result.isErr(result)) throw new Error(result.error.message);

      expect(result.value.anchorsSkipped).toBe(false);
      expect(result.value.anchorChecks).toHaveLength(1);
      expect(result.value.anchorChecks[0]).toMatchObject({
        sequence: record.sequence,
        matchesDatabaseChain: true,
        matchesLedger: true,
        ledgerError: undefined,
      });
    });

    it("flags a log rewritten below an anchor the ledger still agrees with", async () => {
      await recordChain(3);
      const record = await anchorHead();

      // Two committed facts now disagree about what sequence 3 was. The ledger
      // cannot be brought into it — it still holds the original hash — so the
      // database is the side that has to be believed guilty. This is the exact
      // signature of history rewritten after it was published, and it is
      // invisible to a chain check alone, because rewriting the tail honestly
      // re-links everything after it.
      await prisma.auditLogEntry.update({
        where: { sequence: 3 },
        data: { action: "user.registered" },
      });

      const result = await verifyWithLedger([record.chainHash]);
      if (Result.isErr(result)) throw new Error(result.error.message);

      expect(result.value.valid).toBe(false);
      expect(result.value.anchorChecks[0]?.matchesDatabaseChain).toBe(false);
      expect(result.value.anchorChecks[0]?.matchesLedger).toBe(true);
    });

    it("leaves a receipt outside the verified range unchecked rather than guessing", async () => {
      await recordChain(4);
      const record = await anchorHead();

      const limited = await new VerifyAuditChain(
        repository(),
        new PrismaAnchorRecordRepository(prisma.anchorRecord, randomUUID),
        ledger([record.chainHash]),
      ).execute({ checkAnchors: true, toSequence: 2 });

      if (Result.isErr(limited)) throw new Error(limited.error.message);

      const check = limited.value.anchorChecks[0];
      expect(check?.matchesDatabaseChain).toBeUndefined();
      expect(check?.matchesLedger).toBeUndefined();
    });

    it("says so when anchors were asked for but no ledger is wired", async () => {
      await recordChain(2);
      await anchorHead();

      const result = await new VerifyAuditChain(repository()).execute({ checkAnchors: true });
      if (Result.isErr(result)) throw new Error(result.error.message);

      expect(result.value.anchorsSkipped).toBe(true);
      expect(result.value.anchorChecks).toEqual([]);
    });
  });

  describe("the operator's CLI", () => {
    interface Run {
      readonly status: number;
      readonly stdout: string;
      readonly stderr: string;
    }

    function runCli(args: readonly string[]): Run {
      // Run the script as a subprocess, as `seed.spec.ts` does: the thing
      // under test is the command an operator types, including its environment
      // handling and its exit status, which is the machine-readable answer a
      // scheduled job or deploy gate reads.
      const result = spawnSync("pnpm", ["run", "verify-chain", ...args], {
        cwd: auditPackageRoot,
        env: { ...process.env, DATABASE_URL: testDatabaseUrl() },
        encoding: "utf8",
        shell: process.platform === "win32",
      });

      return {
        status: result.status ?? -1,
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? "",
      };
    }

    it("exits 0 and prints the head hash for an intact chain", async () => {
      const hashes = await recordChain(3);

      const run = runCli([]);

      expect(run.status).toBe(0);
      expect(run.stdout).toContain("chain verification: INTACT");
      expect(run.stdout).toMatch(/range:\s+1-3/);
      expect(run.stdout).toContain(hashes[2]!);
    }, 60_000);

    it("exits 1 and names the sequence and reason for a broken chain", async () => {
      await recordChain(4);
      await prisma.auditLogEntry.update({
        where: { sequence: 2 },
        data: { action: "user.registered" },
      });

      const run = runCli([]);

      expect(run.status).toBe(1);
      expect(run.stdout).toContain("chain verification: BROKEN");
      expect(run.stdout).toContain("first break at sequence 2: content_altered");
    }, 60_000);

    it("honours --from, --to and --batch-size from the command line", async () => {
      await recordChain(6);

      const run = runCli(["--from", "3", "--to", "5", "--batch-size", "1"]);

      expect(run.status).toBe(0);
      expect(run.stdout).toMatch(/range:\s+3-5/);
      expect(run.stdout).toMatch(/entries:\s+3 checked/);
      expect(run.stdout).toContain("started mid-chain");
    }, 60_000);

    it("reports the tenant count for --organization", async () => {
      await recordChain(2, { organizationId: "org-a" });
      await recordChain(1);

      const run = runCli(["--organization", "org-a"]);

      expect(run.status).toBe(0);
      expect(run.stdout).toMatch(/org:\s+org-a \(2 entries in range\)/);
    }, 60_000);

    it("refuses to run without a database to read", () => {
      const result = spawnSync("pnpm", ["run", "verify-chain"], {
        cwd: auditPackageRoot,
        env: { ...process.env, DATABASE_URL: "" },
        encoding: "utf8",
        shell: process.platform === "win32",
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("DATABASE_URL must be set");
    }, 60_000);

    it("rejects a malformed option rather than verifying something else", () => {
      const run = runCli(["--batch-size", "everything"]);

      expect(run.status).toBe(1);
      expect(run.stderr).toContain("expects an integer");
    }, 60_000);

    it("fails a range check when an anchor disagrees with the chain it claims", async () => {
      await recordChain(3);
      const head = await prisma.auditLogEntry.findFirst({ orderBy: { sequence: "desc" } });
      if (head === null) throw new Error("fixture setup failed");

      await prisma.anchorRecord.create({
        data: {
          id: randomUUID(),
          sequence: head.sequence,
          chainHash: "f".repeat(64),
          anchorRef: randomUUID(),
          network: "stellar:testnet",
          anchoredAt: new Date(),
        },
      });

      // A receipt whose recorded hash the database does not produce at that
      // sequence is a false proof, whatever the chain itself says.
      //
      // Only the database column is asserted: the ledger column depends on a
      // live Horizon round trip, which this suite deliberately does not make a
      // requirement of running (see the file comment).
      const run = runCli(["--check-anchors"]);

      expect(run.status).toBe(1);
      expect(run.stdout).toContain("database MISMATCH");
    }, 120_000);
  });
});
