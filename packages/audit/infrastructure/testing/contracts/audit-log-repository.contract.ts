import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { AuditLogRepository } from "../../../application/ports/audit-log-repository.js";
import {
  AuditLogEntry,
  GENESIS_HASH,
  verifyChain,
} from "../../../domain/entities/audit-log-entry.js";

function entryAfter(previous: AuditLogEntry | undefined, index: number): AuditLogEntry {
  return AuditLogEntry.append({
    action: "user.login_succeeded",
    actorId: `actor-${String(index)}`,
    previous,
    occurredAt: new Date(1_700_000_000_000 + index * 1000),
  });
}

/** Builds and appends one entry the way a well-behaved caller does. */
async function appendOne(repository: AuditLogRepository, index: number): Promise<AuditLogEntry> {
  const previous = await repository.findLatest();
  const entry = entryAfter(previous, index);
  const outcome = await repository.append(entry, previous?.hash ?? GENESIS_HASH);
  if (Result.isErr(outcome)) {
    throw new Error(`contract setup failed: ${outcome.error.message}`);
  }
  return entry;
}

/** Builds `count` consecutive entries chained onto `head`. */
function chainFrom(head: AuditLogEntry | undefined, count: number, offset = 1): AuditLogEntry[] {
  const entries: AuditLogEntry[] = [];
  let previous = head;
  for (let index = 0; index < count; index += 1) {
    const entry = entryAfter(previous, offset + index);
    entries.push(entry);
    previous = entry;
  }
  return entries;
}

/**
 * Behavioral contract every `AuditLogRepository` implementation must satisfy.
 *
 * Run against `InMemoryAuditLogRepository` on every test run and against
 * `PrismaAuditLogRepository` (over a fake transactional client) without a
 * database, plus the real Postgres adapter in the network-dependent suite. Same
 * one-suite-many-implementations approach as every other repository port here.
 *
 * The append-protocol cases are the ones that earn this suite its place. A fake
 * that accepted a stale `previousHash`, or that wrote half a batch, would let
 * every test built on it pass against a chain the real database would have
 * rejected — and a forked audit chain is not a bug someone notices in review, it
 * is a bug that shows up while answering a regulator.
 */
export function auditLogRepositoryContract(createRepository: () => AuditLogRepository): void {
  describe("AuditLogRepository contract", () => {
    it("reports an empty log as having no head", async () => {
      const repository = createRepository();

      expect(await repository.findLatest()).toBeUndefined();
      expect(await repository.count()).toBe(0);
    });

    it("appends to the genesis hash on an empty chain", async () => {
      const repository = createRepository();

      const first = await appendOne(repository, 0);

      expect(first.previousHash).toBe(GENESIS_HASH);
      expect(await repository.count()).toBe(1);
      expect(await repository.findLatest()).toMatchObject({ sequence: 1 });
    });

    it("reads back exactly what was written", async () => {
      const repository = createRepository();

      const written = await appendOne(repository, 0);
      const read = await repository.findLatest();

      expect(read?.id).toBe(written.id);
      expect(read?.hash).toBe(written.hash);
      expect(read?.metadata).toEqual(written.metadata);
      expect(read?.occurredAt.getTime()).toBe(written.occurredAt.getTime());
    });

    it("rejects an append whose expected head is stale", async () => {
      const repository = createRepository();
      const first = await appendOne(repository, 0);

      // Built against the genesis head but offered after the chain moved, which
      // is the fork this protocol exists to prevent.
      const stale = entryAfter(undefined, 1);
      const outcome = await repository.append(stale, GENESIS_HASH);

      expect(Result.isErr(outcome)).toBe(true);
      if (Result.isErr(outcome)) {
        expect(outcome.error.actualPreviousHash).toBe(first.hash);
      }
      // Rejection must not have written anything.
      expect(await repository.count()).toBe(1);
    });

    it("rejects an append that duplicates an existing sequence", async () => {
      const repository = createRepository();
      const first = await appendOne(repository, 0);

      const duplicate = entryAfter(first, 1);
      const conflicting = AuditLogEntry.reconstitute({
        ...duplicate,
        sequence: first.sequence,
      });

      const outcome = await repository.append(conflicting, first.hash);

      expect(Result.isErr(outcome)).toBe(true);
      expect(await repository.count()).toBe(1);
    });

    it("serializes concurrent appends so no two claim the same predecessor", async () => {
      const repository = createRepository();
      const head = await appendOne(repository, 0);

      // Both racers read the same head, so both propose sequence 2 against it.
      const proposals = [entryAfter(head, 1), entryAfter(head, 2)];
      const outcomes = await Promise.all(
        proposals.map((entry) => repository.append(entry, head.hash)),
      );

      const accepted = outcomes.filter((outcome) => Result.isOk(outcome));
      expect(accepted.length).toBe(1);

      const stored = await repository.findFrom(1, 10);
      const break_ = verifyChain(stored);
      // The whole point: whatever won, the stored chain is intact.
      expect(break_).toBeUndefined();
      expect(await repository.count()).toBe(2);
    });

    it("appends a batch atomically and in order", async () => {
      const repository = createRepository();
      const head = await appendOne(repository, 0);

      const batch = chainFrom(head, 3, 1);
      const outcome = await repository.appendMany(batch, head.hash);

      expect(Result.isOk(outcome)).toBe(true);
      expect(await repository.count()).toBe(4);

      const stored = await repository.findFrom(1, 10);
      expect(stored.map((entry) => entry.sequence)).toEqual([1, 2, 3, 4]);
      expect(verifyChain(stored)).toBeUndefined();
    });

    it("writes none of a batch whose head expectation is stale", async () => {
      const repository = createRepository();
      const head = await appendOne(repository, 0);

      const outcome = await repository.appendMany(chainFrom(head, 2, 1), GENESIS_HASH);

      expect(Result.isErr(outcome)).toBe(true);
      // A partial batch would be a gap, and a gap is indistinguishable from
      // tampering — so the only acceptable outcome here is zero rows.
      expect(await repository.count()).toBe(1);
    });

    it("writes none of a batch that is not internally chained", async () => {
      const repository = createRepository();
      const head = await appendOne(repository, 0);

      const first = entryAfter(head, 1);
      const disconnected = entryAfter(undefined, 2);
      const outcome = await repository.appendMany([first, disconnected], head.hash);

      expect(Result.isErr(outcome)).toBe(true);
      expect(await repository.count()).toBe(1);
    });

    it("treats an empty batch as a no-op rather than an error", async () => {
      const repository = createRepository();

      const outcome = await repository.appendMany([], GENESIS_HASH);

      expect(Result.isOk(outcome)).toBe(true);
      expect(await repository.count()).toBe(0);
    });

    it("paginates forward from a sequence in order", async () => {
      const repository = createRepository();
      for (let index = 0; index < 5; index += 1) {
        await appendOne(repository, index);
      }

      const page = await repository.findFrom(3, 2);

      expect(page.map((entry) => entry.sequence)).toEqual([3, 4]);
    });

    it("keeps a chain that verifies end to end", async () => {
      const repository = createRepository();
      for (let index = 0; index < 12; index += 1) {
        await appendOne(repository, index);
      }

      const stored = await repository.findFrom(1, 100);

      expect(stored.length).toBe(12);
      expect(verifyChain(stored)).toBeUndefined();
      for (const entry of stored) {
        expect(entry.hasValidHash).toBe(true);
      }
    });
  });
}
