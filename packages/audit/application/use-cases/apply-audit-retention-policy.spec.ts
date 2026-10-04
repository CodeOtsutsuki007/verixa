import { describe, expect, it } from "vitest";

import { AuditLogEntry } from "../../domain/entities/audit-log-entry.js";
import { InMemoryAuditLogRepository } from "../../infrastructure/testing/in-memory-audit-repositories.js";
import { AgeRetentionPolicy, DEFAULT_RETENTION_POLICY } from "../ports/retention-policy.js";

import { ApplyAuditRetentionPolicy } from "./apply-audit-retention-policy.js";

const NOW = new Date("2026-10-02T12:00:00.000Z");
const DAY = 86_400_000;

function policy(days: number): AgeRetentionPolicy {
  return new AgeRetentionPolicy("test-window", { days });
}

/**
 * A chain of entries at `daysAgo` offsets, oldest first, so the sequence order
 * and the age order agree — which is what a real log looks like and what makes
 * cursor arithmetic meaningful in these tests.
 */
async function seed(
  repository: InMemoryAuditLogRepository,
  agesInDays: readonly number[],
  metadata: (index: number) => Record<string, string> = () => ({}),
): Promise<void> {
  let previous: AuditLogEntry | undefined;

  for (const [index, daysAgo] of agesInDays.entries()) {
    const entry = AuditLogEntry.append({
      action: "user.login_succeeded",
      actorId: `actor-${String(index)}`,
      metadata: metadata(index),
      occurredAt: new Date(NOW.getTime() - daysAgo * DAY),
      previous,
    });
    await repository.append(entry);
    previous = entry;
  }
}

function retained(days: number) {
  const repository = new InMemoryAuditLogRepository();
  const useCase = new ApplyAuditRetentionPolicy(repository, policy(days));
  return { repository, useCase };
}

describe("AgeRetentionPolicy", () => {
  it("puts the cutoff exactly one window before the evaluation instant", () => {
    expect(policy(30).cutoffDate(NOW)).toEqual(new Date(NOW.getTime() - 30 * DAY));
  });

  it("defaults to seven years", () => {
    expect(DEFAULT_RETENTION_POLICY.cutoffDate(NOW)).toEqual(
      new Date(NOW.getTime() - 7 * 365 * DAY),
    );
  });

  it("refuses a window that is not a whole number of days", () => {
    // A fractional or non-positive window silently nominates everything or
    // nothing, and both look like a working policy in a dry run.
    expect(() => policy(0)).toThrow(/whole number of days/u);
    expect(() => policy(1.5)).toThrow(/whole number of days/u);
  });
});

describe("ApplyAuditRetentionPolicy", () => {
  it("identifies entries past the window and leaves the rest alone", async () => {
    const { repository, useCase } = retained(30);
    await seed(repository, [45, 31, 30, 10, 1]);

    const review = await useCase.execute({ now: NOW });

    // 45 and 31 days are plainly outside a 30-day window; the entry at exactly
    // 30 days is included too, which the boundary test below pins down
    // separately.
    expect(review.candidates.map((candidate) => candidate.entry.actorId)).toEqual([
      "actor-0",
      "actor-1",
      "actor-2",
    ]);
    expect(review.cutoff).toEqual(new Date(NOW.getTime() - 30 * DAY));
    expect(review.evaluatedAt).toEqual(NOW);
  });

  it("counts an entry sitting exactly on the boundary as past retention", async () => {
    const { repository, useCase } = retained(30);
    await seed(repository, [30]);

    const review = await useCase.execute({ now: NOW });

    // Inclusive at the edge, deliberately: the alternative means an entry can
    // age past its window by one millisecond and stay unreported, which is a
    // discrepancy nobody will ever notice in a review.
    expect(review.candidates).toHaveLength(1);
    expect(review.candidates[0]?.ageDays).toBe(30);
  });

  it("does not delete, alter, or move anything", async () => {
    const { repository, useCase } = retained(30);
    await seed(repository, [45, 40, 35, 1]);
    const before = repository.all();

    const review = await useCase.execute({ now: NOW });

    expect(review.candidates).toHaveLength(3);
    expect(review.disposition).toBe("identified_only");
    expect(await repository.count()).toBe(4);
    expect(repository.all()).toEqual(before);
    // The chain still verifies: identification cannot have touched a hash.
    expect(before.every((entry) => entry.hasValidHash)).toBe(true);
  });

  it("reports the policy that produced the review", async () => {
    const repository = new InMemoryAuditLogRepository();
    const useCase = new ApplyAuditRetentionPolicy(
      repository,
      new AgeRetentionPolicy("support-logs-90d", { days: 90 }),
    );

    expect((await useCase.execute({ now: NOW })).policy).toBe("support-logs-90d");
  });

  it("pages with a cursor and says when there is more", async () => {
    const { repository, useCase } = retained(30);
    await seed(repository, [100, 99, 98, 97, 96]);

    const first = await useCase.execute({ now: NOW, limit: 2 });
    expect(first.hasMore).toBe(true);
    expect(first.nextCursor).toBe(2);
    expect(first.candidates).toHaveLength(2);

    const second = await useCase.execute({ now: NOW, limit: 2, cursor: first.nextCursor });
    expect(second.candidates.map((c) => c.entry.sequence)).toEqual([3, 4]);
    expect(second.hasMore).toBe(true);

    const third = await useCase.execute({ now: NOW, limit: 2, cursor: second.nextCursor });
    expect(third.candidates).toHaveLength(1);
    expect(third.hasMore).toBe(false);
    expect(third.nextCursor).toBeUndefined();
  });

  it("walks the whole log when resumed until nothing is left", async () => {
    const { repository, useCase } = retained(30);
    await seed(repository, [100, 90, 80, 70, 60, 50]);

    const seen: number[] = [];
    let cursor: number | undefined;

    for (;;) {
      const review = await useCase.execute({ now: NOW, limit: 2, cursor });
      seen.push(...review.candidates.map((candidate) => candidate.entry.sequence));
      if (!review.hasMore) break;
      cursor = review.nextCursor;
    }

    expect(seen).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it("restricts the review to one organization when asked", async () => {
    const { repository, useCase } = retained(30);
    await seed(repository, [100, 90, 80], (index) => ({
      organizationId: index === 1 ? "org-b" : "org-a",
    }));

    const review = await useCase.execute({ now: NOW, organizationId: "org-b" });

    expect(review.candidates.map((candidate) => candidate.entry.actorId)).toEqual(["actor-1"]);
  });

  it("returns an empty review for a log that is all inside the window", async () => {
    const { repository, useCase } = retained(365);
    await seed(repository, [10, 5, 1]);

    const review = await useCase.execute({ now: NOW });

    expect(review.candidates).toHaveLength(0);
    expect(review.hasMore).toBe(false);
    expect(review.evaluatedThroughSequence).toBeUndefined();
  });
});
