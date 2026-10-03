import { describe, expect, it } from "vitest";

import type { StaleCredentialMetrics } from "../../application/ports/credential-repository.js";
import { Credential, type CredentialUserId } from "../../domain/entities/credential.js";
import { asId } from "@verixa/shared-kernel";
import { InMemoryCredentialRepository } from "../testing/in-memory-credential-repository.js";
import { Argon2PasswordHasher, DEFAULT_ARGON2_PARAMETERS } from "../argon2-password-hasher.js";

/**
 * Weak and strong parameter sets for testing staleness detection.
 *
 * A hasher configured with STRONG parameters will report WEAK hashes as stale,
 * which is exactly the scenario the metric is measuring: cost parameters that
 * rose over time, and old hashes that need upgrading.
 */
const WEAK = { memoryCost: 64, timeCost: 1, parallelism: 1 };
const STRONG = { memoryCost: 256, timeCost: 2, parallelism: 1 };

describe("PrismaCredentialRepository.getStaleCredentialMetrics", () => {
  const weakHasher = new Argon2PasswordHasher(WEAK);
  const strongHasher = new Argon2PasswordHasher(STRONG);

  describe("empty repository", () => {
    it("returns zero count and null dates when no credentials exist", async () => {
      const repo = new InMemoryCredentialRepository();

      const metrics = await repo.getStaleCredentialMetrics(strongHasher);

      expect(metrics).toEqual({
        count: 0,
        oldestCreatedAt: null,
        medianCreatedAt: null,
        p95CreatedAt: null,
      });
    });
  });

  describe("all credentials current", () => {
    it("returns zero count when all credentials are at or above current parameters", async () => {
      const repo = new InMemoryCredentialRepository();

      // Create credentials with the strong hasher, then check staleness
      // against the same strong hasher — none should be stale.
      const hash1 = await strongHasher.hash("password1");
      const hash2 = await strongHasher.hash("password2");

      const cred1 = Credential.create({ userId: asId("UserId")("user1"), passwordHash: hash1 });
      const cred2 = Credential.create({ userId: asId("UserId")("user2"), passwordHash: hash2 });

      await repo.save(cred1);
      await repo.save(cred2);

      const metrics = await repo.getStaleCredentialMetrics(strongHasher);

      expect(metrics.count).toBe(0);
      expect(metrics.oldestCreatedAt).toBeNull();
      expect(metrics.medianCreatedAt).toBeNull();
      expect(metrics.p95CreatedAt).toBeNull();
    });
  });

  describe("all credentials stale", () => {
    it("identifies all credentials as stale and calculates distribution", async () => {
      const repo = new InMemoryCredentialRepository();

      // Create credentials with weak parameters, then check against strong hasher.
      // All should be stale.
      const hash1 = await weakHasher.hash("password1");
      const hash2 = await weakHasher.hash("password2");
      const hash3 = await weakHasher.hash("password3");

      const now = new Date();
      const oneWeekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const twoWeeksAgo = new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000);
      const threeWeeksAgo = new Date(now.getTime() - 21 * 24 * 60 * 60 * 1000);

      const cred1 = Credential.reconstitute({
        id: asId("CredentialId")("cred1"),
        userId: asId("UserId")("user1"),
        passwordHash: hash1,
        failedAttempts: 0,
        lockedUntil: undefined,
        createdAt: oneWeekAgo,
        updatedAt: oneWeekAgo,
      });

      const cred2 = Credential.reconstitute({
        id: asId("CredentialId")("cred2"),
        userId: asId("UserId")("user2"),
        passwordHash: hash2,
        failedAttempts: 0,
        lockedUntil: undefined,
        createdAt: twoWeeksAgo,
        updatedAt: twoWeeksAgo,
      });

      const cred3 = Credential.reconstitute({
        id: asId("CredentialId")("cred3"),
        userId: asId("UserId")("user3"),
        passwordHash: hash3,
        failedAttempts: 0,
        lockedUntil: undefined,
        createdAt: threeWeeksAgo,
        updatedAt: threeWeeksAgo,
      });

      await repo.save(cred1);
      await repo.save(cred2);
      await repo.save(cred3);

      // Check staleness against strong hasher (all weak hashes are stale).
      const metrics = await repo.getStaleCredentialMetrics(strongHasher);

      expect(metrics.count).toBe(3);
      expect(metrics.oldestCreatedAt).toEqual(threeWeeksAgo);
      expect(metrics.medianCreatedAt).toEqual(twoWeeksAgo);
      // For 3 items (indices 0, 1, 2), p95 is at index floor(0.95 * 2) = 1.
      expect(metrics.p95CreatedAt).toEqual(twoWeeksAgo);
    });
  });

  describe("mixed stale and current", () => {
    it("counts only stale credentials and calculates their age distribution", async () => {
      const repo = new InMemoryCredentialRepository();

      // Mix of weak (stale) and strong (current) hashes.
      const weakHash1 = await weakHasher.hash("old_password1");
      const weakHash2 = await weakHasher.hash("old_password2");
      const strongHash1 = await strongHasher.hash("current_password1");
      const strongHash2 = await strongHasher.hash("current_password2");

      const now = new Date();
      const oneMonthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      const twoMonthsAgo = new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000);

      const weakCred1 = Credential.reconstitute({
        id: asId("CredentialId")("wcred1"),
        userId: asId("UserId")("wuser1"),
        passwordHash: weakHash1,
        failedAttempts: 0,
        lockedUntil: undefined,
        createdAt: oneMonthAgo,
        updatedAt: oneMonthAgo,
      });

      const weakCred2 = Credential.reconstitute({
        id: asId("CredentialId")("wcred2"),
        userId: asId("UserId")("wuser2"),
        passwordHash: weakHash2,
        failedAttempts: 0,
        lockedUntil: undefined,
        createdAt: twoMonthsAgo,
        updatedAt: twoMonthsAgo,
      });

      const strongCred1 = Credential.reconstitute({
        id: asId("CredentialId")("scred1"),
        userId: asId("UserId")("suser1"),
        passwordHash: strongHash1,
        failedAttempts: 0,
        lockedUntil: undefined,
        createdAt: now,
        updatedAt: now,
      });

      const strongCred2 = Credential.reconstitute({
        id: asId("CredentialId")("scred2"),
        userId: asId("UserId")("suser2"),
        passwordHash: strongHash2,
        failedAttempts: 0,
        lockedUntil: undefined,
        createdAt: now,
        updatedAt: now,
      });

      await repo.save(weakCred1);
      await repo.save(weakCred2);
      await repo.save(strongCred1);
      await repo.save(strongCred2);

      const metrics = await repo.getStaleCredentialMetrics(strongHasher);

      // Only the two weak hashes should be counted.
      expect(metrics.count).toBe(2);
      expect(metrics.oldestCreatedAt).toEqual(twoMonthsAgo);
      // For 2 items (indices 0, 1), median is at index floor((2-1)/2) = 0.
      expect(metrics.medianCreatedAt).toEqual(twoMonthsAgo);
      // p95 is at index floor(0.95 * 1) = 0.
      expect(metrics.p95CreatedAt).toEqual(twoMonthsAgo);
    });
  });

  describe("percentile calculations", () => {
    it("correctly calculates percentiles for a larger dataset", async () => {
      const repo = new InMemoryCredentialRepository();

      // 100 weak credentials spread over 100 days.
      const now = new Date();
      for (let i = 0; i < 100; i++) {
        const createdAt = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
        const hash = await weakHasher.hash(`password${i}`);
        const cred = Credential.reconstitute({
          id: asId("CredentialId")(`cred${i}`),
          userId: asId("UserId")(`user${i}`),
          passwordHash: hash,
          failedAttempts: 0,
          lockedUntil: undefined,
          createdAt,
          updatedAt: createdAt,
        });
        await repo.save(cred);
      }

      const metrics = await repo.getStaleCredentialMetrics(strongHasher);

      expect(metrics.count).toBe(100);

      // Oldest should be 99 days ago (i=99).
      const expectedOldest = new Date(now.getTime() - 99 * 24 * 60 * 60 * 1000);
      expect(metrics.oldestCreatedAt).toEqual(expectedOldest);

      // Median: for 100 items (indices 0-99), median index is floor((100-1)/2) = 49.
      // That's item created 49 days ago.
      const expectedMedian = new Date(now.getTime() - 49 * 24 * 60 * 60 * 1000);
      expect(metrics.medianCreatedAt).toEqual(expectedMedian);

      // p95: index floor(0.95 * 99) = 94.
      // That's item created 94 days ago.
      const expectedP95 = new Date(now.getTime() - 94 * 24 * 60 * 60 * 1000);
      expect(metrics.p95CreatedAt).toEqual(expectedP95);
    });
  });

  describe("single stale credential", () => {
    it("reports same value for oldest, median, and p95 when only one stale credential exists", async () => {
      const repo = new InMemoryCredentialRepository();

      const weakHash = await weakHasher.hash("old_password");
      const strongHash = await strongHasher.hash("current_password");

      const weakCred = Credential.reconstitute({
        id: asId("CredentialId")("wcred"),
        userId: asId("UserId")("wuser"),
        passwordHash: weakHash,
        failedAttempts: 0,
        lockedUntil: undefined,
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
      });

      const strongCred = Credential.reconstitute({
        id: asId("CredentialId")("scred"),
        userId: asId("UserId")("suser"),
        passwordHash: strongHash,
        failedAttempts: 0,
        lockedUntil: undefined,
        createdAt: new Date("2026-01-01"),
        updatedAt: new Date("2026-01-01"),
      });

      await repo.save(weakCred);
      await repo.save(strongCred);

      const metrics = await repo.getStaleCredentialMetrics(strongHasher);

      expect(metrics.count).toBe(1);
      expect(metrics.oldestCreatedAt).toEqual(new Date("2025-01-01"));
      expect(metrics.medianCreatedAt).toEqual(new Date("2025-01-01"));
      expect(metrics.p95CreatedAt).toEqual(new Date("2025-01-01"));
    });
  });

  describe("malformed hashes", () => {
    it("treats malformed hashes as not stale (needsRehash returns false for corrupt data)", async () => {
      const repo = new InMemoryCredentialRepository();

      // A malformed hash is not a valid argon2 string, so needsRehash returns false.
      const malformedCred = Credential.reconstitute({
        id: asId("CredentialId")("corrupt"),
        userId: asId("UserId")("corruptuser"),
        passwordHash: "not-a-valid-hash",
        failedAttempts: 0,
        lockedUntil: undefined,
        createdAt: new Date("2020-01-01"),
        updatedAt: new Date("2020-01-01"),
      });

      const weakCred = Credential.reconstitute({
        id: asId("CredentialId")("wcred"),
        userId: asId("UserId")("wuser"),
        passwordHash: await weakHasher.hash("password"),
        failedAttempts: 0,
        lockedUntil: undefined,
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
      });

      await repo.save(malformedCred);
      await repo.save(weakCred);

      const metrics = await repo.getStaleCredentialMetrics(strongHasher);

      // Only the weak hash should be counted; malformed is not stale.
      expect(metrics.count).toBe(1);
      expect(metrics.oldestCreatedAt).toEqual(new Date("2025-01-01"));
    });
  });

  describe("two credentials (edge case for median)", () => {
    it("calculates median correctly for exactly 2 stale credentials", async () => {
      const repo = new InMemoryCredentialRepository();

      const hash1 = await weakHasher.hash("password1");
      const hash2 = await weakHasher.hash("password2");

      const cred1 = Credential.reconstitute({
        id: asId("CredentialId")("cred1"),
        userId: asId("UserId")("user1"),
        passwordHash: hash1,
        failedAttempts: 0,
        lockedUntil: undefined,
        createdAt: new Date("2024-01-01"),
        updatedAt: new Date("2024-01-01"),
      });

      const cred2 = Credential.reconstitute({
        id: asId("CredentialId")("cred2"),
        userId: asId("UserId")("user2"),
        passwordHash: hash2,
        failedAttempts: 0,
        lockedUntil: undefined,
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
      });

      await repo.save(cred1);
      await repo.save(cred2);

      const metrics = await repo.getStaleCredentialMetrics(strongHasher);

      expect(metrics.count).toBe(2);
      expect(metrics.oldestCreatedAt).toEqual(new Date("2024-01-01"));
      // For 2 items, median index is floor((2-1)/2) = 0, so it's the oldest.
      expect(metrics.medianCreatedAt).toEqual(new Date("2024-01-01"));
      // p95 index is floor(0.95 * 1) = 0, also the oldest.
      expect(metrics.p95CreatedAt).toEqual(new Date("2024-01-01"));
    });
  });

  describe("stale hash identification", () => {
    it("correctly identifies a hash as stale when parameters are weaker", async () => {
      // Create a hash with old/weak parameters.
      const oldHash = await weakHasher.hash("password");

      // Strong hasher should report it as needing rehash.
      expect(strongHasher.needsRehash(oldHash)).toBe(true);

      // Weak hasher should NOT report it as needing rehash (it's at weak parameters already).
      expect(weakHasher.needsRehash(oldHash)).toBe(false);
    });

    it("correctly identifies a hash as current when parameters match", async () => {
      const currentHash = await strongHasher.hash("password");

      // Strong hasher should NOT report it as needing rehash.
      expect(strongHasher.needsRehash(currentHash)).toBe(false);
    });

    it("does not report downgrade as needing rehash", async () => {
      // Create a hash with strong parameters.
      const strongHash = await strongHasher.hash("password");

      // Weak hasher should NOT report it as needing rehash (it's stronger).
      // This is the downgrade guard: we only upgrade, never downgrade.
      expect(weakHasher.needsRehash(strongHash)).toBe(false);
    });
  });
});
