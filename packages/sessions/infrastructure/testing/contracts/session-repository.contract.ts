import { describe, expect, it } from "vitest";

import type { SessionRepository } from "../../../application/ports/session-repository.js";
import { Session, type SessionId, type UserId } from "../../../domain/entities/session.js";
import { SessionExpiryPolicy } from "../../../domain/value-objects/session-expiry-policy.js";
import { createId } from "@verixa/shared-kernel";

function makeUserId(): UserId {
  return createId<"UserId">();
}

function makeSession(userId: UserId): Session {
  const expiryPolicy = SessionExpiryPolicy.sliding(3600 * 1000); // 1 hour
  return Session.create({ userId, expiryPolicy });
}

/**
 * Behavioral contract every `SessionRepository` implementation must satisfy —
 * run against `InMemorySessionRepository` today and, once it exists, the
 * Postgres or Redis-backed adapter from Phase 05, via the same test bodies.
 * This is **contract testing**: one shared suite, multiple implementations,
 * each proven to behave identically rather than merely "compile against the
 * same interface." See `docs/guides/testing.md`.
 */
export function sessionRepositoryContract(createRepository: () => SessionRepository): void {
  describe("SessionRepository contract", () => {
    it("returns undefined for a session that was never saved", async () => {
      const repository = createRepository();
      const userId = makeUserId();
      const session = makeSession(userId);

      const found = await repository.findById(session.id);

      expect(found).toBeUndefined();
    });

    it("finds a saved session by id", async () => {
      const repository = createRepository();
      const userId = makeUserId();
      const session = makeSession(userId);

      await repository.save(session);

      const found = await repository.findById(session.id);

      // Asserts equality of state, not object identity (same reasoning as
      // UserRepository: a real adapter will reconstruct the instance from
      // storage, never returning the exact object instance it was given).
      expect(found?.id).toBe(session.id);
      expect(found?.userId).toBe(session.userId);
      expect(found?.createdAt).toEqual(session.createdAt);
      expect(found?.lastSeenAt).toEqual(session.lastSeenAt);
      expect(found?.expiresAt).toEqual(session.expiresAt);
      expect(found?.revokedAt).toEqual(session.revokedAt);
      expect(found?.isRevoked()).toBe(session.isRevoked());
      expect(found?.isExpired()).toBe(session.isExpired());
    });

    it("save is an idempotent upsert", async () => {
      const repository = createRepository();
      const userId = makeUserId();
      const session = makeSession(userId);

      await repository.save(session);

      // Touch the session to update its state.
      const touched = session.touch();
      await repository.save(touched);

      const found = await repository.findById(session.id);

      // The updated state should be persisted.
      expect(found?.lastSeenAt).toEqual(touched.lastSeenAt);
      expect(found?.expiresAt).toEqual(touched.expiresAt);
    });

    it("returns empty array when a user has no active sessions", async () => {
      const repository = createRepository();
      const userId = makeUserId();

      const active = await repository.findActiveByUserId(userId);

      expect(active).toEqual([]);
    });

    it("finds active sessions for a user", async () => {
      const repository = createRepository();
      const userId = makeUserId();
      const session1 = makeSession(userId);
      const session2 = makeSession(userId);

      await repository.save(session1);
      await repository.save(session2);

      const active = await repository.findActiveByUserId(userId);

      expect(active).toHaveLength(2);
      expect(active.map((s) => s.id)).toContain(session1.id);
      expect(active.map((s) => s.id)).toContain(session2.id);
    });

    it("excludes revoked sessions from findActiveByUserId", async () => {
      const repository = createRepository();
      const userId = makeUserId();
      const session1 = makeSession(userId);
      const session2 = makeSession(userId);

      await repository.save(session1);
      await repository.save(session2);

      // Revoke one session.
      await repository.revoke(session1.id);

      const active = await repository.findActiveByUserId(userId);

      expect(active).toHaveLength(1);
      expect(active[0]?.id).toBe(session2.id);
    });

    it("excludes expired sessions from findActiveByUserId", async () => {
      const repository = createRepository();
      const userId = makeUserId();
      // Create a session that expires immediately (duration = 0).
      // We'll create it with a past expiry time instead.
      const now = new Date();
      const pastDate = new Date(now.getTime() - 1000); // 1 second in the past
      const expiryPolicy = SessionExpiryPolicy.sliding(1000);
      const session = Session.reconstitute({
        id: createId<"SessionId">(),
        userId,
        createdAt: new Date(pastDate.getTime() - 10000),
        lastSeenAt: new Date(pastDate.getTime() - 5000),
        expiresAt: pastDate, // Expired
        expiryPolicy,
      });

      await repository.save(session);

      const active = await repository.findActiveByUserId(userId);

      expect(active).toEqual([]);
    });

    it("orders findActiveByUserId results by lastSeenAt descending", async () => {
      const repository = createRepository();
      const userId = makeUserId();
      const now = new Date();

      // Create three sessions with different lastSeenAt times.
      const expiryPolicy = SessionExpiryPolicy.sliding(3600 * 1000);
      const session1 = Session.reconstitute({
        id: createId<"SessionId">(),
        userId,
        createdAt: new Date(now.getTime() - 3000),
        lastSeenAt: new Date(now.getTime() - 3000),
        expiresAt: new Date(now.getTime() + 3600 * 1000),
        expiryPolicy,
      });

      const session2 = Session.reconstitute({
        id: createId<"SessionId">(),
        userId,
        createdAt: new Date(now.getTime() - 2000),
        lastSeenAt: new Date(now.getTime() - 2000),
        expiresAt: new Date(now.getTime() + 3600 * 1000),
        expiryPolicy,
      });

      const session3 = Session.reconstitute({
        id: createId<"SessionId">(),
        userId,
        createdAt: new Date(now.getTime() - 1000),
        lastSeenAt: new Date(now.getTime() - 1000),
        expiresAt: new Date(now.getTime() + 3600 * 1000),
        expiryPolicy,
      });

      await repository.save(session1);
      await repository.save(session2);
      await repository.save(session3);

      const active = await repository.findActiveByUserId(userId);

      // Should be ordered with session3 first (most recently active).
      expect(active[0]?.id).toBe(session3.id);
      expect(active[1]?.id).toBe(session2.id);
      expect(active[2]?.id).toBe(session1.id);
    });

    it("revoke is idempotent", async () => {
      const repository = createRepository();
      const userId = makeUserId();
      const session = makeSession(userId);

      await repository.save(session);
      await repository.revoke(session.id);
      await repository.revoke(session.id); // Second revoke should be a no-op.

      const found = await repository.findById(session.id);

      expect(found?.isRevoked()).toBe(true);
    });

    it("revoking a non-existent session is a silent no-op", async () => {
      const repository = createRepository();
      const fakeSessionId = createId<"SessionId">();

      // Should not throw.
      await expect(repository.revoke(fakeSessionId)).resolves.toBeUndefined();
    });

    it("revokeAllForUser marks all sessions for that user as revoked", async () => {
      const repository = createRepository();
      const userId = makeUserId();
      const session1 = makeSession(userId);
      const session2 = makeSession(userId);

      await repository.save(session1);
      await repository.save(session2);

      await repository.revokeAllForUser(userId);

      const found1 = await repository.findById(session1.id);
      const found2 = await repository.findById(session2.id);

      expect(found1?.isRevoked()).toBe(true);
      expect(found2?.isRevoked()).toBe(true);
    });

    it("revokeAllForUser does not affect other users' sessions", async () => {
      const repository = createRepository();
      const user1Id = makeUserId();
      const user2Id = makeUserId();
      const user1Session = makeSession(user1Id);
      const user2Session = makeSession(user2Id);

      await repository.save(user1Session);
      await repository.save(user2Session);

      await repository.revokeAllForUser(user1Id);

      const user1Found = await repository.findById(user1Session.id);
      const user2Found = await repository.findById(user2Session.id);

      expect(user1Found?.isRevoked()).toBe(true);
      expect(user2Found?.isRevoked()).toBe(false);
    });

    it("revokeAllForUser for a user with no sessions is a silent no-op", async () => {
      const repository = createRepository();
      const userId = makeUserId();

      // Should not throw.
      await expect(repository.revokeAllForUser(userId)).resolves.toBeUndefined();
    });

    it("revokeAllForUser still revokes already-revoked sessions", async () => {
      const repository = createRepository();
      const userId = makeUserId();
      const session1 = makeSession(userId);
      const session2 = makeSession(userId);

      await repository.save(session1);
      await repository.save(session2);

      // Revoke session1 individually.
      await repository.revoke(session1.id);

      // Now revoke all for the user.
      await repository.revokeAllForUser(userId);

      const found1 = await repository.findById(session1.id);
      const found2 = await repository.findById(session2.id);

      // Both should be revoked (session1 was already revoked, session2 is newly revoked).
      expect(found1?.isRevoked()).toBe(true);
      expect(found2?.isRevoked()).toBe(true);
    });

    it("after revokeAllForUser, findActiveByUserId returns an empty array", async () => {
      const repository = createRepository();
      const userId = makeUserId();
      const session1 = makeSession(userId);
      const session2 = makeSession(userId);

      await repository.save(session1);
      await repository.save(session2);

      await repository.revokeAllForUser(userId);

      const active = await repository.findActiveByUserId(userId);

      expect(active).toEqual([]);
    });
  });
}
