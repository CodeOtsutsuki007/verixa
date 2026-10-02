import { asId } from "@verixa/shared-kernel";
import { describe, expect, it, vi } from "vitest";

import { SessionExpiryPolicy } from "../value-objects/session-expiry-policy.js";
import { Session, type SessionId, type UserId } from "./session.js";

describe("Session", () => {
  const userId = asId<"UserId">("user-123");

  describe("create", () => {
    it("creates a new session with sliding policy", () => {
      const policy = SessionExpiryPolicy.sliding(3600000); // 1 hour
      const before = new Date();

      const session = Session.create({ userId, expiryPolicy: policy });

      const after = new Date();

      expect(session.id).toBeDefined();
      expect(session.userId).toBe(userId);
      expect(session.createdAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(session.createdAt.getTime()).toBeLessThanOrEqual(after.getTime());
      expect(session.lastSeenAt).toEqual(session.createdAt);
      expect(session.revokedAt).toBeUndefined();
      expect(session.expiryPolicy).toBe(policy);
      expect(session.isExpired()).toBe(false);
      expect(session.isRevoked()).toBe(false);
    });

    it("creates a new session with absolute policy", () => {
      const policy = SessionExpiryPolicy.absolute(86400000); // 1 day
      const session = Session.create({ userId, expiryPolicy: policy });

      expect(session.expiryPolicy).toBe(policy);
      expect(session.isExpired()).toBe(false);
      expect(session.isRevoked()).toBe(false);
    });

    it("sets expiresAt to createdAt + policy duration", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session = Session.create({ userId, expiryPolicy: policy });

      const expectedExpiresAt = session.createdAt.getTime() + 3600000;
      expect(session.expiresAt.getTime()).toBe(expectedExpiresAt);
    });

    it("generates a unique SessionId for each session", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session1 = Session.create({ userId, expiryPolicy: policy });
      const session2 = Session.create({ userId, expiryPolicy: policy });

      expect(session1.id).not.toBe(session2.id);
    });

    it("pulls no domain events on creation", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session = Session.create({ userId, expiryPolicy: policy });

      expect(session.pullDomainEvents()).toEqual([]);
    });
  });

  describe("reconstitute", () => {
    it("rebuilds a session from trusted data", () => {
      const sessionId = asId<"SessionId">("session-123");
      const createdAt = new Date("2024-01-15T10:00:00Z");
      const lastSeenAt = new Date("2024-01-15T11:00:00Z");
      const expiresAt = new Date("2024-01-15T13:00:00Z");
      const policy = SessionExpiryPolicy.sliding(3600000);

      const session = Session.reconstitute({
        id: sessionId,
        userId,
        createdAt,
        lastSeenAt,
        expiresAt,
        expiryPolicy: policy,
      });

      expect(session.id).toBe(sessionId);
      expect(session.userId).toBe(userId);
      expect(session.createdAt).toEqual(createdAt);
      expect(session.lastSeenAt).toEqual(lastSeenAt);
      expect(session.expiresAt).toEqual(expiresAt);
      expect(session.expiryPolicy).toBe(policy);
      expect(session.revokedAt).toBeUndefined();
    });

    it("reconstitutes a revoked session", () => {
      const revokedAt = new Date("2024-01-15T12:00:00Z");
      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date("2024-01-15T10:00:00Z"),
        lastSeenAt: new Date("2024-01-15T11:00:00Z"),
        expiresAt: new Date("2024-01-15T13:00:00Z"),
        revokedAt,
        expiryPolicy: SessionExpiryPolicy.sliding(3600000),
      });

      expect(session.revokedAt).toEqual(revokedAt);
      expect(session.isRevoked()).toBe(true);
    });

    it("pulls no domain events after reconstitution", () => {
      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date(),
        lastSeenAt: new Date(),
        expiresAt: new Date(),
        expiryPolicy: SessionExpiryPolicy.sliding(3600000),
      });

      expect(session.pullDomainEvents()).toEqual([]);
    });
  });

  describe("isExpired", () => {
    it("returns false for a session that has not yet expired", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session = Session.create({ userId, expiryPolicy: policy });

      const inFiveMinutes = new Date(new Date().getTime() + 5 * 60000);
      expect(session.isExpired(inFiveMinutes)).toBe(false);
    });

    it("returns true for a session that has expired", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session = Session.create({ userId, expiryPolicy: policy });

      const inTwoHours = new Date(new Date().getTime() + 2 * 3600000);
      expect(session.isExpired(inTwoHours)).toBe(true);
    });

    it("returns true when checked at the exact expiry moment", () => {
      const now = new Date("2024-01-15T10:00:00Z");
      const expiresAt = new Date("2024-01-15T11:00:00Z");

      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date("2024-01-15T09:00:00Z"),
        lastSeenAt: now,
        expiresAt,
        expiryPolicy: SessionExpiryPolicy.sliding(3600000),
      });

      // At the exact moment of expiry, isExpired returns true (>= comparison)
      expect(session.isExpired(expiresAt)).toBe(true);
    });

    it("returns true one millisecond before expiry", () => {
      const expiresAt = new Date("2024-01-15T11:00:00Z");
      const oneMillisecondBefore = new Date(expiresAt.getTime() - 1);

      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date("2024-01-15T09:00:00Z"),
        lastSeenAt: new Date("2024-01-15T10:00:00Z"),
        expiresAt,
        expiryPolicy: SessionExpiryPolicy.sliding(3600000),
      });

      expect(session.isExpired(oneMillisecondBefore)).toBe(false);
    });

    it("uses current time by default", () => {
      const policy = SessionExpiryPolicy.sliding(1000); // 1 second
      const session = Session.create({ userId, expiryPolicy: policy });

      // Should not be expired right now
      expect(session.isExpired()).toBe(false);
    });
  });

  describe("isRevoked", () => {
    it("returns false for a fresh session", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session = Session.create({ userId, expiryPolicy: policy });

      expect(session.isRevoked()).toBe(false);
    });

    it("returns true for a revoked session", () => {
      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date(),
        lastSeenAt: new Date(),
        expiresAt: new Date(),
        revokedAt: new Date(),
        expiryPolicy: SessionExpiryPolicy.sliding(3600000),
      });

      expect(session.isRevoked()).toBe(true);
    });
  });

  describe("revoke", () => {
    it("marks a session as revoked and returns a new instance", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session = Session.create({ userId, expiryPolicy: policy });

      const revokedSession = session.revoke();

      expect(revokedSession.isRevoked()).toBe(true);
      expect(revokedSession.revokedAt).toBeDefined();
      expect(revokedSession.revokedAt?.getTime()).toBeGreaterThanOrEqual(new Date().getTime() - 10);
    });

    it("sets revokedAt to the provided time", () => {
      const revokeTime = new Date("2024-01-15T12:00:00Z");
      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date("2024-01-15T10:00:00Z"),
        lastSeenAt: new Date("2024-01-15T11:00:00Z"),
        expiresAt: new Date("2024-01-15T13:00:00Z"),
        expiryPolicy: SessionExpiryPolicy.sliding(3600000),
      });

      const revokedSession = session.revoke(revokeTime);

      expect(revokedSession.revokedAt).toEqual(revokeTime);
    });

    it("is idempotent: revoking an already-revoked session returns the same instance", () => {
      const revokeTime1 = new Date("2024-01-15T12:00:00Z");
      const revokeTime2 = new Date("2024-01-15T12:30:00Z");

      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date("2024-01-15T10:00:00Z"),
        lastSeenAt: new Date("2024-01-15T11:00:00Z"),
        expiresAt: new Date("2024-01-15T13:00:00Z"),
        revokedAt: revokeTime1,
        expiryPolicy: SessionExpiryPolicy.sliding(3600000),
      });

      const revokedAgain = session.revoke(revokeTime2);

      // Should be the exact same instance, not a new one
      expect(revokedAgain).toBe(session);
      // Original revoke time should not change
      expect(revokedAgain.revokedAt).toEqual(revokeTime1);
    });

    it("preserves the session's other fields after revocation", () => {
      const originalSession = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date("2024-01-15T10:00:00Z"),
        lastSeenAt: new Date("2024-01-15T11:00:00Z"),
        expiresAt: new Date("2024-01-15T13:00:00Z"),
        expiryPolicy: SessionExpiryPolicy.sliding(3600000),
      });

      const revokedSession = originalSession.revoke();

      expect(revokedSession.id).toEqual(originalSession.id);
      expect(revokedSession.userId).toEqual(originalSession.userId);
      expect(revokedSession.createdAt).toEqual(originalSession.createdAt);
      expect(revokedSession.lastSeenAt).toEqual(originalSession.lastSeenAt);
      expect(revokedSession.expiresAt).toEqual(originalSession.expiresAt);
    });
  });

  describe("touch (sliding policy)", () => {
    it("updates lastSeenAt and extends expiresAt under sliding policy", () => {
      const policy = SessionExpiryPolicy.sliding(3600000); // 1 hour
      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date("2024-01-15T10:00:00Z"),
        lastSeenAt: new Date("2024-01-15T10:30:00Z"),
        expiresAt: new Date("2024-01-15T11:30:00Z"),
        expiryPolicy: policy,
      });

      const touchTime = new Date("2024-01-15T11:00:00Z");
      const touched = session.touch(touchTime);

      // lastSeenAt should be updated
      expect(touched.lastSeenAt).toEqual(touchTime);
      // expiresAt should be extended by 1 hour from touchTime
      const expectedExpiresAt = new Date("2024-01-15T12:00:00Z");
      expect(touched.expiresAt).toEqual(expectedExpiresAt);
      // Original session should be unchanged
      expect(session.lastSeenAt).toEqual(new Date("2024-01-15T10:30:00Z"));
      expect(session.expiresAt).toEqual(new Date("2024-01-15T11:30:00Z"));
    });

    it("extends expiresAt beyond its original time when touched", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date("2024-01-15T10:00:00Z"),
        lastSeenAt: new Date("2024-01-15T10:00:00Z"),
        expiresAt: new Date("2024-01-15T11:00:00Z"),
        expiryPolicy: policy,
      });

      const touchTime = new Date("2024-01-15T10:45:00Z");
      const touched = session.touch(touchTime);

      // Original expiry: 11:00, New expiry: 10:45 + 1 hour = 11:45
      expect(touched.expiresAt.getTime()).toBeGreaterThan(session.expiresAt.getTime());
    });

    it("uses current time by default", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session = Session.create({ userId, expiryPolicy: policy });

      const before = new Date();
      const touched = session.touch();
      const after = new Date();

      expect(touched.lastSeenAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(touched.lastSeenAt.getTime()).toBeLessThanOrEqual(after.getTime());
    });
  });

  describe("touch (absolute policy)", () => {
    it("updates lastSeenAt but leaves expiresAt unchanged under absolute policy", () => {
      const policy = SessionExpiryPolicy.absolute(86400000); // 1 day
      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date("2024-01-15T10:00:00Z"),
        lastSeenAt: new Date("2024-01-15T10:30:00Z"),
        expiresAt: new Date("2024-01-16T10:00:00Z"),
        expiryPolicy: policy,
      });

      const touchTime = new Date("2024-01-15T23:00:00Z");
      const touched = session.touch(touchTime);

      // lastSeenAt should be updated
      expect(touched.lastSeenAt).toEqual(touchTime);
      // expiresAt should NOT change
      expect(touched.expiresAt).toEqual(session.expiresAt);
      expect(touched.expiresAt).toEqual(new Date("2024-01-16T10:00:00Z"));
    });

    it("leaves expiresAt unchanged even when touched multiple times", () => {
      const policy = SessionExpiryPolicy.absolute(86400000);
      const originalExpiresAt = new Date("2024-01-16T10:00:00Z");
      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date("2024-01-15T10:00:00Z"),
        lastSeenAt: new Date("2024-01-15T10:00:00Z"),
        expiresAt: originalExpiresAt,
        expiryPolicy: policy,
      });

      const touch1 = session.touch(new Date("2024-01-15T12:00:00Z"));
      const touch2 = touch1.touch(new Date("2024-01-15T18:00:00Z"));
      const touch3 = touch2.touch(new Date("2024-01-15T23:59:00Z"));

      // All touches should have the same expiresAt
      expect(touch1.expiresAt).toEqual(originalExpiresAt);
      expect(touch2.expiresAt).toEqual(originalExpiresAt);
      expect(touch3.expiresAt).toEqual(originalExpiresAt);
    });
  });

  describe("touch with revoked sessions", () => {
    it("is a no-op on a revoked session (returns same instance)", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date("2024-01-15T10:00:00Z"),
        lastSeenAt: new Date("2024-01-15T10:00:00Z"),
        expiresAt: new Date("2024-01-15T11:00:00Z"),
        revokedAt: new Date("2024-01-15T10:30:00Z"),
        expiryPolicy: policy,
      });

      const touched = session.touch(new Date("2024-01-15T10:45:00Z"));

      // Should return the same instance
      expect(touched).toBe(session);
      // Nothing should change
      expect(touched.lastSeenAt).toEqual(session.lastSeenAt);
      expect(touched.expiresAt).toEqual(session.expiresAt);
    });

    it("prevents revoked sessions from being reactivated by touch", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const revokedAt = new Date("2024-01-15T10:30:00Z");
      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt: new Date("2024-01-15T10:00:00Z"),
        lastSeenAt: new Date("2024-01-15T10:00:00Z"),
        expiresAt: new Date("2024-01-15T11:00:00Z"),
        revokedAt,
        expiryPolicy: policy,
      });

      const touched = session.touch(new Date("2024-01-15T10:45:00Z"));

      // Should still be revoked
      expect(touched.isRevoked()).toBe(true);
      expect(touched.revokedAt).toEqual(revokedAt);
    });
  });

  describe("immutability", () => {
    it("does not modify the original session when calling touch", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session = Session.create({ userId, expiryPolicy: policy });

      const originalLastSeenAt = session.lastSeenAt;
      const originalExpiresAt = session.expiresAt;

      session.touch();

      expect(session.lastSeenAt).toEqual(originalLastSeenAt);
      expect(session.expiresAt).toEqual(originalExpiresAt);
    });

    it("does not modify the original session when calling revoke", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session = Session.create({ userId, expiryPolicy: policy });

      expect(session.isRevoked()).toBe(false);

      session.revoke();

      expect(session.isRevoked()).toBe(false);
    });
  });

  describe("edge cases", () => {
    it("handles sessions created and touched in rapid succession", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session = Session.create({ userId, expiryPolicy: policy });

      const touched1 = session.touch();
      const touched2 = touched1.touch();
      const touched3 = touched2.touch();

      // Each touch should extend expiry further
      expect(touched1.expiresAt.getTime()).toBeGreaterThan(session.expiresAt.getTime());
      expect(touched2.expiresAt.getTime()).toBeGreaterThan(touched1.expiresAt.getTime());
      expect(touched3.expiresAt.getTime()).toBeGreaterThan(touched2.expiresAt.getTime());
    });

    it("handles sessions that are revoked and then conceptually touched", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const session = Session.create({ userId, expiryPolicy: policy });

      const revoked = session.revoke(new Date("2024-01-15T11:00:00Z"));
      const touchedAfterRevoke = revoked.touch(new Date("2024-01-15T11:30:00Z"));

      // touch() on a revoked session is idempotent
      expect(touchedAfterRevoke).toBe(revoked);
      expect(touchedAfterRevoke.isRevoked()).toBe(true);
    });

    it("correctly handles sessions with microsecond-precision timestamps", () => {
      const createdAt = new Date("2024-01-15T10:00:00.123Z");
      const lastSeenAt = new Date("2024-01-15T10:30:45.456Z");
      const expiresAt = new Date("2024-01-15T11:30:45.456Z");

      const session = Session.reconstitute({
        id: asId<"SessionId">("session-123"),
        userId,
        createdAt,
        lastSeenAt,
        expiresAt,
        expiryPolicy: SessionExpiryPolicy.sliding(3600000),
      });

      expect(session.createdAt).toEqual(createdAt);
      expect(session.lastSeenAt).toEqual(lastSeenAt);
      expect(session.expiresAt).toEqual(expiresAt);
import { describe, expect, it } from "vitest";

import { Session, type SessionUserId } from "./session.js";

const userId: SessionUserId = asId("11111111-1111-1111-1111-111111111111");

function accessToken(now: Date) {
  return { tokenId: "token-1", expiresAt: new Date(now.getTime() + 60_000) };
}

describe("Session", () => {
  describe("issue", () => {
    it("captures the metadata seen at login as the first history entry", () => {
      const now = new Date("2026-01-01T00:00:00Z");
      const metadata = { ipAddress: "203.0.113.10", userAgent: "curl/8.0", deviceLabel: "CLI" };

      const { session, rawRefreshToken } = Session.issue({
        userId,
        metadata,
        accessToken: accessToken(now),
        now,
      });

      expect(session.metadataHistory).toHaveLength(1);
      expect(session.metadataHistory[0]!.metadata).toEqual(metadata);
      expect(session.metadataHistory[0]!.recordedAt).toEqual(now);
      expect(session.currentMetadata).toEqual(metadata);
      expect(session.createdAt).toEqual(now);
      expect(session.lastActiveAt).toEqual(now);
      expect(session.isRevoked).toBe(false);
      expect(rawRefreshToken).toHaveLength(43); // 32 bytes, base64url
    });

    it("issues a session whose refresh token can be verified but no other string matches", () => {
      const now = new Date();
      const { session, rawRefreshToken } = Session.issue({
        userId,
        metadata: {},
        accessToken: accessToken(now),
        now,
      });

      expect(session.matchesRefreshToken(rawRefreshToken)).toBe(true);
      expect(session.matchesRefreshToken("not-the-token")).toBe(false);
    });

    it("defaults to a 30-day expiry from issuance", () => {
      const now = new Date("2026-01-01T00:00:00Z");
      const { session } = Session.issue({
        userId,
        metadata: {},
        accessToken: accessToken(now),
        now,
      });

      expect(session.expiresAt.getTime() - now.getTime()).toBe(30 * 24 * 60 * 60 * 1000);
    });
  });

  describe("recordActivity", () => {
    it("appends a new metadata observation when the presented metadata changed", () => {
      const now = new Date("2026-01-01T00:00:00Z");
      const { session } = Session.issue({
        userId,
        metadata: { ipAddress: "203.0.113.10" },
        accessToken: accessToken(now),
        now,
      });

      const later = new Date(now.getTime() + 60_000);
      const refreshed = session.recordActivity({
        metadata: { ipAddress: "198.51.100.20" },
        accessToken: { tokenId: "token-2", expiresAt: new Date(later.getTime() + 60_000) },
        now: later,
      });

      expect(refreshed.metadataHistory).toHaveLength(2);
      expect(refreshed.metadataHistory[1]!.metadata).toEqual({ ipAddress: "198.51.100.20" });
      expect(refreshed.metadataHistory[1]!.recordedAt).toEqual(later);
      expect(refreshed.currentMetadata).toEqual({ ipAddress: "198.51.100.20" });
      // The original observation survives — it is not overwritten.
      expect(refreshed.metadataHistory[0]!.metadata).toEqual({ ipAddress: "203.0.113.10" });
    });

    it("does not append a new observation when the presented metadata is unchanged", () => {
      const now = new Date("2026-01-01T00:00:00Z");
      const metadata = { ipAddress: "203.0.113.10", userAgent: "curl/8.0" };
      const { session } = Session.issue({ userId, metadata, accessToken: accessToken(now), now });

      const later = new Date(now.getTime() + 60_000);
      const refreshed = session.recordActivity({
        metadata,
        accessToken: { tokenId: "token-2", expiresAt: new Date(later.getTime() + 60_000) },
        now: later,
      });

      expect(refreshed.metadataHistory).toHaveLength(1);
      // Activity is still bumped even without a new observation.
      expect(refreshed.lastActiveAt).toEqual(later);
    });

    it("always updates the current access token, whether or not metadata changed", () => {
      const now = new Date();
      const { session } = Session.issue({
        userId,
        metadata: {},
        accessToken: accessToken(now),
        now,
      });

      const refreshed = session.recordActivity({
        metadata: {},
        accessToken: { tokenId: "token-2", expiresAt: new Date(now.getTime() + 120_000) },
        now,
      });

      expect(refreshed.currentAccessToken!.tokenId).toBe("token-2");
    });
  });

  describe("revoke", () => {
    it("marks the session revoked and inactive", () => {
      const now = new Date();
      const { session } = Session.issue({
        userId,
        metadata: {},
        accessToken: accessToken(now),
        now,
      });

      const revoked = session.revoke(now);

      expect(revoked.isRevoked).toBe(true);
      expect(revoked.isActiveAt(now)).toBe(false);
    });

    it("is idempotent: revoking an already-revoked session keeps the original timestamp", () => {
      const firstRevocation = new Date("2026-01-01T00:00:00Z");
      const now = new Date();
      const { session } = Session.issue({
        userId,
        metadata: {},
        accessToken: accessToken(now),
        now,
      });

      const revokedOnce = session.revoke(firstRevocation);
      const revokedAgain = revokedOnce.revoke(new Date("2026-06-01T00:00:00Z"));

      expect(revokedAgain.revokedAt).toEqual(firstRevocation);
    });
  });

  describe("isActiveAt", () => {
    it("is inactive once expired, even if never revoked", () => {
      const now = new Date("2026-01-01T00:00:00Z");
      const { session } = Session.issue({
        userId,
        metadata: {},
        accessToken: accessToken(now),
        ttlMs: 1000,
        now,
      });

      expect(session.isActiveAt(new Date(now.getTime() + 500))).toBe(true);
      expect(session.isActiveAt(new Date(now.getTime() + 1000))).toBe(false);
    });
  });

  describe("reconstitute", () => {
    it("rebuilds a session from stored props without going through issue", () => {
      const now = new Date("2026-01-01T00:00:00Z");
      const { session: issued } = Session.issue({
        userId,
        metadata: { deviceLabel: "iPhone" },
        accessToken: accessToken(now),
        now,
      });

      const rebuilt = Session.reconstitute({ ...issued });

      expect(rebuilt.id).toBe(issued.id);
      expect(rebuilt.currentMetadata).toEqual({ deviceLabel: "iPhone" });
    });
  });

  describe("toJSON", () => {
    it("redacts the refresh token hash", () => {
      const now = new Date();
      const { session } = Session.issue({
        userId,
        metadata: {},
        accessToken: accessToken(now),
        now,
      });

      const serialized = session.toJSON();

      expect(serialized["refreshTokenHash"]).toBe("[REDACTED]");
    });
  });
});
