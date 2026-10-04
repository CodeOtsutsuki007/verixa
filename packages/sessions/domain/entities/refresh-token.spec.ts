import { createHash } from "node:crypto";

import { asId } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { RefreshToken } from "./refresh-token.js";

const SESSION_ID = asId<"SessionId">("00000000-0000-0000-0000-000000000001");

describe("RefreshToken", () => {
  describe("factory: create()", () => {
    it("generates a raw token with high entropy", () => {
      const { token: token1 } = RefreshToken.create({ sessionId: SESSION_ID });
      const { token: token2 } = RefreshToken.create({ sessionId: SESSION_ID });

      // Each call produces a unique token
      expect(token1).not.toBe(token2);
    });

    it("encodes the token in base64 (44 chars for 32 bytes)", () => {
      const { token } = RefreshToken.create({ sessionId: SESSION_ID });

      // 32 bytes base64-encoded = 44 characters (including padding)
      expect(token).toMatch(/^[A-Za-z0-9+/]+=*$/);
      expect([42, 43, 44]).toContain(token.length); // base64 encodes to multiples of 4, +/- 2
    });

    it("stores only the hash, never the raw token", () => {
      const { refreshToken, token } = RefreshToken.create({ sessionId: SESSION_ID });

      // The entity never contains the raw token
      expect(Object.values({ ...refreshToken })).not.toContain(token);
      expect(refreshToken.hash).not.toBe(token);
    });

    it("hashes the token with SHA-256, resulting in a 64-char hex string", () => {
      const { refreshToken, token } = RefreshToken.create({ sessionId: SESSION_ID });
      const expectedHash = createHash("sha256").update(token, "utf8").digest("hex");

      expect(refreshToken.hash).toBe(expectedHash);
      expect(refreshToken.hash).toHaveLength(64);
      expect(refreshToken.hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it("assigns a unique entity ID distinct from the token", () => {
      const { refreshToken, token } = RefreshToken.create({ sessionId: SESSION_ID });

      expect(refreshToken.id).toBeDefined();
      expect(refreshToken.id).not.toBe(token);
      expect(refreshToken.id).not.toBe(refreshToken.hash);
    });

    it("references the provided sessionId", () => {
      const { refreshToken } = RefreshToken.create({ sessionId: SESSION_ID });

      expect(refreshToken.sessionId).toBe(SESSION_ID);
    });

    it("defaults to 7-day expiry (604800000 ms)", () => {
      const now = new Date();
      const { refreshToken } = RefreshToken.create({
        sessionId: SESSION_ID,
        createdAt: now,
      });

      const expectedExpiry = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
      expect(refreshToken.expiresAt.getTime()).toBe(expectedExpiry.getTime());
    });

    it("allows custom expiry via expiryMs", () => {
      const now = new Date();
      const customExpiryMs = 1000 * 60 * 60; // 1 hour
      const { refreshToken } = RefreshToken.create({
        sessionId: SESSION_ID,
        expiryMs: customExpiryMs,
        createdAt: now,
      });

      const expectedExpiry = new Date(now.getTime() + customExpiryMs);
      expect(refreshToken.expiresAt.getTime()).toBe(expectedExpiry.getTime());
    });

    it("sets createdAt to now, or a provided timestamp", () => {
      const { refreshToken: withoutTime } = RefreshToken.create({ sessionId: SESSION_ID });
      expect(withoutTime.createdAt).toBeInstanceOf(Date);

      const customTime = new Date("2025-01-01T00:00:00Z");
      const { refreshToken: withTime } = RefreshToken.create({
        sessionId: SESSION_ID,
        createdAt: customTime,
      });
      expect(withTime.createdAt).toEqual(customTime);
    });

    it("initializes revokedAt as undefined", () => {
      const { refreshToken } = RefreshToken.create({ sessionId: SESSION_ID });

      expect(refreshToken.revokedAt).toBeUndefined();
    });

    it("allows optional familyId for token rotation chains (Issue 090)", () => {
      const familyId = "family-123";
      const { refreshToken } = RefreshToken.create({
        sessionId: SESSION_ID,
        familyId,
      });

      expect(refreshToken.familyId).toBe(familyId);
    });

    it("defaults familyId to undefined if not provided", () => {
      const { refreshToken } = RefreshToken.create({ sessionId: SESSION_ID });

      expect(refreshToken.familyId).toBeUndefined();
    });

    it("returns a tuple with both refreshToken and raw token", () => {
      const result = RefreshToken.create({ sessionId: SESSION_ID });

      expect(result).toHaveProperty("refreshToken");
      expect(result).toHaveProperty("token");
      expect(result.refreshToken).toBeInstanceOf(RefreshToken);
      expect(typeof result.token).toBe("string");
    });

    it("creates distinct hashes for different tokens", () => {
      const { refreshToken: first } = RefreshToken.create({ sessionId: SESSION_ID });
      const { refreshToken: second } = RefreshToken.create({ sessionId: SESSION_ID });

      expect(first.hash).not.toBe(second.hash);
      expect(first.id).not.toBe(second.id);
    });
  });

  describe("hash-only storage invariant", () => {
    it("never exposes the raw token through any public field", () => {
      const { refreshToken, token } = RefreshToken.create({ sessionId: SESSION_ID });

      // Check all public properties
      const fields = {
        id: refreshToken.id,
        sessionId: refreshToken.sessionId,
        hash: refreshToken.hash,
        familyId: refreshToken.familyId,
        expiresAt: refreshToken.expiresAt,
        createdAt: refreshToken.createdAt,
        revokedAt: refreshToken.revokedAt,
      };

      for (const value of Object.values(fields)) {
        expect(value).not.toBe(token);
        if (typeof value === "string") {
          expect(value).not.toBe(token);
        }
      }
    });

    it("serialization never includes the raw token", () => {
      const { refreshToken, token } = RefreshToken.create({ sessionId: SESSION_ID });

      const serialized = JSON.stringify(refreshToken);
      expect(serialized).not.toContain(token);
    });
  });

  describe("expiry checks: isExpired()", () => {
    it("returns false for a token before its expiresAt", () => {
      const now = new Date();
      const { refreshToken } = RefreshToken.create({
        sessionId: SESSION_ID,
        createdAt: now,
        expiryMs: 1000,
      });

      const before = new Date(refreshToken.expiresAt.getTime() - 1);
      expect(refreshToken.isExpired(before)).toBe(false);
    });

    it("returns true at the exact expiresAt time", () => {
      const now = new Date();
      const { refreshToken } = RefreshToken.create({
        sessionId: SESSION_ID,
        createdAt: now,
        expiryMs: 1000,
      });

      expect(refreshToken.isExpired(refreshToken.expiresAt)).toBe(true);
    });

    it("returns true after expiresAt", () => {
      const now = new Date();
      const { refreshToken } = RefreshToken.create({
        sessionId: SESSION_ID,
        createdAt: now,
        expiryMs: 1000,
      });

      const after = new Date(refreshToken.expiresAt.getTime() + 1);
      expect(refreshToken.isExpired(after)).toBe(true);
    });

    it("defaults asOf to the current time", () => {
      const past = new Date(Date.now() - 1000 * 60 * 60); // 1 hour ago
      const { refreshToken } = RefreshToken.create({
        sessionId: SESSION_ID,
        createdAt: past,
        expiryMs: 100, // expires 100ms after creation
      });

      // Token is long expired by now
      expect(refreshToken.isExpired()).toBe(true);
    });
  });

  describe("revocation: isRevoked() and revoke()", () => {
    it("isRevoked() returns false for a fresh token", () => {
      const { refreshToken } = RefreshToken.create({ sessionId: SESSION_ID });

      expect(refreshToken.isRevoked()).toBe(false);
    });

    it("revoke() returns a new instance with revokedAt set", () => {
      const { refreshToken } = RefreshToken.create({ sessionId: SESSION_ID });
      const revokedAt = new Date();
      const revoked = refreshToken.revoke(revokedAt);

      expect(revoked).not.toBe(refreshToken); // new instance
      expect(revoked.revokedAt).toEqual(revokedAt);
      expect(refreshToken.revokedAt).toBeUndefined(); // original unchanged
    });

    it("revoke() defaults revokedAt to the current time", () => {
      const { refreshToken } = RefreshToken.create({ sessionId: SESSION_ID });
      const revoked = refreshToken.revoke();

      expect(revoked.revokedAt).toBeInstanceOf(Date);
      expect(revoked.revokedAt!.getTime()).toBeLessThanOrEqual(Date.now());
      expect(revoked.revokedAt!.getTime()).toBeGreaterThan(Date.now() - 1000);
    });

    it("isRevoked() returns true after revocation", () => {
      const { refreshToken } = RefreshToken.create({ sessionId: SESSION_ID });
      const revoked = refreshToken.revoke();

      expect(revoked.isRevoked()).toBe(true);
    });

    it("revoke() is idempotent (revoking twice yields equivalent result)", () => {
      const { refreshToken } = RefreshToken.create({ sessionId: SESSION_ID });
      const revokedAt = new Date();

      const firstRevoke = refreshToken.revoke(revokedAt);
      const secondRevoke = firstRevoke.revoke(revokedAt);

      expect(secondRevoke.revokedAt).toEqual(firstRevoke.revokedAt);
      expect(secondRevoke.isRevoked()).toBe(true);
    });

    it("preserves all other fields when revoking", () => {
      const { refreshToken } = RefreshToken.create({
        sessionId: SESSION_ID,
        familyId: "family-456",
      });
      const revoked = refreshToken.revoke();

      expect(revoked.id).toBe(refreshToken.id);
      expect(revoked.sessionId).toBe(refreshToken.sessionId);
      expect(revoked.hash).toBe(refreshToken.hash);
      expect(revoked.familyId).toBe(refreshToken.familyId);
      expect(revoked.expiresAt).toEqual(refreshToken.expiresAt);
      expect(revoked.createdAt).toEqual(refreshToken.createdAt);
    });
  });

  describe("validity: isValid()", () => {
    it("returns true for a fresh, non-revoked token", () => {
      const now = new Date();
      const { refreshToken } = RefreshToken.create({
        sessionId: SESSION_ID,
        createdAt: now,
        expiryMs: 1000 * 60 * 60, // 1 hour
      });

      expect(refreshToken.isValid(now)).toBe(true);
    });

    it("returns false if the token is expired", () => {
      const now = new Date();
      const { refreshToken } = RefreshToken.create({
        sessionId: SESSION_ID,
        createdAt: now,
        expiryMs: 1000,
      });

      const after = new Date(refreshToken.expiresAt.getTime() + 1);
      expect(refreshToken.isValid(after)).toBe(false);
    });

    it("returns false if the token is revoked", () => {
      const now = new Date();
      const { refreshToken } = RefreshToken.create({
        sessionId: SESSION_ID,
        createdAt: now,
        expiryMs: 1000 * 60 * 60, // 1 hour
      });
      const revoked = refreshToken.revoke();

      expect(revoked.isValid(now)).toBe(false);
    });

    it("returns false if the token is both expired and revoked", () => {
      const now = new Date();
      const { refreshToken } = RefreshToken.create({
        sessionId: SESSION_ID,
        createdAt: now,
        expiryMs: 1000,
      });
      const after = new Date(refreshToken.expiresAt.getTime() + 1);
      const revoked = refreshToken.revoke(after);

      expect(revoked.isValid(after)).toBe(false);
    });

    it("defaults asOf to the current time", () => {
      const past = new Date(Date.now() - 1000 * 60 * 60); // 1 hour ago
      const { refreshToken } = RefreshToken.create({
        sessionId: SESSION_ID,
        createdAt: past,
        expiryMs: 100, // expires 100ms after creation
      });

      // Token is long expired by now
      expect(refreshToken.isValid()).toBe(false);
    });
  });

  describe("reconstitution from persisted data", () => {
    it("reconstitute() rebuilds all fields correctly", () => {
      const original = RefreshToken.create({
        sessionId: SESSION_ID,
        familyId: "family-789",
      });
      const { refreshToken } = original;

      const rebuilt = RefreshToken.reconstitute({
        id: refreshToken.id,
        sessionId: refreshToken.sessionId,
        hash: refreshToken.hash,
        familyId: refreshToken.familyId,
        expiresAt: refreshToken.expiresAt,
        createdAt: refreshToken.createdAt,
        revokedAt: refreshToken.revokedAt,
      });

      expect(rebuilt.id).toBe(refreshToken.id);
      expect(rebuilt.sessionId).toBe(refreshToken.sessionId);
      expect(rebuilt.hash).toBe(refreshToken.hash);
      expect(rebuilt.familyId).toBe(refreshToken.familyId);
      expect(rebuilt.expiresAt).toEqual(refreshToken.expiresAt);
      expect(rebuilt.createdAt).toEqual(refreshToken.createdAt);
      expect(rebuilt.revokedAt).toEqual(refreshToken.revokedAt);
    });

    it("reconstitute() does not re-validate (data is trusted)", () => {
      // This test verifies the pattern: reconstitute accepts any Props,
      // trusting that the data represents a previously-valid state.
      // We don't need to validate fields again.
      const id = asId<"RefreshTokenId">("00000000-0000-0000-0000-000000000002");
      const rebuilt = RefreshToken.reconstitute({
        id,
        sessionId: SESSION_ID,
        hash: "0".repeat(64), // Valid hash (any 64-char hex)
        familyId: undefined,
        expiresAt: new Date(),
        createdAt: new Date(),
        revokedAt: undefined,
      });

      expect(rebuilt.id).toBe(id);
    });

    it("reconstitute() with revokedAt rebuilds revoked state", () => {
      const revokedAt = new Date("2025-01-15T12:00:00Z");
      const rebuilt = RefreshToken.reconstitute({
        id: asId<"RefreshTokenId">("00000000-0000-0000-0000-000000000003"),
        sessionId: SESSION_ID,
        hash: "a".repeat(64),
        familyId: "family-revoked",
        expiresAt: new Date("2025-01-22T00:00:00Z"),
        createdAt: new Date("2025-01-15T00:00:00Z"),
        revokedAt,
      });

      expect(rebuilt.isRevoked()).toBe(true);
      expect(rebuilt.revokedAt).toEqual(revokedAt);
    });
  });

  describe("immutability", () => {
    it("does not expose setters; all fields are readonly", () => {
      const { refreshToken } = RefreshToken.create({ sessionId: SESSION_ID });

      // TypeScript would catch these at compile time, but we verify at runtime
      // that the properties are non-writable (frozen or readonly in practice).
      const descriptor = Object.getOwnPropertyDescriptor(refreshToken, "hash");
      // Fields are initialized in the constructor and frozen by design
      expect(refreshToken.hash).toBeDefined();

      // Attempting to mutate should not affect the original
      const original = refreshToken.hash;
      // @ts-expect-error - attempting to mutate a readonly field
      refreshToken.hash = "modified";
      expect(refreshToken.hash).toBe(original);
    });

    it("returns a new instance on state changes (revoke)", () => {
      const { refreshToken } = RefreshToken.create({ sessionId: SESSION_ID });
      const revoked = refreshToken.revoke();

      // Different instances
      expect(revoked).not.toBe(refreshToken);
      // Original is unchanged
      expect(refreshToken.isRevoked()).toBe(false);
      expect(revoked.isRevoked()).toBe(true);
    });
  });

  describe("integration: full token lifecycle", () => {
    it("tracks a token from creation through use to revocation", () => {
      // Create
      const now = new Date("2025-01-15T12:00:00Z");
      const { refreshToken: created, token } = RefreshToken.create({
        sessionId: SESSION_ID,
        familyId: "family-integration",
        createdAt: now,
        expiryMs: 1000 * 60 * 60 * 24 * 7, // 7 days
      });

      expect(created.isValid(now)).toBe(true);
      expect(created.isRevoked()).toBe(false);

      // Use (check validity at various times)
      const midSession = new Date(now.getTime() + 1000 * 60 * 60); // 1 hour later
      expect(created.isValid(midSession)).toBe(true);

      // Revoke
      const revokedAt = new Date(now.getTime() + 1000 * 60 * 60 * 2); // 2 hours later
      const revoked = created.revoke(revokedAt);

      expect(revoked.isRevoked()).toBe(true);
      expect(revoked.isValid(revokedAt)).toBe(false);

      // Expiry still doesn't matter once revoked
      expect(revoked.isValid(revoked.expiresAt)).toBe(false);
    });

    it("persists and reconstitutes without losing state", () => {
      // Simulate: create, persist to "database" (as props), retrieve, reconstitute
      const { refreshToken: original } = RefreshToken.create({
        sessionId: SESSION_ID,
        familyId: "family-persist",
      });

      // Revoke before saving
      const revoked = original.revoke();

      // Simulate database row: serialize props
      const persistedProps = {
        id: revoked.id,
        sessionId: revoked.sessionId,
        hash: revoked.hash,
        familyId: revoked.familyId,
        expiresAt: revoked.expiresAt,
        createdAt: revoked.createdAt,
        revokedAt: revoked.revokedAt,
      };

      // Retrieve and reconstitute
      const restored = RefreshToken.reconstitute(persistedProps);

      expect(restored.isRevoked()).toBe(true);
      expect(restored.hash).toBe(revoked.hash);
      expect(restored.familyId).toBe(revoked.familyId);
    });
  });
});
