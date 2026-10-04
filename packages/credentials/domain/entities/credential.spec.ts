import { inspect } from "node:util";

import { asId } from "@verixa/shared-kernel";
import { describe, expect, it, beforeEach } from "vitest";

import { Argon2PasswordHasher } from "../../infrastructure/argon2-password-hasher.js";
import { DEFAULT_PASSWORD_HISTORY_POLICY } from "../value-objects/password-history-policy.js";

import { Credential } from "./credential.js";

const USER_ID = asId<"UserId">("00000000-0000-4000-8000-000000000001");
const HASH = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g";

describe("Credential", () => {
  it("is created from an already-hashed password", () => {
    const credential = Credential.create({ userId: USER_ID, passwordHash: HASH });

    expect(credential.userId).toBe(USER_ID);
    expect(credential.passwordHash).toBe(HASH);
    expect(credential.id).toBeDefined();
    expect(credential.createdAt).toEqual(credential.updatedAt);
  });

  it("offers no way to construct one from a plaintext password", () => {
    // Asserted as a type-level fact rather than a runtime one: there is no
    // overload taking a RawPassword, so the aggregate cannot hash — and
    // therefore cannot hash wrongly or store a plaintext by mistake.
    // @ts-expect-error — create() accepts a hash, never a raw password.
    Credential.create({ userId: USER_ID, password: "correct horse battery staple" });

    expect(Object.keys(Credential)).not.toContain("fromPlaintext");
  });

  it("replaces the hash and bumps updatedAt", async () => {
    const original = Credential.create({ userId: USER_ID, passwordHash: HASH });
    await new Promise((resolve) => setTimeout(resolve, 5));

    const rotated = original.withPasswordHash("$argon2id$v=19$m=65536,t=3,p=1$bmV3$bmV3aGFzaA");

    expect(rotated.passwordHash).not.toBe(HASH);
    expect(rotated.id).toBe(original.id);
    expect(rotated.createdAt).toEqual(original.createdAt);
    expect(rotated.updatedAt.getTime()).toBeGreaterThan(original.updatedAt.getTime());
  });

  it("reconstitutes from trusted data", () => {
    const now = new Date();
    const rebuilt = Credential.reconstitute({
      id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000aa"),
      userId: USER_ID,
      passwordHash: HASH,
      failedAttempts: 0,
      lockedUntil: undefined,
      passwordHistory: [],
      createdAt: now,
      updatedAt: now,
    });

    expect(rebuilt.passwordHash).toBe(HASH);
    expect(rebuilt.passwordHistory).toEqual([]);
  });

  describe("hash redaction", () => {
    // A hash is less damaging than a plaintext but not harmless: leaked, it
    // can be ground offline at the attacker's pace against a target they now
    // know exists. It does not belong in a log line or an API response.

    it("redacts the hash under JSON.stringify", () => {
      const credential = Credential.create({ userId: USER_ID, passwordHash: HASH });

      expect(JSON.stringify(credential)).not.toContain(HASH);
      expect(JSON.stringify({ credential })).not.toContain(HASH);
    });

    it("redacts the hash under util.inspect", () => {
      const credential = Credential.create({ userId: USER_ID, passwordHash: HASH });

      expect(inspect(credential)).not.toContain(HASH);
      expect(inspect({ nested: { credential } }, { depth: 5 })).not.toContain(HASH);
    });

    it("still exposes the hash as a property, since verification needs it", () => {
      const credential = Credential.create({ userId: USER_ID, passwordHash: HASH });

      // Redaction covers accidental serialization, not deliberate access:
      // authentication genuinely has to read this to verify against it.
      expect(credential.passwordHash).toBe(HASH);
    });
  });

  describe("password history — isPasswordReused (Issue 072)", () => {
    // Use fast parameters for testing; production uses OWASP defaults
    const FAST = { memoryCost: 64, timeCost: 1, parallelism: 1 };
    let hasher: Argon2PasswordHasher;
    let hashA: string;
    let hashB: string;

    beforeEach(async () => {
      hasher = new Argon2PasswordHasher(FAST);
      [hashA, hashB] = await Promise.all([hasher.hash("PasswordA1!"), hasher.hash("PasswordB2!")]);
    });

    it("returns true when candidate matches current password", async () => {
      const credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashA,
        failedAttempts: 0,
        lockedUntil: undefined,
        passwordHistory: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const reused = await credential.isPasswordReused("PasswordA1!", (plain, hash) =>
        hasher.verify(plain, hash),
      );

      expect(reused).toBe(true);
    });

    it("returns true when candidate matches a password in history", async () => {
      const credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashB,
        failedAttempts: 0,
        lockedUntil: undefined,
        passwordHistory: [hashA],
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const reused = await credential.isPasswordReused("PasswordA1!", (plain, hash) =>
        hasher.verify(plain, hash),
      );

      expect(reused).toBe(true);
    });

    it("returns false when candidate does not match current or history", async () => {
      const credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashA,
        failedAttempts: 0,
        lockedUntil: undefined,
        passwordHistory: [hashB],
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const reused = await credential.isPasswordReused("PasswordC3!", (plain, hash) =>
        hasher.verify(plain, hash),
      );

      expect(reused).toBe(false);
    });

    it("returns false when history is empty and candidate is not current", async () => {
      const credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashA,
        failedAttempts: 0,
        lockedUntil: undefined,
        passwordHistory: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const reused = await credential.isPasswordReused("PasswordB2!", (plain, hash) =>
        hasher.verify(plain, hash),
      );

      expect(reused).toBe(false);
    });

    it("checks all N entries in password history (short-circuits on match)", async () => {
      // Create 5 hashes (the default history depth)
      const hashes = await Promise.all(
        Array.from({ length: 5 }, (_, i) => hasher.hash(`OldPassword${i}!`)),
      );

      const credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashA,
        failedAttempts: 0,
        lockedUntil: undefined,
        passwordHistory: hashes,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      // Last entry in history should be detected
      const reused = await credential.isPasswordReused("OldPassword4!", (plain, hash) =>
        hasher.verify(plain, hash),
      );

      expect(reused).toBe(true);
    });

    it("rejects candidate that matches middle entry of history", async () => {
      const hashes = await Promise.all(
        Array.from({ length: 3 }, (_, i) => hasher.hash(`OldPassword${i}!`)),
      );

      const credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashA,
        failedAttempts: 0,
        lockedUntil: undefined,
        passwordHistory: hashes,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      // Middle entry
      const reused = await credential.isPasswordReused("OldPassword1!", (plain, hash) =>
        hasher.verify(plain, hash),
      );

      expect(reused).toBe(true);
    });

    it("returns false for case-sensitive password mismatch", async () => {
      const credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashA,
        failedAttempts: 0,
        lockedUntil: undefined,
        passwordHistory: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const reused = await credential.isPasswordReused(
        "passworda1!", // lowercase 'p' differs
        (plain, hash) => hasher.verify(plain, hash),
      );

      expect(reused).toBe(false);
    });
  });

  describe("password history — rotatePassword (Issue 072)", () => {
    const FAST = { memoryCost: 64, timeCost: 1, parallelism: 1 };
    let hasher: Argon2PasswordHasher;
    let hashA: string;
    let hashB: string;
    let hashC: string;

    beforeEach(async () => {
      hasher = new Argon2PasswordHasher(FAST);
      [hashA, hashB, hashC] = await Promise.all([
        hasher.hash("PasswordA1!"),
        hasher.hash("PasswordB2!"),
        hasher.hash("PasswordC3!"),
      ]);
    });

    it("sets new passwordHash", () => {
      const credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashA,
        failedAttempts: 0,
        lockedUntil: undefined,
        passwordHistory: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const rotated = credential.rotatePassword(hashB, DEFAULT_PASSWORD_HISTORY_POLICY);

      expect(rotated.passwordHash).toBe(hashB);
    });

    it("pushes old password to front of history", () => {
      const credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashA,
        failedAttempts: 0,
        lockedUntil: undefined,
        passwordHistory: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const rotated = credential.rotatePassword(hashB, DEFAULT_PASSWORD_HISTORY_POLICY);

      expect(rotated.passwordHistory[0]).toBe(hashA);
    });

    it("preserves existing history entries (in order)", () => {
      const credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashB,
        failedAttempts: 0,
        lockedUntil: undefined,
        passwordHistory: [hashA],
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const rotated = credential.rotatePassword(hashC, DEFAULT_PASSWORD_HISTORY_POLICY);

      // After rotation: [hashB, hashA]
      expect(rotated.passwordHistory).toContain(hashA);
      expect(rotated.passwordHistory).toContain(hashB);
      expect(rotated.passwordHistory[0]).toBe(hashB); // most recent first
    });

    it("caps history at policy depth", async () => {
      let credential = Credential.create({ userId: USER_ID, passwordHash: hashA });
      const policy = { depth: 3 };

      // Rotate N+2 times (4 times with depth 3)
      for (let i = 0; i < 4; i++) {
        const newHash = await hasher.hash(`Password${i}!`);
        credential = credential.rotatePassword(newHash, policy);
      }

      expect(credential.passwordHistory.length).toBeLessThanOrEqual(policy.depth);
    });

    it("history length is exactly N after N+1 rotations", () => {
      let credential = Credential.create({ userId: USER_ID, passwordHash: hashA });
      const policy = { depth: 5 };

      // Rotate 6 times (depth + 1)
      const hashes: string[] = [];
      for (let i = 0; i <= policy.depth; i++) {
        hashes.push(`$argon2id$v=19$m=64,t=1,p=1$salt${i}$hash${i}`);
      }

      for (const hash of hashes.slice(0, -1)) {
        credential = credential.rotatePassword(hash, policy);
      }

      expect(credential.passwordHistory.length).toBe(policy.depth);
    });

    it("most recent previous password is at index 0", () => {
      let credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashA,
        failedAttempts: 0,
        lockedUntil: undefined,
        passwordHistory: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      credential = credential.rotatePassword(hashB, DEFAULT_PASSWORD_HISTORY_POLICY);
      credential = credential.rotatePassword(hashC, DEFAULT_PASSWORD_HISTORY_POLICY);

      // After two rotations: history = [hashB, hashA]
      expect(credential.passwordHistory[0]).toBe(hashB);
      expect(credential.passwordHistory[1]).toBe(hashA);
    });

    it("oldest password is dropped when cap exceeded", () => {
      let credential = Credential.create({ userId: USER_ID, passwordHash: hashA });
      const policy = { depth: 2 };
      const firstHash = hashA;

      // Add more than N entries
      credential = credential.rotatePassword(hashB, policy);
      credential = credential.rotatePassword(hashC, policy);
      credential = credential.rotatePassword("$argon2id$v=19$m=64,t=1,p=1$salt$hash4", policy);

      // firstHash should be dropped
      expect(credential.passwordHistory).not.toContain(firstHash);
      expect(credential.passwordHistory.length).toBe(policy.depth);
    });

    it("clears failedAttempts and lockedUntil when rotating", () => {
      const credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashA,
        failedAttempts: 5,
        lockedUntil: new Date(Date.now() + 600_000),
        passwordHistory: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const rotated = credential.rotatePassword(hashB, DEFAULT_PASSWORD_HISTORY_POLICY);

      expect(rotated.failedAttempts).toBe(0);
      expect(rotated.lockedUntil).toBeUndefined();
    });

    it("returns a new Credential instance (immutable)", () => {
      const credential = Credential.create({ userId: USER_ID, passwordHash: hashA });
      const rotated = credential.rotatePassword(hashB, DEFAULT_PASSWORD_HISTORY_POLICY);

      // Same id but different object
      expect(rotated.id).toBe(credential.id);
      expect(rotated).not.toBe(credential);
      // Original unchanged
      expect(credential.passwordHash).toBe(hashA);
      expect(credential.passwordHistory).toEqual([]);
    });

    it("bumps updatedAt when rotating", async () => {
      const credential = Credential.create({ userId: USER_ID, passwordHash: hashA });
      await new Promise((resolve) => setTimeout(resolve, 5));

      const rotated = credential.rotatePassword(hashB, DEFAULT_PASSWORD_HISTORY_POLICY);

      expect(rotated.updatedAt.getTime()).toBeGreaterThan(credential.updatedAt.getTime());
    });
  });

  describe("integration — withPasswordHash vs rotatePassword", () => {
    const FAST = { memoryCost: 64, timeCost: 1, parallelism: 1 };
    let hasher: Argon2PasswordHasher;
    let hashA: string;
    let hashB: string;

    beforeEach(async () => {
      hasher = new Argon2PasswordHasher(FAST);
      [hashA, hashB] = await Promise.all([hasher.hash("PasswordA1!"), hasher.hash("PasswordB2!")]);
    });

    it("withPasswordHash does not maintain history (for rehashing)", () => {
      const credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashA,
        failedAttempts: 0,
        lockedUntil: undefined,
        passwordHistory: ["old-hash"],
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      // withPasswordHash is for transparent rehashing (Issue 073), not
      // password changes — history is NOT updated
      const rehashed = credential.withPasswordHash(hashB);

      expect(rehashed.passwordHash).toBe(hashB);
      expect(rehashed.passwordHistory).toEqual(["old-hash"]); // unchanged
    });

    it("rotatePassword maintains history (for password changes)", () => {
      const credential = Credential.reconstitute({
        id: asId<"CredentialId">("00000000-0000-4000-8000-0000000000bb"),
        userId: USER_ID,
        passwordHash: hashA,
        failedAttempts: 0,
        lockedUntil: undefined,
        passwordHistory: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const rotated = credential.rotatePassword(hashB, DEFAULT_PASSWORD_HISTORY_POLICY);

      expect(rotated.passwordHash).toBe(hashB);
      expect(rotated.passwordHistory).toContain(hashA); // old one moved to history
    });
  });
});
