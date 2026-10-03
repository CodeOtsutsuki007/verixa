import { Email, type User } from "@verixa/identity";
import { NoopRateLimiter, Result, asId } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { Argon2PasswordHasher } from "../../infrastructure/argon2-password-hasher.js";
import { InMemoryCredentialsUnitOfWork } from "../../infrastructure/testing/in-memory-credentials-unit-of-work.js";

import { ChangePassword } from "./change-password.js";
import { RegisterUserWithPassword } from "./register-user-with-password.js";

const FAST = { memoryCost: 64, timeCost: 1, parallelism: 1 };
const EMAIL = "alice@example.com";
const PASSWORD = "correct horse battery staple";
const NEW_PASSWORD = "an entirely different passphrase";
const ANOTHER_PASSWORD = "yet another password phrase";

describe("ChangePassword (Issue 071)", () => {
  let unitOfWork: InMemoryCredentialsUnitOfWork;
  let hasher: Argon2PasswordHasher;
  let rateLimiter: NoopRateLimiter;
  let changePassword: ChangePassword;
  let user: User;

  beforeEach(async () => {
    unitOfWork = new InMemoryCredentialsUnitOfWork();
    hasher = new Argon2PasswordHasher(FAST);
    rateLimiter = new NoopRateLimiter();
    changePassword = new ChangePassword(unitOfWork, hasher, rateLimiter);

    // Register a test user
    const registered = await new RegisterUserWithPassword(unitOfWork, hasher).execute({
      email: EMAIL,
      displayName: "Alice",
      password: PASSWORD,
    });
    if (!Result.isOk(registered)) throw new Error("fixture setup failed");

    const email = Email.create(EMAIL);
    if (!Result.isOk(email)) throw new Error("fixture setup failed");
    const found = await unitOfWork.repositories.users.findByEmail(email.value);
    if (found === undefined) throw new Error("fixture setup failed");
    user = found;
  });

  describe("happy path", () => {
    it("changes the password with correct current password", async () => {
      const result = await changePassword.execute({
        userId: user.id,
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
      });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;
      expect(result.value.user.id).toBe(user.id);
    });

    it("new password works for authentication afterward", async () => {
      await changePassword.execute({
        userId: user.id,
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
      });

      const credential = await unitOfWork.repositories.credentials.findByUserId(user.id);
      expect(credential).toBeDefined();
      if (credential === undefined) return;

      const matches = await hasher.verify(NEW_PASSWORD, credential.passwordHash);
      expect(matches).toBe(true);
    });

    it("old password no longer works", async () => {
      await changePassword.execute({
        userId: user.id,
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
      });

      const credential = await unitOfWork.repositories.credentials.findByUserId(user.id);
      expect(credential).toBeDefined();
      if (credential === undefined) return;

      const matches = await hasher.verify(PASSWORD, credential.passwordHash);
      expect(matches).toBe(false);
    });

    it("clears any account lockout", async () => {
      // Artificially lock the account
      const credential = await unitOfWork.repositories.credentials.findByUserId(user.id);
      if (credential === undefined) throw new Error("fixture setup failed");
      const locked = credential.recordFailedAttempt(
        { threshold: 1, baseDurationMs: 600_000, backoffFactor: 2, maxDurationMs: 600_000 },
        new Date(),
      );
      await unitOfWork.repositories.credentials.save(locked);

      await changePassword.execute({
        userId: user.id,
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
      });

      const updated = await unitOfWork.repositories.credentials.findByUserId(user.id);
      expect(updated?.failedAttempts).toBe(0);
      expect(updated?.lockedUntil).toBeUndefined();
    });
  });

  describe("re-authentication (current password)", () => {
    it("rejects wrong current password", async () => {
      const result = await changePassword.execute({
        userId: user.id,
        currentPassword: "wrong password",
        newPassword: NEW_PASSWORD,
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.fieldErrors["currentPassword"]).toContain("incorrect");
    });

    it("error message is generic for wrong current password", async () => {
      const result = await changePassword.execute({
        userId: user.id,
        currentPassword: "wrong password",
        newPassword: NEW_PASSWORD,
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.message).toContain("current password is incorrect");
    });

    it("does not change password on wrong current", async () => {
      await changePassword.execute({
        userId: user.id,
        currentPassword: "wrong password",
        newPassword: NEW_PASSWORD,
      });

      const credential = await unitOfWork.repositories.credentials.findByUserId(user.id);
      expect(credential).toBeDefined();
      if (credential === undefined) return;

      // Original password still works
      const matches = await hasher.verify(PASSWORD, credential.passwordHash);
      expect(matches).toBe(true);
    });
  });

  describe("password policy validation", () => {
    it("rejects a weak new password without changing the credential", async () => {
      const result = await changePassword.execute({
        userId: user.id,
        currentPassword: PASSWORD,
        newPassword: "short", // too short
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.fieldErrors["password"]).toContain("too_short");

      // Original password still works
      const credential = await unitOfWork.repositories.credentials.findByUserId(user.id);
      if (credential === undefined) return;
      const matches = await hasher.verify(PASSWORD, credential.passwordHash);
      expect(matches).toBe(true);
    });

    it("policy validation happens before current password verification", async () => {
      // Even with a wrong current password, weak password is rejected first
      const result = await changePassword.execute({
        userId: user.id,
        currentPassword: "wrong",
        newPassword: "short",
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      // Password error, not auth error
      expect(result.error.fieldErrors["password"]).toContain("too_short");
    });
  });

  describe("password history — reuse prevention (Issue 072)", () => {
    it("rejects reuse of current password", async () => {
      const result = await changePassword.execute({
        userId: user.id,
        currentPassword: PASSWORD,
        newPassword: PASSWORD, // same as current
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.fieldErrors["password"]).toContain("reused");
    });

    it("accepts a completely new password", async () => {
      const result = await changePassword.execute({
        userId: user.id,
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
      });

      expect(Result.isOk(result)).toBe(true);
    });

    it("rejects reuse of a password from history on second change", async () => {
      // First change: PASSWORD -> NEW_PASSWORD
      await changePassword.execute({
        userId: user.id,
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
      });

      // Second change: try to reuse the original PASSWORD
      const result = await changePassword.execute({
        userId: user.id,
        currentPassword: NEW_PASSWORD,
        newPassword: PASSWORD, // in history now
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.fieldErrors["password"]).toContain("reused");
    });

    it("allows a password when history is exhausted (more than N changes)", async () => {
      const policy = { depth: 2 };
      changePassword = new ChangePassword(unitOfWork, hasher, rateLimiter, undefined, policy);

      let current = PASSWORD;
      // Make enough changes to exhaust history beyond depth
      for (let i = 1; i <= 4; i++) {
        const next = `NewPassword${i}`;
        const result = await changePassword.execute({
          userId: user.id,
          currentPassword: current,
          newPassword: next,
        });
        expect(Result.isOk(result)).toBe(true);
        current = next;
      }

      // Now the original password should be out of history and allowed
      const result = await changePassword.execute({
        userId: user.id,
        currentPassword: current,
        newPassword: PASSWORD, // very first password, now out of history
      });

      expect(Result.isOk(result)).toBe(true);
    });

    it("maintains password history after successful change", async () => {
      await changePassword.execute({
        userId: user.id,
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
      });

      const credential = await unitOfWork.repositories.credentials.findByUserId(user.id);
      expect(credential?.passwordHistory.length).toBeGreaterThan(0);
    });

    it("error message includes history depth", async () => {
      const result = await changePassword.execute({
        userId: user.id,
        currentPassword: PASSWORD,
        newPassword: PASSWORD,
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.message).toContain("5"); // default depth
    });

    it("reuse error includes guidance", async () => {
      const result = await changePassword.execute({
        userId: user.id,
        currentPassword: PASSWORD,
        newPassword: PASSWORD,
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.message).toContain("recently used");
      expect(result.error.message).toContain("choose a password");
    });
  });

  describe("edge cases", () => {
    it("throws for unknown user (internal error)", async () => {
      await expect(
        changePassword.execute({
          userId: asId<"UserId">("00000000-0000-4000-8000-000000000099"),
          currentPassword: PASSWORD,
          newPassword: NEW_PASSWORD,
        }),
      ).rejects.toThrow();
    });

    it("throws for user with no credential (internal error)", async () => {
      // Register another user
      const registered = await new RegisterUserWithPassword(unitOfWork, hasher).execute({
        email: "bob@example.com",
        displayName: "Bob",
        password: "bob's password",
      });
      if (!Result.isOk(registered)) throw new Error("fixture setup failed");

      const email = Email.create("bob@example.com");
      if (!Result.isOk(email)) throw new Error("fixture setup failed");
      const bob = await unitOfWork.repositories.users.findByEmail(email.value);
      if (bob === undefined) throw new Error("fixture setup failed");

      // Delete the credential to simulate SSO-only account
      await unitOfWork.repositories.credentials.deleteByUserId(bob.id);

      await expect(
        changePassword.execute({
          userId: bob.id,
          currentPassword: PASSWORD,
          newPassword: NEW_PASSWORD,
        }),
      ).rejects.toThrow();
    });

    it("multiple consecutive changes work correctly", async () => {
      let current = PASSWORD;

      for (let i = 1; i <= 3; i++) {
        const next = `NewPassword${i}`;
        const result = await changePassword.execute({
          userId: user.id,
          currentPassword: current,
          newPassword: next,
        });

        expect(Result.isOk(result)).toBe(true);
        current = next;
      }

      // Final state should have new password
      const credential = await unitOfWork.repositories.credentials.findByUserId(user.id);
      if (credential === undefined) return;
      const matches = await hasher.verify(current, credential.passwordHash);
      expect(matches).toBe(true);
    });

    it("original password rejected after change", async () => {
      await changePassword.execute({
        userId: user.id,
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
      });

      // Try to change again using old password
      const result = await changePassword.execute({
        userId: user.id,
        currentPassword: PASSWORD, // old password
        newPassword: ANOTHER_PASSWORD,
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.fieldErrors["currentPassword"]).toContain("incorrect");
    });
  });
});
