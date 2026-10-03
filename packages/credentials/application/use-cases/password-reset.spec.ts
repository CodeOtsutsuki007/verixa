import { Email, type User } from "@verixa/identity";
import { Result } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { PasswordResetToken } from "../../domain/entities/password-reset-token.js";
import { Argon2PasswordHasher } from "../../infrastructure/argon2-password-hasher.js";
import { InMemoryCredentialsUnitOfWork } from "../../infrastructure/testing/in-memory-credentials-unit-of-work.js";
import { InMemoryPasswordResetTokenRepository } from "../../infrastructure/testing/in-memory-verification-token-repositories.js";
import type { CredentialNotifier } from "../ports/credential-notifier.js";
import type { SessionRevoker } from "../ports/session-revoker.js";

import { AuthenticateWithPassword } from "./authenticate-with-password.js";
import { ConfirmPasswordReset } from "./confirm-password-reset.js";
import { RegisterUserWithPassword } from "./register-user-with-password.js";
import { RequestPasswordReset } from "./request-password-reset.js";

const FAST = { memoryCost: 64, timeCost: 1, parallelism: 1 };
const EMAIL = "alice@example.com";
const PASSWORD = "correct horse battery staple";
const NEW_PASSWORD = "an entirely different passphrase";

class CapturingNotifier implements CredentialNotifier {
  readonly resets: { email: string; rawToken: string; expiresAt: Date }[] = [];
  shouldThrow = false;

  sendEmailVerification(): Promise<void> {
    return Promise.resolve();
  }

  sendPasswordReset(params: { email: string; rawToken: string; expiresAt: Date }): Promise<void> {
    if (this.shouldThrow) return Promise.reject(new Error("mail server is down"));
    this.resets.push(params);
    return Promise.resolve();
  }
}

class RecordingSessionRevoker implements SessionRevoker {
  readonly revoked: string[] = [];
  shouldThrow = false;

  revokeAllForUser(userId: string): Promise<void> {
    if (this.shouldThrow) return Promise.reject(new Error("session store unreachable"));
    this.revoked.push(userId);
    return Promise.resolve();
  }
}

describe("password reset (Issues 069 and 070)", () => {
  let unitOfWork: InMemoryCredentialsUnitOfWork;
  let tokens: InMemoryPasswordResetTokenRepository;
  let notifier: CapturingNotifier;
  let revoker: RecordingSessionRevoker;
  let hasher: Argon2PasswordHasher;
  let request: RequestPasswordReset;
  let confirm: ConfirmPasswordReset;

  beforeEach(async () => {
    tokens = new InMemoryPasswordResetTokenRepository();
    unitOfWork = new InMemoryCredentialsUnitOfWork({ passwordResetTokens: tokens });
    notifier = new CapturingNotifier();
    revoker = new RecordingSessionRevoker();
    hasher = new Argon2PasswordHasher(FAST);
    request = new RequestPasswordReset(unitOfWork, notifier);
    confirm = new ConfirmPasswordReset(unitOfWork, hasher, revoker);

    const registered = await new RegisterUserWithPassword(unitOfWork, hasher).execute({
      email: EMAIL,
      displayName: "Alice",
      password: PASSWORD,
    });
    if (!Result.isOk(registered)) throw new Error("fixture setup failed");
  });

  async function loadUser(): Promise<User> {
    const email = Email.create(EMAIL);
    if (!Result.isOk(email)) throw new Error("fixture setup failed");
    const user = await unitOfWork.repositories.users.findByEmail(email.value);
    if (user === undefined) throw new Error("fixture setup failed");
    return user;
  }

  async function issueToken(): Promise<string> {
    const result = await request.execute({ email: EMAIL });
    if (!Result.isOk(result) || !result.value.issued) throw new Error("fixture setup failed");
    const delivered = notifier.resets.at(-1);
    if (delivered === undefined) throw new Error("fixture setup failed");
    return delivered.rawToken;
  }

  describe("requesting (Issue 069)", () => {
    it("issues a token and sends it", async () => {
      const result = await request.execute({ email: EMAIL });

      expect(Result.isOk(result) && result.value.issued).toBe(true);
      expect(notifier.resets).toHaveLength(1);
    });

    it("responds identically whether or not the account exists", async () => {
      // A reset endpoint reporting "no account with that address" is a
      // *better* enumeration oracle than the login form: no password guess is
      // needed at all. One request per address and you have the answer.
      const known = await request.execute({ email: EMAIL });
      const unknown = await request.execute({ email: "nobody@example.com" });

      expect(Result.isOk(known)).toBe(true);
      expect(Result.isOk(unknown)).toBe(true);
      if (!Result.isOk(known) || !Result.isOk(unknown)) return;

      // Issue 069's criterion in full: token generation is observable only
      // internally, never through the response.
      expect(known.value.issued).toBe(true);
      expect(unknown.value.issued).toBe(false);
      expect(tokens.all()).toHaveLength(1);
    });

    it("stores only the digest", async () => {
      const rawToken = await issueToken();

      const stored = tokens.all();
      expect(stored[0]?.tokenHash).toBe(PasswordResetToken.hashToken(rawToken));
      expect(JSON.stringify(stored)).not.toContain(rawToken);
    });

    it("issues nothing for an account with no password credential", async () => {
      // SSO-only or passkey-only. Issuing a token would let someone *create*
      // a password on an account deliberately configured without one — a
      // privilege escalation dressed as a convenience.
      const user = await loadUser();
      await unitOfWork.repositories.credentials.deleteByUserId(user.id);

      const result = await request.execute({ email: EMAIL });

      expect(Result.isOk(result) && result.value.issued).toBe(false);
      expect(tokens.all()).toHaveLength(0);
    });

    it("retires the previous token when a new one is issued", async () => {
      // Each of these is account takeover in a URL. Several live at once
      // multiplies the surface for no benefit.
      const first = await issueToken();
      await issueToken();

      const result = await confirm.execute({ token: first, newPassword: NEW_PASSWORD });

      expect(Result.isErr(result)).toBe(true);
    });

    it("still reports success when delivery fails", async () => {
      notifier.shouldThrow = true;

      const result = await request.execute({ email: EMAIL });

      expect(Result.isOk(result)).toBe(true);
    });
  });

  describe("confirming (Issue 070)", () => {
    it("replaces the password", async () => {
      const rawToken = await issueToken();

      const result = await confirm.execute({ token: rawToken, newPassword: NEW_PASSWORD });

      expect(Result.isOk(result)).toBe(true);

      const authenticate = new AuthenticateWithPassword(unitOfWork, hasher);
      await expect(
        authenticate
          .execute({ email: EMAIL, password: NEW_PASSWORD })
          .then((outcome) => Result.isOk(outcome)),
      ).resolves.toBe(true);
    });

    it("stops the old password working", async () => {
      const rawToken = await issueToken();
      await confirm.execute({ token: rawToken, newPassword: NEW_PASSWORD });

      const authenticate = new AuthenticateWithPassword(unitOfWork, hasher);
      const result = await authenticate.execute({ email: EMAIL, password: PASSWORD });

      expect(Result.isErr(result)).toBe(true);
    });

    it("revokes every existing session", async () => {
      // The step everyone forgets, and the reason the flow exists. An
      // attacker who got in is holding a session; changing the password
      // revokes their knowledge of the credential and does nothing about the
      // session. They stay signed in while the user believes otherwise.
      const rawToken = await issueToken();
      const user = await loadUser();

      await confirm.execute({ token: rawToken, newPassword: NEW_PASSWORD });

      expect(revoker.revoked).toEqual([user.id]);
    });

    it("reports a partial failure when revocation fails", async () => {
      // Deliberately not swallowed, unlike a failed notification. The worst
      // case there is an email nobody received; here it is a user who
      // believes they have locked an attacker out and has not.
      const rawToken = await issueToken();
      revoker.shouldThrow = true;

      const result = await confirm.execute({ token: rawToken, newPassword: NEW_PASSWORD });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.fieldErrors["sessions"]).toContain("revocation_failed");
      // And it says so while being honest that the password *did* change —
      // the message has to tell the user what to do next.
      expect(result.error.message).toContain("password was changed");
    });

    it("marks the token used", async () => {
      const rawToken = await issueToken();

      await confirm.execute({ token: rawToken, newPassword: NEW_PASSWORD });

      expect(tokens.all()[0]?.consumedAt).toBeDefined();
    });

    it("rejects a reused token", async () => {
      // A reusable reset link in an old email is a permanent backdoor that
      // survives every subsequent password change.
      const rawToken = await issueToken();
      await confirm.execute({ token: rawToken, newPassword: NEW_PASSWORD });

      const result = await confirm.execute({
        token: rawToken,
        newPassword: "yet another password",
      });

      expect(Result.isErr(result)).toBe(true);
    });

    it("rejects an expired token", async () => {
      const shortLived = new RequestPasswordReset(unitOfWork, notifier, -1);
      await shortLived.execute({ email: EMAIL });
      const rawToken = notifier.resets.at(-1)?.rawToken ?? "";

      const result = await confirm.execute({ token: rawToken, newPassword: NEW_PASSWORD });

      expect(Result.isErr(result)).toBe(true);
    });

    it("rejects a token that was never issued", async () => {
      const result = await confirm.execute({
        token: "not-a-real-token",
        newPassword: NEW_PASSWORD,
      });

      expect(Result.isErr(result)).toBe(true);
    });

    it("reports every rejection identically, unlike email verification", async () => {
      // The opposite call from Issue 068, and the stakes are why. An attacker
      // holding a *used* reset token learns from "already used" that it was
      // real and that the account exists. Expired leaks the same. One message
      // for all three.
      const used = await issueToken();
      await confirm.execute({ token: used, newPassword: NEW_PASSWORD });

      const shortLived = new RequestPasswordReset(unitOfWork, notifier, -1);
      await shortLived.execute({ email: EMAIL });
      const expired = notifier.resets.at(-1)?.rawToken ?? "";

      const reused = await confirm.execute({ token: used, newPassword: NEW_PASSWORD });
      const stale = await confirm.execute({ token: expired, newPassword: NEW_PASSWORD });
      const unknown = await confirm.execute({ token: "nope", newPassword: NEW_PASSWORD });

      expect(Result.isErr(reused) && Result.isErr(stale) && Result.isErr(unknown)).toBe(true);
      if (!Result.isErr(reused) || !Result.isErr(stale) || !Result.isErr(unknown)) return;
      expect(reused.error.message).toBe(unknown.error.message);
      expect(stale.error.message).toBe(unknown.error.message);
      expect(reused.error.fieldErrors).toEqual(unknown.error.fieldErrors);
    });

    it("rejects a weak password without consuming the token", async () => {
      // Otherwise choosing a too-short password burns the one-time link and
      // sends the user back to their inbox for another email.
      const rawToken = await issueToken();

      const rejected = await confirm.execute({ token: rawToken, newPassword: "short" });
      expect(Result.isErr(rejected)).toBe(true);
      if (!Result.isErr(rejected)) return;
      expect(rejected.error.fieldErrors["password"]).toContain("too_short");

      const retried = await confirm.execute({ token: rawToken, newPassword: NEW_PASSWORD });
      expect(Result.isOk(retried)).toBe(true);
    });

    it("clears any account lockout", async () => {
      // The failures that locked the account were not the owner's, and after
      // a reset they have no way to wait one out.
      const rawToken = await issueToken();
      const user = await loadUser();
      const credential = await unitOfWork.repositories.credentials.findByUserId(user.id);
      if (credential === undefined) throw new Error("fixture setup failed");
      await unitOfWork.repositories.credentials.save(
        credential.recordFailedAttempt(
          { threshold: 1, baseDurationMs: 600_000, backoffFactor: 2, maxDurationMs: 600_000 },
          new Date(),
        ),
      );

      await confirm.execute({ token: rawToken, newPassword: NEW_PASSWORD });

      const after = await unitOfWork.repositories.credentials.findByUserId(user.id);
      expect(after?.failedAttempts).toBe(0);
      expect(after?.lockedUntil).toBeUndefined();
    });

    // ── ISSUE 072: Password history / reuse prevention ──────────────────

    it("rejects reuse of current password during reset", async () => {
      // A user resets their password but tries to set it back to the current one.
      const rawToken = await issueToken();

      const result = await confirm.execute({
        token: rawToken,
        newPassword: PASSWORD, // same as current
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.fieldErrors["password"]).toContain("reused");
    });

    it("rejects reuse of a password from history", async () => {
      // Set up a credential with password history
      const user = await loadUser();
      const credential = await unitOfWork.repositories.credentials.findByUserId(user.id);
      if (credential === undefined) throw new Error("fixture setup failed");

      // Manually inject an old password into history to simulate prior rotations
      const tempNew = await hasher.hash("TemporaryPassword1!");
      const withHistory = credential.rotatePassword(tempNew, { depth: 5 });
      await unitOfWork.repositories.credentials.save(withHistory);

      // Now try to reset back to the old password
      const rawToken = await issueToken();
      const result = await confirm.execute({
        token: rawToken,
        newPassword: PASSWORD, // This was the original password (in history now)
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.fieldErrors["password"]).toContain("reused");
    });

    it("accepts a new password not in history", async () => {
      const rawToken = await issueToken();

      const result = await confirm.execute({
        token: rawToken,
        newPassword: NEW_PASSWORD, // completely new password
      });

      expect(Result.isOk(result)).toBe(true);

      // Verify the new password works
      const authenticate = new AuthenticateWithPassword(unitOfWork, hasher);
      await expect(
        authenticate
          .execute({ email: EMAIL, password: NEW_PASSWORD })
          .then((outcome) => Result.isOk(outcome)),
      ).resolves.toBe(true);
    });

    it("maintains password history after successful reset", async () => {
      const user = await loadUser();
      const originalCredential = await unitOfWork.repositories.credentials.findByUserId(user.id);
      if (originalCredential === undefined) throw new Error("fixture setup failed");

      const rawToken = await issueToken();
      await confirm.execute({
        token: rawToken,
        newPassword: NEW_PASSWORD,
      });

      const updated = await unitOfWork.repositories.credentials.findByUserId(user.id);
      expect(updated?.passwordHistory).toContain(originalCredential.passwordHash);
    });

    it("reuse error message includes history depth", async () => {
      const rawToken = await issueToken();

      const result = await confirm.execute({
        token: rawToken,
        newPassword: PASSWORD, // reuse
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.message).toContain("5"); // default depth
    });
  });
});
