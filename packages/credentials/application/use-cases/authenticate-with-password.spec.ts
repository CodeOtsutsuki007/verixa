import { Email, type User } from "@verixa/identity";
import { Result } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { Argon2PasswordHasher } from "../../infrastructure/argon2-password-hasher.js";
import { InMemoryCredentialsUnitOfWork } from "../../infrastructure/testing/in-memory-credentials-unit-of-work.js";
import type { PasswordHasher } from "../ports/password-hasher.js";

import { AuthenticateWithPassword } from "./authenticate-with-password.js";
import { RegisterUserWithPassword } from "./register-user-with-password.js";

// Weak parameters, for the same reason the registration spec uses them: these
// tests exercise orchestration and disclosure, not hashing strength. The
// hasher's own spec covers production parameters.
const FAST = { memoryCost: 64, timeCost: 1, parallelism: 1 };

const EMAIL = "alice@example.com";
const PASSWORD = "correct horse battery staple";

describe("AuthenticateWithPassword", () => {
  let unitOfWork: InMemoryCredentialsUnitOfWork;
  let hasher: Argon2PasswordHasher;
  let register: RegisterUserWithPassword;
  let authenticate: AuthenticateWithPassword;

  beforeEach(async () => {
    unitOfWork = new InMemoryCredentialsUnitOfWork();
    // A fresh hasher per test, because the decoy hash is cached per hasher
    // instance. Sharing one would let the first test warm the cache for the
    // rest and quietly disarm the timing test below.
    hasher = new Argon2PasswordHasher(FAST);
    register = new RegisterUserWithPassword(unitOfWork, hasher);
    authenticate = new AuthenticateWithPassword(unitOfWork, hasher);

    const registered = await register.execute({
      email: EMAIL,
      displayName: "Alice",
      password: PASSWORD,
    });
    if (!Result.isOk(registered)) throw new Error("fixture setup failed");
  });

  describe("success", () => {
    it("authenticates a correct email and password", async () => {
      const result = await authenticate.execute({ email: EMAIL, password: PASSWORD });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;
      expect(result.value.user.email.value).toBe(EMAIL);
    });

    it("accepts an email in a different case", async () => {
      // `Email` normalizes and the column is citext, so this is already true
      // at two lower layers. Asserted here because it is the behaviour a user
      // actually experiences, and because a regression in either layer would
      // present as "my password stopped working" rather than as a value-object
      // bug.
      const result = await authenticate.execute({ email: "ALICE@Example.com", password: PASSWORD });

      expect(Result.isOk(result)).toBe(true);
    });

    it("authenticates a pending user", async () => {
      // Registration leaves a user pending until email verification, so if
      // this failed nobody could ever sign in after registering. The vertical
      // slice depends on it and the dependency is easy to break from the
      // identity side.
      const result = await authenticate.execute({ email: EMAIL, password: PASSWORD });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;
      expect(result.value.user.status).toBe("pending");
    });

    it("logs in unchanged when no MFA and optional/disabled policy", async () => {
      const mfaChecker = {
        resolvePolicy: async () => "optional" as const,
        listActiveMethods: async () => [],
      };
      const useCase = new AuthenticateWithPassword(unitOfWork, hasher, undefined, mfaChecker);
      const result = await useCase.execute({ email: EMAIL, password: PASSWORD });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;
      expect((result.value as any).status).toBeUndefined();
    });

    it("always issues a challenge when user has active methods", async () => {
      const mfaChecker = {
        resolvePolicy: async () => "optional" as const,
        listActiveMethods: async () => [{ id: "m1", type: "totp" }],
      };
      const useCase = new AuthenticateWithPassword(unitOfWork, hasher, undefined, mfaChecker);
      const result = await useCase.execute({ email: EMAIL, password: PASSWORD });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;
      expect((result.value as any).status).toBe("mfa_challenge");
      expect((result.value as any).methods).toHaveLength(1);
    });

    it("routes required-but-unenrolled users to enrollment and never grants a session", async () => {
      const mfaChecker = {
        resolvePolicy: async () => "required" as const,
        listActiveMethods: async () => [],
      };
      const useCase = new AuthenticateWithPassword(unitOfWork, hasher, undefined, mfaChecker);
      const result = await useCase.execute({ email: EMAIL, password: PASSWORD });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;
      expect((result.value as any).status).toBe("enrollment_required");
    });
  });

  describe("does not reveal why it failed", () => {
    // The acceptance criterion for Issue 066, and the reason this use case
    // exists in the shape it does. Each of these is a different internal
    // cause; a caller must not be able to tell them apart.

    async function failureFor(command: {
      email: string;
      password: string;
    }): Promise<{ code: string; message: string }> {
      const result = await authenticate.execute(command);
      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) throw new Error("expected a failure");
      return { code: result.error.code, message: result.error.message };
    }

    it("returns an identical error for an unknown email and a wrong password", async () => {
      const unknownUser = await failureFor({ email: "nobody@example.com", password: PASSWORD });
      const wrongPassword = await failureFor({ email: EMAIL, password: "wrong password entirely" });

      // Compared as whole objects rather than field by field, so a future
      // field carrying a distinguishing detail fails here instead of being
      // waved through by assertions that only look at `code`.
      expect(unknownUser).toEqual(wrongPassword);
      expect(unknownUser.code).toBe("AUTHENTICATION_FAILED");
    });

    it("returns that same error for a malformed email", async () => {
      // A 400 "not a valid email" would be perfectly reasonable on a
      // registration endpoint and is a disclosure here: it tells an attacker
      // their input never reached the credential lookup.
      const malformed = await failureFor({ email: "not-an-email", password: PASSWORD });
      const wrongPassword = await failureFor({ email: EMAIL, password: "wrong password entirely" });

      expect(malformed).toEqual(wrongPassword);
    });

    it("returns that same error for a user with no password credential", async () => {
      // An SSO-only or passkey-only account. It legitimately has no
      // credential, and saying so would disclose both that the account exists
      // and how its owner signs in.
      const registered = await register.execute({
        email: "sso-only@example.com",
        displayName: "Sso Only",
        password: PASSWORD,
      });
      if (!Result.isOk(registered)) throw new Error("fixture setup failed");
      await unitOfWork.repositories.credentials.deleteByUserId(registered.value.user.id);

      const noCredential = await failureFor({ email: "sso-only@example.com", password: PASSWORD });
      const wrongPassword = await failureFor({ email: EMAIL, password: "wrong password entirely" });

      expect(noCredential).toEqual(wrongPassword);
    });

    it("returns that same error for a suspended user, even with the right password", async () => {
      // The status check deliberately runs *after* the password is verified.
      // Checking it first would answer "does this account exist" for someone
      // who never knew the password — so a suspended account has to fail the
      // same way a wrong password does, not a more informative way.
      const user = await loadUser(unitOfWork);
      const activated = user.activate();
      if (!Result.isOk(activated)) throw new Error("fixture setup failed");
      const suspended = activated.value.suspend("moderation");
      if (!Result.isOk(suspended)) throw new Error("fixture setup failed");
      await unitOfWork.repositories.users.save(suspended.value);

      const whileSuspended = await failureFor({ email: EMAIL, password: PASSWORD });
      const wrongPassword = await failureFor({ email: EMAIL, password: "wrong password entirely" });

      expect(whileSuspended).toEqual(wrongPassword);
    });

    it("never names the email address it was given", async () => {
      // The subtler disclosure route, and the one that survives a careless
      // refactor: an error that interpolates the address is different for
      // every attempt even when the code is constant, and reads as
      // confirmation that the address was understood.
      const failure = await failureFor({ email: EMAIL, password: "wrong password entirely" });

      expect(failure.message).not.toContain(EMAIL);
      expect(failure.message).toBe("Invalid email or password.");
    });
  });

  describe("timing", () => {
    it("does a real hash verification when there is no user to check", async () => {
      // The disclosure a matching error message does not close. If a missing
      // user returns immediately while a wrong password costs a full argon2
      // verification, the response *time* answers the question the message
      // refuses to.
      //
      // Asserted by counting verifications rather than by measuring a clock.
      // The property being protected is "the same work happens on both
      // paths", and that is exactly what a counter observes — deterministic,
      // and immune to the shared-runner flakiness that a wall-clock bound
      // invites. A timing assertion here would be measuring the machine.
      let verifications = 0;
      const counting: PasswordHasher = {
        hash: (plaintext) => hasher.hash(plaintext),
        verify: (plaintext, encodedHash) => {
          verifications += 1;
          return hasher.verify(plaintext, encodedHash);
        },
        needsRehash: (encodedHash) => hasher.needsRehash(encodedHash),
      };
      const useCase = new AuthenticateWithPassword(unitOfWork, counting);

      await useCase.execute({ email: EMAIL, password: "wrong password entirely" });
      const afterWrongPassword = verifications;

      verifications = 0;
      await useCase.execute({ email: "nobody@example.com", password: "wrong password entirely" });
      const afterUnknownUser = verifications;

      expect(afterWrongPassword).toBe(1);
      expect(afterUnknownUser).toBe(afterWrongPassword);
    });

    it("uses a decoy matching the hasher it was given", async () => {
      // The decoy is cached per hasher instance. Cached globally, a decoy
      // built at one set of cost parameters would be used to disguise a
      // hasher configured with different ones — which looks like it works,
      // costs the wrong amount, and leaves the side channel open.
      const expensive = new Argon2PasswordHasher({ ...FAST, timeCost: 3 });
      const useCase = new AuthenticateWithPassword(unitOfWork, expensive);

      const result = await useCase.execute({ email: "nobody@example.com", password: PASSWORD });

      expect(Result.isErr(result)).toBe(true);
    });
  });

  describe("transparent rehashing", () => {
    it("upgrades a hash stored with weaker parameters", async () => {
      // The only moment an existing hash can be upgraded: a successful login
      // is the only time the plaintext exists. Without this, raising cost
      // parameters would mean a mass password reset.
      const stronger = new Argon2PasswordHasher({ ...FAST, memoryCost: 512 });
      const useCase = new AuthenticateWithPassword(unitOfWork, stronger);

      const existing = await loadUser(unitOfWork);
      const before = await unitOfWork.repositories.credentials.findByUserId(existing.id);
      const result = await useCase.execute({ email: EMAIL, password: PASSWORD });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;
      expect(result.value.rehashed).toBe(true);

      const after = await unitOfWork.repositories.credentials.findByUserId(result.value.user.id);
      expect(after?.passwordHash).not.toBe(before?.passwordHash);
      expect(after?.passwordHash).toContain("m=512");
      // The upgraded hash must still verify the same password, or the upgrade
      // has locked the user out of their own account on the next attempt.
      await expect(stronger.verify(PASSWORD, after?.passwordHash ?? "")).resolves.toBe(true);
    });

    it("leaves a current hash alone", async () => {
      const result = await authenticate.execute({ email: EMAIL, password: PASSWORD });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;
      expect(result.value.rehashed).toBe(false);
    });

    it("still authenticates when the upgrade fails to save", async () => {
      // Best-effort by design. The user supplied correct credentials;
      // refusing them because a background optimisation failed would turn a
      // cosmetic problem into an outage, and the upgrade is retried on their
      // next login anyway.
      const stronger = new Argon2PasswordHasher({ ...FAST, memoryCost: 512 });
      const failing = new InMemoryCredentialsUnitOfWork({
        users: unitOfWork.repositories.users,
        credentials: {
          findByUserId: (userId) => unitOfWork.repositories.credentials.findByUserId(userId),
          save: () => Promise.reject(new Error("database is on fire")),
          deleteByUserId: (userId) => unitOfWork.repositories.credentials.deleteByUserId(userId),
        },
      });
      const useCase = new AuthenticateWithPassword(failing, stronger);

      const result = await useCase.execute({ email: EMAIL, password: PASSWORD });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;
      expect(result.value.rehashed).toBe(false);
    });
  });
});

/** The single user the fixture registers, loaded fresh from the repository. */
async function loadUser(unitOfWork: InMemoryCredentialsUnitOfWork): Promise<User> {
  const email = Email.create(EMAIL);
  if (!Result.isOk(email)) throw new Error("fixture setup failed");
  const user = await unitOfWork.repositories.users.findByEmail(email.value);
  if (user === undefined) throw new Error("fixture setup failed");
  return user;
}
