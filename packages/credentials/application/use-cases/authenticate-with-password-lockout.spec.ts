import { Email, type User } from "@verixa/identity";
import {
  NoopRateLimiter,
  AccountLockedError,
  AuthenticationError,
  Result,
} from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import type { Credential } from "../../domain/entities/credential.js";
import type { LockoutPolicy } from "../../domain/value-objects/lockout-policy.js";
import { Argon2PasswordHasher } from "../../infrastructure/argon2-password-hasher.js";
import { InMemoryCredentialsUnitOfWork } from "../../infrastructure/testing/in-memory-credentials-unit-of-work.js";
import type { PasswordHasher } from "../ports/password-hasher.js";

import { AuthenticateWithPassword } from "./authenticate-with-password.js";
import { RegisterUserWithPassword } from "./register-user-with-password.js";

/**
 * Account lockout (Issue 067), in its own file because it is a distinct
 * behaviour with its own fixture: a deliberately tiny policy, so the suite
 * observes real expiry without sleeping for a minute.
 *
 * The thresholds being configuration rather than constants baked into the
 * aggregate is what makes that possible, and is most of the reason they are
 * configuration.
 */

const FAST = { memoryCost: 64, timeCost: 1, parallelism: 1 };

const POLICY: LockoutPolicy = {
  threshold: 3,
  baseDurationMs: 40,
  backoffFactor: 2,
  maxDurationMs: 200,
};

const EMAIL = "alice@example.com";
const PASSWORD = "correct horse battery staple";
const WRONG = "wrong password entirely";

describe("AuthenticateWithPassword — lockout", () => {
  let unitOfWork: InMemoryCredentialsUnitOfWork;
  let hasher: Argon2PasswordHasher;
  let authenticate: AuthenticateWithPassword;

  beforeEach(async () => {
    unitOfWork = new InMemoryCredentialsUnitOfWork();
    hasher = new Argon2PasswordHasher(FAST);
    authenticate = new AuthenticateWithPassword(unitOfWork, hasher, new NoopRateLimiter(), POLICY);

    const registered = await new RegisterUserWithPassword(
      unitOfWork,
      hasher,
      new NoopRateLimiter(),
    ).execute({
      email: EMAIL,
      displayName: "Alice",
      password: PASSWORD,
    });
    if (!Result.isOk(registered)) throw new Error("fixture setup failed");
  });

  async function failOnce(): Promise<void> {
    await authenticate.execute({ email: EMAIL, password: WRONG });
  }

  async function loadUser(): Promise<User> {
    const email = Email.create(EMAIL);
    if (!Result.isOk(email)) throw new Error("fixture setup failed");
    const user = await unitOfWork.repositories.users.findByEmail(email.value);
    if (user === undefined) throw new Error("fixture setup failed");
    return user;
  }

  async function storedCredential(): Promise<Credential> {
    const credential = await unitOfWork.repositories.credentials.findByUserId(
      (await loadUser()).id,
    );
    if (credential === undefined) throw new Error("fixture setup failed");
    return credential;
  }

  async function reachThreshold(): Promise<void> {
    for (let attempt = 0; attempt < POLICY.threshold; attempt += 1) {
      await failOnce();
    }
  }

  describe("threshold", () => {
    it("counts consecutive failures without locking below the threshold", async () => {
      await failOnce();
      await failOnce();

      const credential = await storedCredential();
      expect(credential.failedAttempts).toBe(2);
      expect(credential.lockedUntil).toBeUndefined();
    });

    it("locks on the Nth consecutive failure", async () => {
      await reachThreshold();

      const credential = await storedCredential();
      expect(credential.failedAttempts).toBe(POLICY.threshold);
      expect(credential.lockedUntil).toBeDefined();
    });

    it("refuses the correct password while locked", async () => {
      // The part that feels wrong until it is said out loud: once locked,
      // knowing the password is not enough. If it were, lockout would stop
      // nothing — an attacker who guesses correctly on attempt six is exactly
      // the case it exists to prevent.
      await reachThreshold();

      const result = await authenticate.execute({ email: EMAIL, password: PASSWORD });

      expect(Result.isErr(result)).toBe(true);
    });
  });

  describe("disclosure", () => {
    it("is distinct to the caller and identical to a client", async () => {
      // Two requirements pulling against each other. Operationally a lockout
      // and a bad password are very different signals, and collapsing them
      // makes a credential-stuffing campaign look like ordinary user error.
      // On the wire they must be indistinguishable, because lockout state
      // exists only for accounts that exist — so "fail five times and watch
      // what changes" would be an enumeration oracle, undoing what the
      // generic error is for.
      //
      // Resolved by distinguishing the error *type* while keeping code,
      // status and message identical.
      await reachThreshold();

      const locked = await authenticate.execute({ email: EMAIL, password: PASSWORD });
      const unknown = await authenticate.execute({
        email: "nobody@example.com",
        password: PASSWORD,
      });

      expect(Result.isErr(locked)).toBe(true);
      expect(Result.isErr(unknown)).toBe(true);
      if (!Result.isErr(locked) || !Result.isErr(unknown)) return;

      expect(locked.error).toBeInstanceOf(AccountLockedError);
      expect(unknown.error).toBeInstanceOf(AuthenticationError);

      expect(locked.error.code).toBe(unknown.error.code);
      expect(locked.error.message).toBe(unknown.error.message);
      expect(locked.error.httpStatusHint).toBe(unknown.error.httpStatusHint);
      expect(locked.error.toJSON()).toEqual(unknown.error.toJSON());
    });

    it("still hashes while locked, so the fast path is not observable", async () => {
      // Lockout short-circuits ahead of the password check, which is most of
      // its value against credential stuffing — refusing to spend the CPU is
      // the defence. It also makes the locked path the fastest in the use
      // case, which would announce "this address has an account, and someone
      // is attacking it" through response time alone. The decoy runs here for
      // that reason.
      let verifications = 0;
      const counting: PasswordHasher = {
        hash: (plaintext) => hasher.hash(plaintext),
        verify: (plaintext, encodedHash) => {
          verifications += 1;
          return hasher.verify(plaintext, encodedHash);
        },
        needsRehash: (encodedHash) => hasher.needsRehash(encodedHash),
      };
      const useCase = new AuthenticateWithPassword(
        unitOfWork,
        counting,
        new NoopRateLimiter(),
        POLICY,
      );

      for (let attempt = 0; attempt < POLICY.threshold; attempt += 1) {
        await useCase.execute({ email: EMAIL, password: WRONG });
      }

      verifications = 0;
      await useCase.execute({ email: EMAIL, password: PASSWORD });

      expect(verifications).toBe(1);
    });
  });

  describe("backoff and expiry", () => {
    it("extends the lock on each further attempt", async () => {
      await reachThreshold();
      const first = await storedCredential();

      await failOnce();
      const second = await storedCredential();

      expect(second.failedAttempts).toBe(POLICY.threshold + 1);
      expect(second.lockedUntil?.getTime()).toBeGreaterThan(first.lockedUntil?.getTime() ?? 0);
    });

    it("releases the lock on its own once it expires", async () => {
      // An expiry, not a `locked` flag. A flag needs something to come along
      // and clear it, and the failure mode of that job not running is an
      // account locked out permanently, with nothing in the request path able
      // to notice.
      await reachThreshold();

      await new Promise((resolve) => setTimeout(resolve, POLICY.baseDurationMs + 40));

      const result = await authenticate.execute({ email: EMAIL, password: PASSWORD });

      expect(Result.isOk(result)).toBe(true);
    });
  });

  describe("reset", () => {
    it("clears the counter on a successful login", async () => {
      // What makes the threshold count *consecutive* failures. Without it,
      // two mistyped passwords a year apart, each followed by a successful
      // login, would eventually lock the account — indistinguishable from an
      // attack only if you never look at the gaps between attempts.
      await failOnce();
      await failOnce();

      const success = await authenticate.execute({ email: EMAIL, password: PASSWORD });
      expect(Result.isOk(success)).toBe(true);
      expect((await storedCredential()).failedAttempts).toBe(0);

      await failOnce();
      await failOnce();
      expect((await storedCredential()).lockedUntil).toBeUndefined();
    });

    it("does not write the credential on an ordinary successful login", async () => {
      // The counter is already zero, so there is nothing to clear. Writing
      // regardless would turn every login into a row update on the hottest
      // path in the system.
      const before = await storedCredential();

      await authenticate.execute({ email: EMAIL, password: PASSWORD });

      const after = await storedCredential();
      expect(before.failedAttempts).toBe(0);
      expect(after.updatedAt.getTime()).toBe(before.updatedAt.getTime());
    });

    it("clears the lock when the password is changed", async () => {
      // After a reset (Issue 070) the failures were not the owner's, and they
      // have no way to wait out a lock on a credential they have just
      // replaced.
      await reachThreshold();

      const credential = await storedCredential();
      await unitOfWork.repositories.credentials.save(
        credential.withPasswordHash(await hasher.hash("a brand new password here")),
      );

      const result = await authenticate.execute({
        email: EMAIL,
        password: "a brand new password here",
      });

      expect(Result.isOk(result)).toBe(true);
    });

    it("does not count a correct password against a suspended account", async () => {
      // The credential was proven. Counting it as a failure would punish the
      // account holder for the administrative state of their own account, and
      // would let repeated legitimate attempts lock a credential nobody was
      // guessing at.
      const activated = (await loadUser()).activate();
      if (!Result.isOk(activated)) throw new Error("fixture setup failed");
      const suspended = activated.value.suspend("moderation");
      if (!Result.isOk(suspended)) throw new Error("fixture setup failed");
      await unitOfWork.repositories.users.save(suspended.value);

      // The *correct* password, repeatedly. reachThreshold sends a wrong one,
      // which would be counting real failures and prove nothing here.
      for (let attempt = 0; attempt < POLICY.threshold; attempt += 1) {
        const refused = await authenticate.execute({ email: EMAIL, password: PASSWORD });
        expect(Result.isErr(refused)).toBe(true);
      }

      expect((await storedCredential()).failedAttempts).toBe(0);
    });
  });
});
