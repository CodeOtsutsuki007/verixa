import { Email, type User } from "@verixa/identity";
import { NoopRateLimiter, Result } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { EmailVerificationToken } from "../../domain/entities/email-verification-token.js";
import { Argon2PasswordHasher } from "../../infrastructure/argon2-password-hasher.js";
import { InMemoryCredentialsUnitOfWork } from "../../infrastructure/testing/in-memory-credentials-unit-of-work.js";
import { InMemoryEmailVerificationTokenRepository } from "../../infrastructure/testing/in-memory-verification-token-repositories.js";
import type { CredentialNotifier } from "../ports/credential-notifier.js";

import { ConfirmEmailVerification } from "./confirm-email-verification.js";
import { RegisterUserWithPassword } from "./register-user-with-password.js";
import { RequestEmailVerification } from "./request-email-verification.js";

const FAST = { memoryCost: 64, timeCost: 1, parallelism: 1 };
const EMAIL = "alice@example.com";
const PASSWORD = "correct horse battery staple";

/** Captures what would have been delivered, so tests can read the raw token. */
class CapturingNotifier implements CredentialNotifier {
  readonly verifications: { email: string; rawToken: string; expiresAt: Date }[] = [];
  readonly resets: { email: string; rawToken: string; expiresAt: Date }[] = [];
  shouldThrow = false;

  sendEmailVerification(params: {
    email: string;
    rawToken: string;
    expiresAt: Date;
  }): Promise<void> {
    if (this.shouldThrow) return Promise.reject(new Error("mail server is down"));
    this.verifications.push(params);
    return Promise.resolve();
  }

  sendPasswordReset(params: { email: string; rawToken: string; expiresAt: Date }): Promise<void> {
    if (this.shouldThrow) return Promise.reject(new Error("mail server is down"));
    this.resets.push(params);
    return Promise.resolve();
  }
}

describe("email verification (Issue 068)", () => {
  let unitOfWork: InMemoryCredentialsUnitOfWork;
  let tokens: InMemoryEmailVerificationTokenRepository;
  let notifier: CapturingNotifier;
  let request: RequestEmailVerification;
  let confirm: ConfirmEmailVerification;

  beforeEach(async () => {
    tokens = new InMemoryEmailVerificationTokenRepository();
    unitOfWork = new InMemoryCredentialsUnitOfWork({ emailVerificationTokens: tokens });
    notifier = new CapturingNotifier();
    request = new RequestEmailVerification(unitOfWork, notifier);
    confirm = new ConfirmEmailVerification(unitOfWork);

    const registered = await new RegisterUserWithPassword(
      unitOfWork,
      new Argon2PasswordHasher(FAST),
      new NoopRateLimiter(),
    ).execute({ email: EMAIL, displayName: "Alice", password: PASSWORD });
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
    const delivered = notifier.verifications.at(-1);
    if (delivered === undefined) throw new Error("fixture setup failed");
    return delivered.rawToken;
  }

  describe("requesting", () => {
    it("issues a token for a pending user and sends it", async () => {
      const result = await request.execute({ email: EMAIL });

      expect(Result.isOk(result) && result.value.issued).toBe(true);
      expect(notifier.verifications).toHaveLength(1);
      expect(notifier.verifications[0]?.email).toBe(EMAIL);
    });

    it("stores only the digest, never the raw token", async () => {
      const rawToken = await issueToken();

      const stored = tokens.all();
      expect(stored).toHaveLength(1);
      expect(stored[0]?.tokenHash).not.toBe(rawToken);
      expect(stored[0]?.tokenHash).toBe(EmailVerificationToken.hashToken(rawToken));
      // The property that makes a database leak useless: the raw value is not
      // recoverable from anything persisted.
      expect(JSON.stringify(stored)).not.toContain(rawToken);
    });

    it("keeps the digest out of serialization", async () => {
      await issueToken();
      const stored = tokens.all()[0];

      expect(JSON.stringify(stored)).toContain("[REDACTED]");
      expect(JSON.stringify(stored)).not.toContain(stored?.tokenHash ?? "");
    });

    it("succeeds identically for an unknown address", async () => {
      // A verification endpoint that says "no account with that address" is
      // an enumeration oracle needing no password guess at all — cheaper than
      // the login form.
      const known = await request.execute({ email: EMAIL });
      const unknown = await request.execute({ email: "nobody@example.com" });

      expect(Result.isOk(known)).toBe(true);
      expect(Result.isOk(unknown)).toBe(true);
      if (!Result.isOk(known) || !Result.isOk(unknown)) return;

      // The *response* carries no difference. `issued` is internal, and is
      // the only way to assert the behaviour at all — which is the point.
      expect(known.value.issued).toBe(true);
      expect(unknown.value.issued).toBe(false);
    });

    it("succeeds identically for a malformed address", async () => {
      const result = await request.execute({ email: "not-an-email" });

      expect(Result.isOk(result) && result.value.issued).toBe(false);
      expect(notifier.verifications).toHaveLength(0);
    });

    it("issues nothing for an already-active user", async () => {
      const activated = (await loadUser()).activate();
      if (!Result.isOk(activated)) throw new Error("fixture setup failed");
      await unitOfWork.repositories.users.save(activated.value);

      const result = await request.execute({ email: EMAIL });

      expect(Result.isOk(result) && result.value.issued).toBe(false);
    });

    it("retires the previous token when a new one is issued", async () => {
      // Otherwise a user who clicks "resend" three times holds three working
      // links, two of them in a mailbox nobody is watching.
      const first = await issueToken();
      await issueToken();

      const result = await confirm.execute({ token: first });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.fieldErrors["token"]).toContain("already_used");
    });

    it("still reports success when delivery fails", async () => {
      // Surfacing a mail outage would tell the caller an account exists, since
      // only a real account reaches the send.
      notifier.shouldThrow = true;

      const result = await request.execute({ email: EMAIL });

      expect(Result.isOk(result)).toBe(true);
      // The token was still issued and committed — the user can ask again.
      expect(tokens.all()).toHaveLength(1);
    });
  });

  describe("confirming", () => {
    it("activates the user", async () => {
      const rawToken = await issueToken();

      const result = await confirm.execute({ token: rawToken });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;
      expect(result.value.user.status).toBe("active");
      expect((await loadUser()).status).toBe("active");
    });

    it("emits a status-change event on the aggregate", async () => {
      // Issue 068 asks for an event on success. `activate` already emits
      // `UserStatusChanged`, so this use case does not add its own — two
      // records of one fact can disagree.
      const rawToken = await issueToken();

      const result = await confirm.execute({ token: rawToken });

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;
      const eventNames = result.value.user
        .pullDomainEvents()
        .map((event) => event.constructor.name);
      expect(eventNames).toContain("UserStatusChanged");
    });

    it("rejects a second use of the same token", async () => {
      const rawToken = await issueToken();
      await confirm.execute({ token: rawToken });

      const result = await confirm.execute({ token: rawToken });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.fieldErrors["token"]).toContain("already_used");
    });

    it("rejects an expired token", async () => {
      const shortLived = new RequestEmailVerification(unitOfWork, notifier, -1);
      await shortLived.execute({ email: EMAIL });
      const rawToken = notifier.verifications.at(-1)?.rawToken ?? "";

      const result = await confirm.execute({ token: rawToken });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.fieldErrors["token"]).toContain("expired");
    });

    it("rejects a token that was never issued", async () => {
      const result = await confirm.execute({ token: "not-a-real-token" });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.fieldErrors["token"]).toContain("invalid");
    });

    it("distinguishes expired from unknown, which is safe here", async () => {
      // The deliberate departure from the login path. Reaching this use case
      // requires already holding a 256-bit token, so there is nothing left to
      // enumerate — and "expired" versus "already used" lead to different
      // actions ("request another" versus "just sign in"). Copying the login
      // rule here would make the product worse for no security gain.
      const shortLived = new RequestEmailVerification(unitOfWork, notifier, -1);
      await shortLived.execute({ email: EMAIL });
      const expiredToken = notifier.verifications.at(-1)?.rawToken ?? "";

      const expired = await confirm.execute({ token: expiredToken });
      const unknown = await confirm.execute({ token: "not-a-real-token" });

      expect(Result.isErr(expired) && Result.isErr(unknown)).toBe(true);
      if (!Result.isErr(expired) || !Result.isErr(unknown)) return;
      expect(expired.error.message).not.toBe(unknown.error.message);
    });

    it("leaves the user pending when the token is rejected", async () => {
      await confirm.execute({ token: "not-a-real-token" });

      expect((await loadUser()).status).toBe("pending");
    });
  });
});
