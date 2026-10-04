import { NoopRateLimiter, Result } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { Argon2PasswordHasher } from "../../infrastructure/argon2-password-hasher.js";
import { InMemoryCredentialsUnitOfWork } from "../../infrastructure/testing/in-memory-credentials-unit-of-work.js";

import { RegisterUserWithPassword } from "./register-user-with-password.js";

// Weak parameters: these tests exercise orchestration, not hashing strength,
// and argon2 at production settings would make the suite slow enough that
// people skip it. The hasher's own spec covers real parameters.
const hasher = new Argon2PasswordHasher({ memoryCost: 64, timeCost: 1, parallelism: 1 });

const VALID = {
  email: "alice@example.com",
  displayName: "Alice",
  password: "correct horse battery staple",
};

describe("RegisterUserWithPassword", () => {
  let unitOfWork: InMemoryCredentialsUnitOfWork;
  let useCase: RegisterUserWithPassword;

  beforeEach(() => {
    unitOfWork = new InMemoryCredentialsUnitOfWork();
    useCase = new RegisterUserWithPassword(unitOfWork, hasher, new NoopRateLimiter());
  });

  it("creates both a user and a credential", async () => {
    const result = await useCase.execute(VALID);

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    expect(result.value.user.email.value).toBe("alice@example.com");
    expect(result.value.user.status).toBe("pending");
    expect(result.value.credential.userId).toBe(result.value.user.id);

    await expect(
      unitOfWork.repositories.credentials.findByUserId(result.value.user.id),
    ).resolves.toBeDefined();
  });

  it("stores a hash, never the password", async () => {
    const result = await useCase.execute(VALID);
    if (!Result.isOk(result)) throw new Error("fixture setup failed");

    const stored = result.value.credential.passwordHash;
    expect(stored).not.toContain(VALID.password);
    expect(stored).toMatch(/^\$argon2id\$/);
    await expect(hasher.verify(VALID.password, stored)).resolves.toBe(true);
  });

  it("rejects a weak password before persisting anything", async () => {
    const result = await useCase.execute({ ...VALID, password: "short" });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.code).toBe("VALIDATION_ERROR");
    }

    // The acceptance criterion: nothing was written. A registration that
    // creates a user and *then* rejects the password leaves an account with
    // no way to log in and an email nobody can re-register.
    const probe = await useCase.execute(VALID);
    expect(Result.isOk(probe)).toBe(true);
  });

  it("rejects an invalid email before hashing", async () => {
    const result = await useCase.execute({ ...VALID, email: "not-an-email" });

    expect(Result.isErr(result) && result.error.code).toBe("VALIDATION_ERROR");
  });

  it("rejects a duplicate email with a typed conflict", async () => {
    await useCase.execute(VALID);

    const second = await useCase.execute({ ...VALID, displayName: "Alice Again" });

    expect(Result.isErr(second)).toBe(true);
    if (Result.isErr(second)) {
      expect(second.error.code).toBe("CONFLICT");
    }
  });

  it("treats a case-differing email as a duplicate", async () => {
    await useCase.execute(VALID);

    const second = await useCase.execute({ ...VALID, email: "ALICE@EXAMPLE.COM" });

    expect(Result.isErr(second) && second.error.code).toBe("CONFLICT");
  });

  it("registers an optional person name", async () => {
    const result = await useCase.execute({ ...VALID, givenName: "Alice", familyName: "Smith" });

    expect(Result.isOk(result) && result.value.user.personName?.toFullName()).toBe("Alice Smith");
  });

  it("gives each registration a distinct hash, even for identical passwords", async () => {
    const first = await useCase.execute(VALID);
    const second = await useCase.execute({ ...VALID, email: "bob@example.com" });
    if (!Result.isOk(first) || !Result.isOk(second)) throw new Error("fixture setup failed");

    // Per-hash salting, end to end: two users with the same password must not
    // share a hash, or cracking one cracks both.
    expect(first.value.credential.passwordHash).not.toBe(second.value.credential.passwordHash);
  });

  it("records a UserRegistered event on the created user", async () => {
    const result = await useCase.execute(VALID);
    if (!Result.isOk(result)) throw new Error("fixture setup failed");

    expect(result.value.user.pullDomainEvents()).toHaveLength(1);
  });
});
