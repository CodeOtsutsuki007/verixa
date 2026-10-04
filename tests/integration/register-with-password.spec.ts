import {
  Argon2PasswordHasher,
  PrismaCredentialsUnitOfWork,
  RegisterUserWithPassword,
} from "@verixa/credentials";
import { DisplayName, Email, User } from "@verixa/identity";
import { NoopRateLimiter, Result } from "@verixa/shared-kernel";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { createTestPrismaClient, databaseAvailability } from "./helpers/database.js";

/**
 * Atomicity of `RegisterUserWithPassword` against a real database (Issue 065).
 *
 * The in-memory unit of work cannot verify this — it does not roll back, and
 * deliberately so. Faking rollback would make these tests pass against a
 * mechanism production does not share, which is worse than not testing it
 * here at all. So orchestration is tested against fakes, and the transaction
 * is tested where the transaction actually exists.
 */

const available = await databaseAvailability();

const hasher = new Argon2PasswordHasher({ memoryCost: 64, timeCost: 1, parallelism: 1 });

describe.skipIf(!available)("RegisterUserWithPassword (real Postgres)", () => {
  const prisma = createTestPrismaClient();
  const useCase = new RegisterUserWithPassword(
    new PrismaCredentialsUnitOfWork(prisma),
    hasher,
    new NoopRateLimiter(),
  );

  beforeAll(async () => {
    await prisma.$connect();
  }, 60_000);

  afterEach(async () => {
    await prisma.credential.deleteMany({});
    await prisma.invitation.deleteMany({});
    await prisma.organizationMembership.deleteMany({});
    await prisma.organization.deleteMany({});
    await prisma.user.deleteMany({});
  });

  afterAll(async () => {
    await prisma.$disconnect();
  }, 60_000);

  it("commits the user and credential together", async () => {
    const result = await useCase.execute({
      email: "alice@example.com",
      displayName: "Alice",
      password: "correct horse battery staple",
    });

    expect(Result.isOk(result)).toBe(true);
    await expect(prisma.user.count()).resolves.toBe(1);
    await expect(prisma.credential.count()).resolves.toBe(1);
  });

  it("leaves no user behind when a later write fails", async () => {
    const attempt = new PrismaCredentialsUnitOfWork(prisma).run(async (repositories) => {
      const email = Email.create("doomed@example.com");
      const displayName = DisplayName.create("Doomed");
      if (!Result.isOk(email) || !Result.isOk(displayName)) throw new Error("fixture failed");

      const user = User.register({ email: email.value, displayName: displayName.value });
      await repositories.users.save(user);

      // Stand-in for any later failure. The cause is irrelevant; the
      // guarantee is that the user insert above does not survive it.
      throw new Error("simulated failure after the user was written");
    });

    await expect(attempt).rejects.toThrow("simulated failure");

    // The property that matters: no orphaned user. Without a transaction this
    // would be 1 — an account nobody can log into, holding an email address
    // nobody can re-register.
    await expect(prisma.user.count()).resolves.toBe(0);
    await expect(prisma.credential.count()).resolves.toBe(0);
  });

  it("never writes the plaintext password to the database", async () => {
    const password = "correct horse battery staple";
    await useCase.execute({ email: "alice@example.com", displayName: "Alice", password });

    const rows = await prisma.credential.findMany();
    expect(JSON.stringify(rows)).not.toContain(password);
    expect(rows[0]?.passwordHash).toMatch(/^\$argon2id\$/);
  });

  it("rejects a duplicate email at the database level too", async () => {
    const base = { displayName: "Alice", password: "correct horse battery staple" };
    await useCase.execute({ ...base, email: "alice@example.com" });

    const second = await useCase.execute({ ...base, email: "ALICE@EXAMPLE.COM" });

    expect(Result.isErr(second) && second.error.code).toBe("CONFLICT");
    await expect(prisma.user.count()).resolves.toBe(1);
  });
});
