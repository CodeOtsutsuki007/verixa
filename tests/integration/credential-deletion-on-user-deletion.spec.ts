import {
  Argon2PasswordHasher,
  HandleUserDeleted,
  NullCredentialNotifier,
  PrismaCredentialsUnitOfWork,
  RegisterUserWithPassword,
  RequestEmailVerification,
  RequestPasswordReset,
} from "@verixa/credentials";
import { PrismaUserRepository, RegisterUser, UserStatusChanged } from "@verixa/identity";
import { Result } from "@verixa/shared-kernel";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { createTestPrismaClient, databaseAvailability } from "./helpers/database.js";

const available = await databaseAvailability();

const hasher = new Argon2PasswordHasher({ memoryCost: 64, timeCost: 1, parallelism: 1 });
const notifier = new NullCredentialNotifier();

describe.skipIf(!available)("Credential cleanup on user deletion (Issue 075)", () => {
  const prisma = createTestPrismaClient();
  const userRepo = new PrismaUserRepository(prisma);
  const registerUser = new RegisterUser(userRepo);
  const credentialsUnitOfWork = new PrismaCredentialsUnitOfWork(prisma);
  const registerUserWithPassword = new RegisterUserWithPassword(credentialsUnitOfWork, hasher);
  const requestEmailVerification = new RequestEmailVerification(credentialsUnitOfWork, notifier);
  const requestPasswordReset = new RequestPasswordReset(credentialsUnitOfWork, notifier);
  const handler = new HandleUserDeleted(credentialsUnitOfWork);

  beforeAll(async () => {
    await prisma.$connect();
  }, 60_000);

  afterEach(async () => {
    await prisma.passwordResetToken.deleteMany({});
    await prisma.emailVerificationToken.deleteMany({});
    await prisma.credential.deleteMany({});
    await prisma.organizationMembership.deleteMany({});
    await prisma.organization.deleteMany({});
    await prisma.user.deleteMany({});
  });

  afterAll(async () => {
    await prisma.$disconnect();
  }, 60_000);

  it("should invalidate email verification tokens when user is deleted", async () => {
    const registerResult = await registerUserWithPassword.execute({
      email: "alice@example.com",
      displayName: "Alice",
      password: "correct horse battery staple",
    });
    if (!Result.isOk(registerResult)) throw new Error("Registration failed");

    const userId = registerResult.value.user.id;
    const email = registerResult.value.user.email.value;

    const verifyResult = await requestEmailVerification.execute({ email });
    if (!Result.isOk(verifyResult)) throw new Error("Verification request failed");

    const tokensBefore = await prisma.emailVerificationToken.findMany({ where: { userId } });
    expect(tokensBefore.length).toBeGreaterThan(0);
    expect(tokensBefore.every((t) => t.consumedAt === null)).toBe(true);

    const event = new UserStatusChanged(userId, "active", "deleted");
    await handler.handle(event);

    const tokensAfter = await prisma.emailVerificationToken.findMany({ where: { userId } });
    expect(tokensAfter.length).toBe(tokensBefore.length);
    expect(tokensAfter.every((t) => t.consumedAt !== null)).toBe(true);
  });

  it("should invalidate password reset tokens when user is deleted", async () => {
    const registerResult = await registerUserWithPassword.execute({
      email: "bob@example.com",
      displayName: "Bob",
      password: "correct horse battery staple",
    });
    if (!Result.isOk(registerResult)) throw new Error("Registration failed");

    const userId = registerResult.value.user.id;
    const email = registerResult.value.user.email.value;

    const resetResult = await requestPasswordReset.execute({ email });
    if (!Result.isOk(resetResult)) throw new Error("Password reset request failed");

    const tokensBefore = await prisma.passwordResetToken.findMany({ where: { userId } });
    expect(tokensBefore.length).toBeGreaterThan(0);
    expect(tokensBefore.every((t) => t.consumedAt === null)).toBe(true);

    const event = new UserStatusChanged(userId, "active", "deleted");
    await handler.handle(event);

    const tokensAfter = await prisma.passwordResetToken.findMany({ where: { userId } });
    expect(tokensAfter.length).toBe(tokensBefore.length);
    expect(tokensAfter.every((t) => t.consumedAt !== null)).toBe(true);
  });

  it("should clear credential failure counter on user deletion", async () => {
    const registerResult = await registerUserWithPassword.execute({
      email: "charlie@example.com",
      displayName: "Charlie",
      password: "correct horse battery staple",
    });
    if (!Result.isOk(registerResult)) throw new Error("Registration failed");

    const userId = registerResult.value.user.id;
    const credential = registerResult.value.credential;

    await prisma.credential.update({
      where: { id: credential.id },
      data: {
        failedAttempts: 10,
        lockedUntil: new Date(Date.now() + 1000 * 60 * 5),
      },
    });

    const credentialLocked = await prisma.credential.findUniqueOrThrow({
      where: { id: credential.id },
    });
    expect(credentialLocked.failedAttempts).toBe(10);
    expect(credentialLocked.lockedUntil).not.toBeNull();

    const event = new UserStatusChanged(userId, "active", "deleted");
    await handler.handle(event);

    const credentialAfter = await prisma.credential.findUniqueOrThrow({
      where: { id: credential.id },
    });
    expect(credentialAfter.failedAttempts).toBe(0);
    expect(credentialAfter.lockedUntil).toBeNull();
  });

  it("should not throw if user had no credential record", async () => {
    const registerResult = await registerUser.execute({
      email: "sso-only@example.com",
      displayName: "SSO Only",
    });
    if (!Result.isOk(registerResult)) throw new Error("User registration failed");
    const user = registerResult.value;

    const credentialCount = await prisma.credential.count({ where: { userId: user.id } });
    expect(credentialCount).toBe(0);

    const event = new UserStatusChanged(user.id, "pending", "deleted");
    await expect(handler.handle(event)).resolves.not.toThrow();
  });

  it("should not re-invalidate tokens if handler is called twice", async () => {
    const registerResult = await registerUserWithPassword.execute({
      email: "dave@example.com",
      displayName: "Dave",
      password: "correct horse battery staple",
    });
    if (!Result.isOk(registerResult)) throw new Error("Registration failed");

    const userId = registerResult.value.user.id;
    const email = registerResult.value.user.email.value;

    const verifyResult = await requestEmailVerification.execute({ email });
    if (!Result.isOk(verifyResult)) throw new Error("Verification request failed");

    const token = await prisma.emailVerificationToken.findFirstOrThrow({ where: { userId } });
    const consumedAtFirstCall = token.consumedAt;

    const event = new UserStatusChanged(userId, "active", "deleted");
    await handler.handle(event);

    const consumedAfterFirstCall = (
      await prisma.emailVerificationToken.findUniqueOrThrow({ where: { id: token.id } })
    ).consumedAt;

    await handler.handle(event);

    const consumedAfterSecondCall = (
      await prisma.emailVerificationToken.findUniqueOrThrow({ where: { id: token.id } })
    ).consumedAt;

    expect(consumedAtFirstCall).toBeNull();
    expect(consumedAfterFirstCall).not.toBeNull();
    expect(consumedAfterSecondCall).toBe(consumedAfterFirstCall);
  });

  it("should ignore non-deletion status transitions", async () => {
    const registerResult = await registerUserWithPassword.execute({
      email: "eve@example.com",
      displayName: "Eve",
      password: "correct horse battery staple",
    });
    if (!Result.isOk(registerResult)) throw new Error("Registration failed");

    const userId = registerResult.value.user.id;
    const email = registerResult.value.user.email.value;
    const credential = registerResult.value.credential;

    const verifyResult = await requestEmailVerification.execute({ email });
    if (!Result.isOk(verifyResult)) throw new Error("Verification request failed");

    const suspensionEvent = new UserStatusChanged(userId, "active", "suspended");
    await handler.handle(suspensionEvent);

    const token = await prisma.emailVerificationToken.findFirstOrThrow({ where: { userId } });
    expect(token.consumedAt).toBeNull();

    await prisma.credential.update({
      where: { id: credential.id },
      data: { failedAttempts: 5 },
    });

    await handler.handle(suspensionEvent);

    const credAfter = await prisma.credential.findUniqueOrThrow({ where: { id: credential.id } });
    expect(credAfter.failedAttempts).toBe(5);
  });
});
