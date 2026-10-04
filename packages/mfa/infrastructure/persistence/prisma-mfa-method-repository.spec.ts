import { randomUUID } from "node:crypto";
import { createConnection } from "node:net";

import { PrismaClient } from "@verixa/database";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { MfaMethod, type UserId } from "../../domain/entities/mfa-method.js";
import { mfaMethodRepositoryContract } from "../testing/contracts/mfa-method-repository.contract.js";

import { PrismaMfaMethodRepository } from "./prisma-mfa-method-repository.js";

/**
 * Database-backed tests skip when no Postgres is reachable, so a fresh clone
 * without Docker still gets a green `pnpm test`; `TEST_DATABASE_URL` points at
 * one that is already running (CI service container or `docker compose up
 * postgres`). Mirrors the harness used by `@verixa/identity`.
 */
async function databaseUrl(): Promise<string | undefined> {
  const configured = process.env["TEST_DATABASE_URL"];
  if (configured === undefined) return undefined;

  const url = new URL(configured);
  const reachable = await new Promise<boolean>((resolve) => {
    const socket = createConnection({ host: url.hostname, port: Number(url.port || 5432) });
    const finish = (result: boolean): void => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(result);
    };
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.setTimeout(2_000, () => finish(false));
  });

  return reachable ? configured : undefined;
}

const database = await databaseUrl();

describe.skipIf(database === undefined)("PrismaMfaMethodRepository (real Postgres)", () => {
  // The client is created in `beforeAll`, not eagerly: Vitest still executes a
  // skipped suite's body to collect its tests, so constructing `PrismaClient`
  // here would throw on an undefined datasource URL even when no database is
  // configured — turning the intended skip into a red `pnpm test` on a machine
  // without Docker. Mirrors `@verixa/identity`'s harness.
  let prisma: PrismaClient;

  beforeAll(async () => {
    prisma = new PrismaClient({ datasources: { db: { url: database as string } } });
    await prisma.$connect();
  }, 60_000);

  afterAll(async () => {
    await prisma.$disconnect();
  }, 60_000);

  async function setupUser(): Promise<UserId> {
    const id = randomUUID();
    const now = new Date();
    await prisma.user.create({
      data: {
        id,
        email: `mfa-${id}@example.com`,
        displayName: "MFA Test User",
        status: "active",
        createdAt: now,
        updatedAt: now,
      },
    });
    return id as UserId;
  }

  mfaMethodRepositoryContract(() => new PrismaMfaMethodRepository(prisma), setupUser);

  describe("encryption at rest", () => {
    it("stores the TOTP secret encrypted, and decrypts it on read", async () => {
      const repository = new PrismaMfaMethodRepository(prisma);
      const userId = await setupUser();

      const plaintext = "my-super-secret-totp";
      const method = MfaMethod.create(userId, "totp", plaintext);
      await repository.save(method);

      const rawRow = await prisma.mfaMethod.findUnique({ where: { id: method.id } });
      expect(rawRow?.secret).not.toBeNull();
      expect(rawRow?.secret).not.toBe(plaintext);
      expect(rawRow?.secret).not.toContain(plaintext);

      const fetched = await repository.findById(method.id);
      expect(fetched?.secret).toBe(plaintext);
    });
  });
});
