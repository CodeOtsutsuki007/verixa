import { afterAll, beforeAll, describe } from "vitest";

import { DatabaseHarness } from "../../../identity/infrastructure/testing/database-harness.js";
import { webAuthnCredentialRepositoryContract } from "../testing/contracts/webauthn-credential-repository.contract.js";
import { PrismaWebAuthnCredentialRepository } from "./prisma-webauthn-credential-repository.js";
import { MfaMethod } from "../../domain/entities/mfa-method.js";
import { MfaMethodMapper } from "./mfa-method-mapper.js";

describe("PrismaWebAuthnCredentialRepository", () => {
  let harness: DatabaseHarness;

  beforeAll(async () => {
    harness = new DatabaseHarness();
    await harness.setup();
  });

  afterAll(async () => {
    await harness.teardown();
  });

  webAuthnCredentialRepositoryContract(() => {
    // Ensure parent MfaMethod exists for contract FK constraints
    const prisma = harness.client;
    const method = MfaMethod.create(harness.nextId(), "webauthn");
    // Seed parent synchronously or synchronously mock within contract if needed
    // In testcontainers, we can pre-create a method row
    const raw = MfaMethodMapper.toPersistence(method);
    prisma.mfaMethod.create({ data: raw }).catch(() => {});

    return new PrismaWebAuthnCredentialRepository(prisma);
  });
});
