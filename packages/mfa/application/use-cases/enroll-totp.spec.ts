import { createId, Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { MfaMethod } from "../../domain/entities/mfa-method.js";
import type { TotpAlgorithm } from "../../domain/services/totp-algorithm.js";
import type { MfaMethodRepository } from "../ports/mfa-method-repository.js";
import { EnrollTotp } from "./enroll-totp.js";

describe("EnrollTotp", () => {
  it("creates a pending TOTP method and returns the secret once", async () => {
    const savedMethods: MfaMethod[] = [];

    const fakeRepo: MfaMethodRepository = {
      save: async (method) => {
        savedMethods.push(method);
      },
      findById: async () => undefined,
      findActiveByUserId: async () => [],
      findPendingByUserId: async () => [],
      findAllByUserId: async () => [],
      delete: async () => {},
    };

    const fakeAlgo: TotpAlgorithm = {
      generateSecret: async (accountName) => ({
        value: "FAKEBASE32SECRET",
        provisioningUri: `otpauth://totp/Verixa:${accountName}?secret=FAKEBASE32SECRET&issuer=Verixa`,
      }),
      verify: async () => null,
    };

    const useCase = new EnrollTotp(fakeRepo, fakeAlgo);
    const userId = createId<"UserId">();

    const result = await useCase.execute({
      userId,
      accountName: "test@example.com",
    });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    const { methodId, secret, provisioningUri } = result.value;

    expect(secret).toBe("FAKEBASE32SECRET");
    expect(provisioningUri).toContain("test@example.com");

    expect(savedMethods).toHaveLength(1);

    const saved = savedMethods[0]!;
    expect(saved.id).toBe(methodId);
    expect(saved.userId).toBe(userId);
    expect(saved.type).toBe("totp");
    expect(saved.status).toBe("pending");
    expect(saved.secret).toBe("FAKEBASE32SECRET");
  });
});
