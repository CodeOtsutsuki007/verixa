import { AccountLockedError, createId, Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { MfaMethod } from "../../domain/entities/mfa-method.js";
import type { TotpAlgorithm } from "../../domain/services/totp-algorithm.js";
import type { MfaMethodRepository } from "../ports/mfa-method-repository.js";
import { ConfirmTotpEnrollment } from "./confirm-totp-enrollment.js";

describe("ConfirmTotpEnrollment", () => {
  const setup = () => {
    const savedMethods = new Map<string, MfaMethod>();

    const fakeRepo: MfaMethodRepository = {
      save: async (method) => {
        savedMethods.set(method.id, method);
      },
      findById: async (id) => savedMethods.get(id),
      findActiveByUserId: async () => [],
      findPendingByUserId: async () => [],
      findAllByUserId: async () => [],
      delete: async () => {},
    };

    const fakeAlgo: TotpAlgorithm = {
      generateSecret: async () => ({ value: "SECRET", provisioningUri: "uri" }),
      verify: async (_secret, code) => (code === "123456" ? 1000 : null),
    };

    const useCase = new ConfirmTotpEnrollment(fakeRepo, fakeAlgo);

    return { fakeRepo, fakeAlgo, useCase, savedMethods };
  };

  it("activates the method when given the correct code", async () => {
    const { useCase, fakeRepo, savedMethods } = setup();
    const method = MfaMethod.createPendingTotp(createId<"UserId">(), { value: "SECRET" });
    await fakeRepo.save(method);

    const result = await useCase.execute({
      methodId: method.id,
      code: "123456", // correct code
    });

    expect(Result.isOk(result)).toBe(true);
    const updated = savedMethods.get(method.id)!;
    expect(updated.status).toBe("active");
    expect(updated.failedAttempts).toBe(0);
  });

  it("leaves the method pending and records a failed attempt on bad code", async () => {
    const { useCase, fakeRepo, savedMethods } = setup();
    const method = MfaMethod.createPendingTotp(createId<"UserId">(), { value: "SECRET" });
    await fakeRepo.save(method);

    const result = await useCase.execute({
      methodId: method.id,
      code: "000000", // wrong code
    });

    expect(Result.isErr(result)).toBe(true);
    const updated = savedMethods.get(method.id)!;
    expect(updated.status).toBe("pending");
    expect(updated.failedAttempts).toBe(1);
  });

  it("rejects confirmation if the method is already active", async () => {
    const { useCase, fakeRepo } = setup();
    const method = MfaMethod.createPendingTotp(createId<"UserId">(), { value: "SECRET" }).activate();
    await fakeRepo.save(method);

    const result = await useCase.execute({
      methodId: method.id,
      code: "123456",
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.message).toContain("not in a pending state");
    }
  });

  it("rate limits confirmation attempts after consecutive failures", async () => {
    const { useCase, fakeRepo } = setup();
    let method = MfaMethod.createPendingTotp(createId<"UserId">(), { value: "SECRET" });

    // Simulate 5 failures
    for (let i = 0; i < 5; i += 1) {
      method = method.recordFailedAttempt(new Date());
    }
    await fakeRepo.save(method);

    const result = await useCase.execute({
      methodId: method.id,
      code: "123456", // Even correct code should be rejected
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBeInstanceOf(AccountLockedError);
    }
  });
});
