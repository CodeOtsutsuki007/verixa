import { createId } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { MfaMethodRepository } from "../../../application/ports/mfa-method-repository.js";
import { MfaMethod, type UserId } from "../../../domain/entities/mfa-method.js";

/**
 * The shared behavioural contract every `MfaMethodRepository` implementation
 * must satisfy — asserted against both the in-memory fake and the Prisma
 * adapter, so "the fake behaves like the real thing" is proven rather than
 * assumed.
 *
 * `setupUser` must return a persisted `UserId` when the implementation enforces
 * foreign keys (Postgres); the in-memory fake, which has no referential
 * integrity, gets a random id by default.
 */
export function mfaMethodRepositoryContract(
  createRepository: () => MfaMethodRepository,
  setupUser: () => Promise<UserId> = async () => createId<"UserId">(),
): void {
  describe("MfaMethodRepository contract", () => {
    it("returns undefined for a method that was never saved", async () => {
      const repository = createRepository();
      await expect(repository.findById(createId<"MfaMethodId">())).resolves.toBeUndefined();
    });

    it("saves and finds a method by id", async () => {
      const repository = createRepository();
      const userId = await setupUser();
      const method = MfaMethod.create(userId, "totp", "super-secret");

      await repository.save(method);
      const found = await repository.findById(method.id);

      expect(found?.id).toBe(method.id);
      expect(found?.userId).toBe(userId);
      expect(found?.type).toBe("totp");
      expect(found?.status).toBe("pending");
      expect(found?.secret).toBe("super-secret");
    });

    it("save is an idempotent upsert", async () => {
      const repository = createRepository();
      const userId = await setupUser();
      const method = MfaMethod.create(userId, "totp", "secret");
      await repository.save(method);

      await repository.save(method.activate());

      const found = await repository.findById(method.id);
      expect(found?.status).toBe("active");
    });

    it("filters active methods by user id", async () => {
      const repository = createRepository();
      const userId = await setupUser();
      const otherUserId = await setupUser();

      const activeForUser = MfaMethod.create(userId, "totp", "a").activate();
      const pendingForUser = MfaMethod.create(userId, "webauthn");
      const activeForOther = MfaMethod.create(otherUserId, "totp", "b").activate();

      await repository.save(activeForUser);
      await repository.save(pendingForUser);
      await repository.save(activeForOther);

      const active = await repository.findActiveByUserId(userId);
      expect(active).toHaveLength(1);
      expect(active[0]?.id).toBe(activeForUser.id);
    });

    it("filters pending methods by user id", async () => {
      const repository = createRepository();
      const userId = await setupUser();
      const otherUserId = await setupUser();

      const pendingForUser = MfaMethod.create(userId, "totp", "p");
      const activeForUser = MfaMethod.create(userId, "webauthn").activate();
      const pendingForOther = MfaMethod.create(otherUserId, "totp", "q");

      await repository.save(pendingForUser);
      await repository.save(activeForUser);
      await repository.save(pendingForOther);

      const pending = await repository.findPendingByUserId(userId);
      expect(pending).toHaveLength(1);
      expect(pending[0]?.id).toBe(pendingForUser.id);
    });

    it("finds every method for a user regardless of status", async () => {
      const repository = createRepository();
      const userId = await setupUser();

      const pending = MfaMethod.create(userId, "totp", "p");
      const active = MfaMethod.create(userId, "webauthn").activate();
      const disabled = MfaMethod.create(userId, "totp", "d").disable();

      await repository.save(pending);
      await repository.save(active);
      await repository.save(disabled);

      const all = await repository.findAllByUserId(userId);
      expect(all.map((m) => m.id).sort()).toEqual([pending.id, active.id, disabled.id].sort());
    });

    it("deletes a method", async () => {
      const repository = createRepository();
      const userId = await setupUser();
      const method = MfaMethod.create(userId, "webauthn");

      await repository.save(method);
      await repository.delete(method.id);

      await expect(repository.findById(method.id)).resolves.toBeUndefined();
    });
  });
}
