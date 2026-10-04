import { createId, Result } from "@verixa/shared-kernel";
import { describe, expect, it, vi } from "vitest";

import { MfaMethod } from "../../domain/entities/mfa-method.js";
import { InMemoryMfaMethodRepository } from "../../infrastructure/testing/in-memory-mfa-method-repository.js";
import type { AuditLogger } from "../ports/audit-logger.js";
import type { MfaRecoveryAuthorizer } from "../ports/mfa-recovery-authorizer.js";
import type { SessionRevoker } from "../ports/session-revoker.js";
import { RecoverMfaAccess } from "./recover-mfa-access.js";

function setup(options: { authorized?: boolean; sessionsRevoked?: number } = {}) {
  const repository = new InMemoryMfaMethodRepository();
  const auditLogger: AuditLogger = { record: vi.fn().mockResolvedValue(undefined) };
  const authorizer: MfaRecoveryAuthorizer = {
    canRecoverMfaAccess: vi.fn().mockResolvedValue(options.authorized ?? true),
  };
  const sessionRevoker: SessionRevoker = {
    revokeAllForUser: vi.fn().mockResolvedValue(options.sessionsRevoked ?? 3),
  };

  const useCase = new RecoverMfaAccess({
    mfaMethodRepository: repository,
    sessionRevoker,
    authorizer,
    auditLogger,
  });

  return { repository, auditLogger, authorizer, sessionRevoker, useCase };
}

async function seedMethods(
  repository: InMemoryMfaMethodRepository,
  userId: ReturnType<typeof createId<"UserId">>,
): Promise<void> {
  await repository.save(MfaMethod.create(userId, "totp", "secret").activate());
  await repository.save(MfaMethod.create(userId, "webauthn"));
  await repository.save(MfaMethod.create(userId, "totp", "old").disable());
}

describe("RecoverMfaAccess", () => {
  it("clears every method, revokes all sessions, and audit-logs the actor", async () => {
    const { repository, useCase, auditLogger, sessionRevoker } = setup({ sessionsRevoked: 4 });
    const target = createId<"UserId">();
    const actor = createId<"UserId">();
    await seedMethods(repository, target);

    const result = await useCase.execute({
      targetUserId: target,
      actorId: actor,
      reason: "User lost their phone and backup codes",
    });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;
    expect(result.value).toEqual({ methodsCleared: 3, sessionsRevoked: 4 });

    await expect(repository.findAllByUserId(target)).resolves.toHaveLength(0);
    expect(sessionRevoker.revokeAllForUser).toHaveBeenCalledWith(target);
    expect(auditLogger.record).toHaveBeenCalledWith(
      "mfa.recovery.performed",
      actor,
      expect.objectContaining({ targetUserId: target, sessionsRevoked: "4", methodsCleared: "3" }),
    );
  });

  it("rejects an unauthorized actor and changes nothing", async () => {
    const { repository, useCase, sessionRevoker } = setup({ authorized: false });
    const target = createId<"UserId">();
    await seedMethods(repository, target);

    const result = await useCase.execute({
      targetUserId: target,
      actorId: createId<"UserId">(),
      reason: "nope",
    });

    expect(Result.isErr(result)).toBe(true);
    await expect(repository.findAllByUserId(target)).resolves.toHaveLength(3);
    expect(sessionRevoker.revokeAllForUser).not.toHaveBeenCalled();
  });

  it("cannot be self-triggered by the target user", async () => {
    const { repository, useCase, sessionRevoker } = setup();
    const target = createId<"UserId">();
    await seedMethods(repository, target);

    const result = await useCase.execute({
      targetUserId: target,
      actorId: target,
      reason: "self service",
    });

    expect(Result.isErr(result)).toBe(true);
    expect(sessionRevoker.revokeAllForUser).not.toHaveBeenCalled();
  });

  it("clears disabled methods too, leaving nothing to re-use", async () => {
    const { repository, useCase } = setup();
    const target = createId<"UserId">();
    const disabled = MfaMethod.create(target, "totp", "still-has-a-secret").disable();
    await repository.save(disabled);

    await useCase.execute({
      targetUserId: target,
      actorId: createId<"UserId">(),
      reason: "lost device",
    });

    await expect(repository.findById(disabled.id)).resolves.toBeUndefined();
  });
});
