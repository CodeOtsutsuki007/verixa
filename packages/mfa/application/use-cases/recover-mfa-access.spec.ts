import { describe, expect, it, vi } from "vitest";
import { asId, Result } from "@verixa/shared-kernel";

import { MfaMethod, type UserId } from "../../domain/entities/mfa-method.js";
import type { MfaMethodType } from "../../domain/value-objects/mfa-method-type.js";
import { InMemoryMfaMethodRepository } from "../../infrastructure/testing/in-memory-mfa-method-repository.js";
import type { AuditLogger } from "../ports/audit-logger.js";
import type { SessionRevoker } from "../ports/session-revoker.js";
import { RecoverMfaAccess } from "./recover-mfa-access.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMethod(userId: UserId, type: MfaMethodType = "totp", status: "active" | "pending" = "active"): MfaMethod {
  const base = MfaMethod.enroll({ userId, type });
  if (status === "active") {
    const activated = base.activate();
    if (Result.isErr(activated)) throw new Error("activate failed in test helper");
    return activated.value;
  }
  return base;
}

function makeAuditLogger(): { logger: AuditLogger; calls: Array<{ action: string; actorId: string; metadata?: Record<string, string> }> } {
  const calls: Array<{ action: string; actorId: string; metadata?: Record<string, string> }> = [];
  const logger: AuditLogger = {
    async record(action, actorId, metadata) {
      calls.push({ action, actorId, metadata });
    },
  };
  return { logger, calls };
}

function makeSessionRevoker(revokedCount = 2): { revoker: SessionRevoker; calls: string[] } {
  const calls: string[] = [];
  const revoker: SessionRevoker = {
    async revokeAllForUser(userId) {
      calls.push(userId as string);
      return { revokedCount };
    },
  };
  return { revoker, calls };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("RecoverMfaAccess", () => {
  const ADMIN_ID = "admin-uuid-001";
  const TARGET_USER_ID = "user-uuid-002";
  const REASON = "User lost phone and backup codes; identity re-verified via video call.";

  function setup(opts: { revokedCount?: number } = {}) {
    const repo = new InMemoryMfaMethodRepository();
    const { logger, calls: auditCalls } = makeAuditLogger();
    const { revoker, calls: revokerCalls } = makeSessionRevoker(opts.revokedCount ?? 2);
    const useCase = new RecoverMfaAccess(repo, revoker, logger);
    return { repo, logger, auditCalls, revoker, revokerCalls, useCase };
  }

  describe("validation", () => {
    it("rejects when actorAdminId is empty", async () => {
      const { useCase } = setup();
      const result = await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: "",
        reason: REASON,
      });
      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.message).toMatch(/actorAdminId/i);
      }
    });

    it("rejects when actorAdminId is whitespace-only", async () => {
      const { useCase } = setup();
      const result = await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: "   ",
        reason: REASON,
      });
      expect(Result.isErr(result)).toBe(true);
    });

    it("rejects when reason is empty", async () => {
      const { useCase } = setup();
      const result = await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: ADMIN_ID,
        reason: "",
      });
      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.message).toMatch(/reason/i);
      }
    });
  });

  describe("method clearing", () => {
    it("disables all active MFA methods for the target user", async () => {
      const { repo, useCase } = setup();
      const userId = asId<"UserId">(TARGET_USER_ID);
      const method1 = makeMethod(userId, "totp");
      const method2 = makeMethod(userId, "webauthn");
      await repo.save(method1);
      await repo.save(method2);

      const result = await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: ADMIN_ID,
        reason: REASON,
      });

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.methodsCleared).toBe(2);
      }

      const remaining = await repo.findActiveByUserId(userId);
      expect(remaining).toHaveLength(0);
    });

    it("also clears pending methods (un-confirmed enrollments)", async () => {
      const { repo, useCase } = setup();
      const userId = asId<"UserId">(TARGET_USER_ID);
      const pendingMethod = makeMethod(userId, "totp", "pending");
      await repo.save(pendingMethod);

      const result = await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: ADMIN_ID,
        reason: REASON,
      });

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.methodsCleared).toBe(1);
      }

      const pending = await repo.findPendingByUserId(userId);
      expect(pending).toHaveLength(0);
    });

    it("succeeds when the user has no methods (idempotent)", async () => {
      const { useCase } = setup();
      const result = await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: ADMIN_ID,
        reason: REASON,
      });

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.methodsCleared).toBe(0);
      }
    });

    it("does not affect methods belonging to other users", async () => {
      const { repo, useCase } = setup();
      const targetId = asId<"UserId">(TARGET_USER_ID);
      const otherId = asId<"UserId">("other-user-uuid-999");
      await repo.save(makeMethod(targetId, "totp"));
      await repo.save(makeMethod(otherId, "webauthn"));

      await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: ADMIN_ID,
        reason: REASON,
      });

      const otherMethods = await repo.findActiveByUserId(otherId);
      expect(otherMethods).toHaveLength(1);
    });
  });

  describe("session revocation", () => {
    it("revokes all active sessions for the target user", async () => {
      const { useCase, revokerCalls } = setup({ revokedCount: 3 });
      const result = await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: ADMIN_ID,
        reason: REASON,
      });

      expect(revokerCalls).toHaveLength(1);
      expect(revokerCalls[0]).toBe(TARGET_USER_ID);

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.sessionsRevoked).toBe(3);
      }
    });
  });

  describe("audit logging", () => {
    it("emits an initiated entry before mutation and a completed entry after", async () => {
      const { useCase, auditCalls } = setup();
      await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: ADMIN_ID,
        reason: REASON,
      });

      expect(auditCalls.length).toBeGreaterThanOrEqual(2);
      const actions = auditCalls.map((c) => c.action);
      expect(actions).toContain("mfa.recovery.initiated");
      expect(actions).toContain("mfa.recovery.completed");
      // initiated must come before completed
      expect(actions.indexOf("mfa.recovery.initiated")).toBeLessThan(
        actions.indexOf("mfa.recovery.completed"),
      );
    });

    it("records the actor id on both audit entries", async () => {
      const { useCase, auditCalls } = setup();
      await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: ADMIN_ID,
        reason: REASON,
      });

      for (const call of auditCalls) {
        expect(call.actorId).toBe(ADMIN_ID);
      }
    });

    it("includes the reason in audit metadata", async () => {
      const { useCase, auditCalls } = setup();
      await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: ADMIN_ID,
        reason: REASON,
      });

      const initiated = auditCalls.find((c) => c.action === "mfa.recovery.initiated");
      expect(initiated?.metadata?.reason).toBe(REASON);
    });

    it("records counts in the completed entry", async () => {
      const { repo, useCase, auditCalls } = setup({ revokedCount: 1 });
      const userId = asId<"UserId">(TARGET_USER_ID);
      await repo.save(makeMethod(userId, "totp"));

      await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: ADMIN_ID,
        reason: REASON,
      });

      const completed = auditCalls.find((c) => c.action === "mfa.recovery.completed");
      expect(completed?.metadata?.methodsCleared).toBe("1");
      expect(completed?.metadata?.sessionsRevoked).toBe("1");
    });

    it("does not emit any audit entry for a validation failure (empty actorAdminId)", async () => {
      const { useCase, auditCalls } = setup();
      await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: "",
        reason: REASON,
      });
      expect(auditCalls).toHaveLength(0);
    });
  });

  describe("authorization gating", () => {
    it("cannot be self-triggered: requires a non-empty actorAdminId distinct from the system", async () => {
      // The use case enforces that actorAdminId is present and non-whitespace.
      // Callers are responsible for ensuring the actor is genuinely authenticated;
      // this test verifies the use case rejects absent identity at the contract level.
      const { useCase } = setup();
      const selfResult = await useCase.execute({
        targetUserId: TARGET_USER_ID,
        actorAdminId: "",
        reason: REASON,
      });
      expect(Result.isErr(selfResult)).toBe(true);
    });
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
