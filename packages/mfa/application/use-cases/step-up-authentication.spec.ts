import { asId } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";
import { StepUpAuthentication } from "./step-up-authentication.js";
import { InMemoryMfaMethodRepository } from "../../infrastructure/fakes/in-memory-mfa-method-repository.js";
import { MfaMethod, type UserId } from "../../domain/entities/mfa-method.js";
import { TotpAlgorithm } from "../../domain/services/totp-algorithm.js";
import { TotpSecret } from "../../domain/value-objects/totp-secret.js";
import { InMemorySessionRepository } from "../../../sessions/infrastructure/testing/in-memory-session-repository.js";
import { Session, type SessionUserId } from "../../../sessions/domain/entities/session.js";
import { BackupCodeSet } from "../../domain/services/backup-code-set.js";

class FakeAuditLogger {
  async record(event: string, userId: string, metadata?: Record<string, string>): Promise<void> {}
}

const userId = asId<"UserId">("11111111-1111-1111-1111-111111111111");

describe("StepUpAuthentication", () => {
  let mfaMethodRepository: InMemoryMfaMethodRepository;
  let sessionRepository: InMemorySessionRepository;
  let totpAlgorithm: TotpAlgorithm;
  let auditLogger: FakeAuditLogger;
  let stepUpAuthentication: StepUpAuthentication;

  beforeEach(async () => {
    mfaMethodRepository = new InMemoryMfaMethodRepository();
    sessionRepository = new InMemorySessionRepository();
    totpAlgorithm = new TotpAlgorithm();
    auditLogger = new FakeAuditLogger();
    stepUpAuthentication = new StepUpAuthentication(
      mfaMethodRepository,
      sessionRepository,
      totpAlgorithm,
      auditLogger
    );
  });

  it("succeeds with fresh TOTP verification and updates session stepUpVerifiedAt", async () => {
    const now = new Date("2026-01-01T00:00:00Z");
    const secretResult = TotpSecret.generate();
    const secret = secretResult.value.secret;

    const method = MfaMethod.create(userId, "totp", secret);
    const activated = method.activate(now);
    await mfaMethodRepository.save(activated);

    const validCode = totpAlgorithm.generate(secret, now);

    const sessionIssuance = Session.issue({
      userId,
      metadata: {},
      accessToken: { tokenId: "token-1", expiresAt: new Date(now.getTime() + 60_000) },
      now,
    });
    await sessionRepository.save(sessionIssuance.session);

    const result = await stepUpAuthentication.execute({
      sessionId: sessionIssuance.session.id,
      userId,
      methodType: "totp",
      code: validCode,
      now,
    });

    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") throw new Error("unreachable");
    expect(result.value.stepUpVerifiedAt).toEqual(now);
    expect(result.value.isStepUpFresh(300_000, now)).toBe(true);
  });

  it("rejects stale step-up state when max age has passed", async () => {
    const now = new Date("2026-01-01T00:00:00Z");
    const sessionIssuance = Session.issue({
      userId,
      metadata: {},
      accessToken: { tokenId: "token-1", expiresAt: new Date(now.getTime() + 60_000) },
      now,
    });
    const steppedUp = sessionIssuance.session.recordStepUp(now);

    const later = new Date(now.getTime() + 400_000);
    expect(steppedUp.isStepUpFresh(300_000, later)).toBe(false);
  });

  it("succeeds using backup codes and updates session stepUpVerifiedAt", async () => {
    const now = new Date("2026-01-01T00:00:00Z");
    const gen = await BackupCodeSet.generate();
    const backupMethod = MfaMethod.create(userId, "backup_codes", JSON.stringify(gen.hashedCodes));
    backupMethod.activate(now);
    await mfaMethodRepository.save(backupMethod);

    const sessionIssuance = Session.issue({
      userId,
      metadata: {},
      accessToken: { tokenId: "token-1", expiresAt: new Date(now.getTime() + 60_000) },
      now,
    });
    await sessionRepository.save(sessionIssuance.session);

    const result = await stepUpAuthentication.execute({
      sessionId: sessionIssuance.session.id,
      userId,
      methodType: "backup_codes",
      code: gen.rawCodes[0]!,
      now,
    });

    expect(result.kind).toBe(
      "ok"
    );
    if (result.kind !== "ok") throw new Error("unreachable");
    expect(result.value.stepUpVerifiedAt).toEqual(now);
import { createId, Result } from "@verixa/shared-kernel";
import { describe, expect, it, vi } from "vitest";

import { MfaMethod } from "../../domain/entities/mfa-method.js";
import { BackupCodeSet } from "../../domain/services/backup-code-set.js";
import { StepUpAssertion } from "../../domain/value-objects/step-up-assertion.js";
import type { TotpAlgorithm } from "../../domain/services/totp-algorithm.js";
import { InMemoryMfaMethodRepository } from "../../infrastructure/testing/in-memory-mfa-method-repository.js";
import type { StepUpAssertionStore } from "../ports/step-up-assertion-store.js";
import { ConsumeBackupCode } from "./consume-backup-code.js";
import { StepUpAuthentication } from "./step-up-authentication.js";
import { VerifyTotpChallenge } from "./verify-totp-challenge.js";

class InMemoryStepUpAssertionStore implements StepUpAssertionStore {
  private latest = new Map<string, StepUpAssertion>();

  async record(assertion: StepUpAssertion): Promise<void> {
    this.latest.set(assertion.userId, assertion);
  }

  async findLatest(userId: string): Promise<StepUpAssertion | undefined> {
    return this.latest.get(userId);
  }
}

const fakeTotpAlgorithm: TotpAlgorithm = {
  generateSecret: async () => ({ value: "SECRET", provisioningUri: "uri" }),
  verify: async (_secret, code) => (code === "123456" ? 1000 : null),
};

function setup() {
  const repository = new InMemoryMfaMethodRepository();
  const assertionStore = new InMemoryStepUpAssertionStore();
  const auditLogger = { record: vi.fn().mockResolvedValue(undefined) };
  const verifyTotpChallenge = new VerifyTotpChallenge(repository, fakeTotpAlgorithm);
  const consumeBackupCode = new ConsumeBackupCode(repository, auditLogger);

  const useCase = new StepUpAuthentication({
    mfaMethodRepository: repository,
    verifyTotpChallenge,
    consumeBackupCode,
    assertionStore,
    auditLogger,
  });

  return { repository, assertionStore, auditLogger, verifyTotpChallenge, consumeBackupCode, useCase };
}

describe("StepUpAuthentication", () => {
  it("verifies a TOTP code and issues a short-lived assertion", async () => {
    const { repository, useCase, auditLogger } = setup();
    const userId = createId<"UserId">();
    const method = MfaMethod.createPendingTotp(userId, { value: "SECRET" }).activate();
    await repository.save(method);

    const result = await useCase.execute({
      userId,
      method: { type: "totp", methodId: method.id, code: "123456" },
    });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;
    expect(result.value.methodType).toBe("totp");
    expect(result.value.expiresAt.getTime()).toBeGreaterThan(result.value.verifiedAt.getTime());
    expect(auditLogger.record).toHaveBeenCalledWith("mfa.step_up", userId, { method: "totp" });
  });

  it("reuses VerifyTotpChallenge rather than re-implementing verification", async () => {
    const { repository, useCase, verifyTotpChallenge } = setup();
    const userId = createId<"UserId">();
    const method = MfaMethod.createPendingTotp(userId, { value: "SECRET" }).activate();
    await repository.save(method);

    const spy = vi.spyOn(verifyTotpChallenge, "execute");
    await useCase.execute({
      userId,
      method: { type: "totp", methodId: method.id, code: "123456" },
    });

    expect(spy).toHaveBeenCalledWith({ methodId: method.id, code: "123456" });
  });

  it("verifies a backup code through ConsumeBackupCode", async () => {
    const { repository, useCase, consumeBackupCode } = setup();
    const userId = createId<"UserId">();
    const generation = await BackupCodeSet.generate(1);
    const method = MfaMethod.create(userId, "backup_codes", JSON.stringify(generation.hashedCodes));
    method.activate();
    await repository.save(method);

    const spy = vi.spyOn(consumeBackupCode, "execute");
    const result = await useCase.execute({
      userId,
      method: { type: "backup_code", code: generation.rawCodes[0]! },
    });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;
    expect(result.value.methodType).toBe("backup_codes");
    expect(spy).toHaveBeenCalledOnce();
  });

  it("rejects a method that belongs to another user", async () => {
    const { repository, useCase } = setup();
    const owner = createId<"UserId">();
    const attacker = createId<"UserId">();
    const method = MfaMethod.createPendingTotp(owner, { value: "SECRET" }).activate();
    await repository.save(method);

    const result = await useCase.execute({
      userId: attacker,
      method: { type: "totp", methodId: method.id, code: "123456" },
    });

    expect(Result.isErr(result)).toBe(true);
  });

  it("rejects a stale assertion in requireFresh", async () => {
    const { assertionStore, useCase } = setup();
    const userId = createId<"UserId">();
    const now = new Date();
    await assertionStore.record(
      StepUpAssertion.from({
        userId,
        methodType: "totp",
        verifiedAt: new Date(now.getTime() - 10 * 60 * 1000),
        expiresAt: new Date(now.getTime() - 5 * 60 * 1000),
      }),
    );

    const result = await useCase.requireFresh(userId, now);
    expect(Result.isErr(result)).toBe(true);
  });

  it("accepts a fresh assertion in requireFresh", async () => {
    const { assertionStore, useCase } = setup();
    const userId = createId<"UserId">();
    const now = new Date();
    await assertionStore.record(
      StepUpAssertion.from({
        userId,
        methodType: "totp",
        verifiedAt: new Date(now.getTime() - 60 * 1000),
        expiresAt: new Date(now.getTime() + 4 * 60 * 1000),
      }),
    );

    const result = await useCase.requireFresh(userId, now);
    expect(Result.isOk(result)).toBe(true);
  });

  it("reports no step-up when none was ever performed", async () => {
    const { useCase } = setup();
    const result = await useCase.requireFresh(createId<"UserId">());
    expect(Result.isErr(result)).toBe(true);
  });
});
