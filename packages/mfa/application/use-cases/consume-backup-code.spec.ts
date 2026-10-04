import { describe, expect, it, vi } from "vitest";
import { ConsumeBackupCode } from "./consume-backup-code.js";
import { InMemoryMfaMethodRepository } from "../../infrastructure/testing/in-memory-mfa-method-repository.js";
import { BackupCodeSet } from "../../domain/services/backup-code-set.js";
import { MfaMethod, type UserId } from "../../domain/entities/mfa-method.js";
import { Result } from "@verixa/shared-kernel";

describe("ConsumeBackupCode", () => {
  it("verifies a valid code, marks it consumed, and signals remaining count", async () => {
    const repo = new InMemoryMfaMethodRepository();
    const auditLogger = { record: vi.fn().mockResolvedValue(undefined) };
    const userId = "user-123" as UserId;

    const generation = await BackupCodeSet.generate(2);
    const method = MfaMethod.create(userId, "backup_codes", JSON.stringify(generation.hashedCodes));
    method.activate();
    await repo.save(method);

    const useCase = new ConsumeBackupCode(repo, auditLogger);
    const rawCode = generation.rawCodes[0]!;

    const result = await useCase.execute({ userId, code: rawCode });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    expect(result.value).toEqual({ kind: "ok", codesRemaining: 1 });

    const updated = await repo.findById(method.id);
    const hashes = JSON.parse(updated!.secret!);
    expect(hashes).toHaveLength(1);
    expect(hashes).not.toContain(generation.hashedCodes[0]);
    expect(hashes).toContain(generation.hashedCodes[1]);

    expect(auditLogger.record).toHaveBeenCalledWith("backup_code.consumed", userId, {
      remaining: "1",
    });
  });

  it("rejects an invalid code", async () => {
    const repo = new InMemoryMfaMethodRepository();
    const auditLogger = { record: vi.fn().mockResolvedValue(undefined) };
    const userId = "user-123" as UserId;

    const generation = await BackupCodeSet.generate(2);
    const method = MfaMethod.create(userId, "backup_codes", JSON.stringify(generation.hashedCodes));
    method.activate();
    await repo.save(method);

    const useCase = new ConsumeBackupCode(repo, auditLogger);

    const result = await useCase.execute({ userId, code: "INVALID-CODE" });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    expect(result.value).toEqual({ kind: "failed" });
    expect(auditLogger.record).toHaveBeenCalledWith("backup_code.failed", userId);
  });

  it("rejects a previously consumed code", async () => {
    const repo = new InMemoryMfaMethodRepository();
    const auditLogger = { record: vi.fn().mockResolvedValue(undefined) };
    const userId = "user-123" as UserId;

    const generation = await BackupCodeSet.generate(2);
    const method = MfaMethod.create(userId, "backup_codes", JSON.stringify(generation.hashedCodes));
    method.activate();
    await repo.save(method);

    const useCase = new ConsumeBackupCode(repo, auditLogger);
    const rawCode = generation.rawCodes[0]!;

    // First use
    await useCase.execute({ userId, code: rawCode });

    // Second use
    const result = await useCase.execute({ userId, code: rawCode });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    expect(result.value).toEqual({ kind: "failed" });
  });

  it("signals exhaustion on the last code", async () => {
    const repo = new InMemoryMfaMethodRepository();
    const auditLogger = { record: vi.fn().mockResolvedValue(undefined) };
    const userId = "user-123" as UserId;

    const generation = await BackupCodeSet.generate(1);
    const method = MfaMethod.create(userId, "backup_codes", JSON.stringify(generation.hashedCodes));
    method.activate();
    await repo.save(method);

    const useCase = new ConsumeBackupCode(repo, auditLogger);
    const rawCode = generation.rawCodes[0]!;

    const result = await useCase.execute({ userId, code: rawCode });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    expect(result.value).toEqual({ kind: "exhausted" });
  });

  it("returns failed if the user has no backup codes active", async () => {
    const repo = new InMemoryMfaMethodRepository();
    const auditLogger = { record: vi.fn().mockResolvedValue(undefined) };
    const userId = "user-123" as UserId;

    const useCase = new ConsumeBackupCode(repo, auditLogger);
    const result = await useCase.execute({ userId, code: "ANY-CODE" });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    expect(result.value).toEqual({ kind: "failed" });
  });
});
