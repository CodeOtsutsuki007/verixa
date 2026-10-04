import { describe, expect, it, vi } from "vitest";
import { Result } from "@verixa/shared-kernel";
import { GenerateBackupCodes } from "./generate-backup-codes.js";
import { InMemoryMfaMethodRepository } from "../../infrastructure/testing/in-memory-mfa-method-repository.js";
import type { AuditLogger } from "../ports/audit-logger.js";
import { MfaMethod, type UserId } from "../../domain/entities/mfa-method.js";

describe("GenerateBackupCodes", () => {
  it("generates new backup codes, persists them, and deletes old ones", async () => {
    const repo = new InMemoryMfaMethodRepository();
    const auditLogger: AuditLogger = {
      record: vi.fn().mockResolvedValue(undefined),
    };

    const userId = "user-123" as UserId;

    // Create an existing backup_codes method
    const oldMethod = MfaMethod.create(userId, "backup_codes", "old-hashes");
    oldMethod.activate();
    await repo.save(oldMethod);

    // Create another MFA method (e.g. totp) to ensure we don't delete unrelated ones
    const totpMethod = MfaMethod.create(userId, "totp", "totp-secret");
    totpMethod.activate();
    await repo.save(totpMethod);

    const useCase = new GenerateBackupCodes(repo, auditLogger);
    const result = await useCase.execute({ userId });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    const generation = result.value;
    expect(generation.rawCodes).toHaveLength(10);
    expect(generation.hashedCodes).toHaveLength(10);

    const allMethods = await repo.findAll();

    // The old backup_codes method should be gone
    expect(allMethods.find((m) => m.id === oldMethod.id)).toBeUndefined();

    // The totp method should still be there
    expect(allMethods.find((m) => m.id === totpMethod.id)).toBeDefined();

    // A new backup_codes method should be created
    const newBackupCodes = allMethods.filter((m) => m.type === "backup_codes");
    expect(newBackupCodes).toHaveLength(1);

    const newMethod = newBackupCodes[0];
    expect(newMethod?.userId).toBe(userId);
    expect(newMethod?.status).toBe("active");
    expect(newMethod?.secret).toBe(JSON.stringify(generation.hashedCodes));

    expect(auditLogger.record).toHaveBeenCalledWith("backup_codes.generated", userId, {
      count: "10",
    });
  });
});
