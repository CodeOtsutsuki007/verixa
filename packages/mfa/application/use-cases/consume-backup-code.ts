import { Result } from "@verixa/shared-kernel";
import { BackupCodeSet } from "../../domain/services/backup-code-set.js";
import type { UserId } from "../../domain/entities/mfa-method.js";
import type { MfaMethodRepository } from "../ports/mfa-method-repository.js";
import type { AuditLogger } from "../ports/audit-logger.js";

export interface ConsumeBackupCodeCommand {
  readonly userId: string;
  readonly code: string;
}

export type ConsumeBackupCodeOutcome =
  | { readonly kind: "ok"; readonly codesRemaining: number }
  | { readonly kind: "exhausted" }
  | { readonly kind: "failed" };

export type ConsumeBackupCodeResult = Result<ConsumeBackupCodeOutcome, Error>;

export class ConsumeBackupCode {
  constructor(
    private readonly mfaMethodRepository: MfaMethodRepository,
    private readonly auditLogger: AuditLogger,
  ) {}

  async execute(command: ConsumeBackupCodeCommand): Promise<ConsumeBackupCodeResult> {
    const userId = command.userId as UserId;

    const activeMethods = await this.mfaMethodRepository.findActiveByUserId(userId);
    const backupMethod = activeMethods.find((m) => m.type === "backup_codes");

    if (!backupMethod || !backupMethod.secret) {
      // Intentionally taking the same time as a failure?
      // Actually we should burn time here to prevent timing attacks,
      // but without a decoy hash, we can't easily burn time.
      // For now we'll just fail.
      return Result.ok({ kind: "failed" });
    }

    let hashes: string[];
    try {
      hashes = JSON.parse(backupMethod.secret);
    } catch {
      return Result.ok({ kind: "failed" });
    }

    let matchedIndex = -1;

    // Hashing is expensive. We verify sequentially until a match is found.
    // If it's an attack, they will pay the cost of verifying all remaining hashes.
    for (let i = 0; i < hashes.length; i++) {
      const isValid = await BackupCodeSet.verify(command.code, hashes[i]!);
      if (isValid) {
        matchedIndex = i;
        break;
      }
    }

    if (matchedIndex === -1) {
      await this.auditLogger.record("backup_code.failed", userId);
      return Result.ok({ kind: "failed" });
    }

    // Match found. Consume the code by removing its hash.
    hashes.splice(matchedIndex, 1);

    // Update the record with the remaining hashes.
    backupMethod.updateSecret(JSON.stringify(hashes));
    await this.mfaMethodRepository.save(backupMethod);

    await this.auditLogger.record("backup_code.consumed", userId, {
      remaining: hashes.length.toString(),
    });

    if (hashes.length === 0) {
      return Result.ok({ kind: "exhausted" });
    }

    return Result.ok({ kind: "ok", codesRemaining: hashes.length });
  }
}
