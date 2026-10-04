import { Result } from "@verixa/shared-kernel";
import {
  BackupCodeSet,
  type BackupCodeGenerationResult,
} from "../../domain/services/backup-code-set.js";
import { MfaMethod, type UserId } from "../../domain/entities/mfa-method.js";
import type { MfaMethodRepository } from "../ports/mfa-method-repository.js";
import type { AuditLogger } from "../ports/audit-logger.js";

export interface GenerateBackupCodesCommand {
  readonly userId: string;
}

export type GenerateBackupCodesResult = Result<BackupCodeGenerationResult, Error>;

export class GenerateBackupCodes {
  constructor(
    private readonly mfaMethodRepository: MfaMethodRepository,
    private readonly auditLogger: AuditLogger,
  ) {}

  async execute(command: GenerateBackupCodesCommand): Promise<GenerateBackupCodesResult> {
    const userId = command.userId as UserId;

    const generationResult = await BackupCodeSet.generate();

    const active = await this.mfaMethodRepository.findActiveByUserId(userId);
    const pending = await this.mfaMethodRepository.findPendingByUserId(userId);
    const existing = [...active, ...pending].filter((m) => m.type === "backup_codes");

    for (const method of existing) {
      await this.mfaMethodRepository.delete(method.id);
    }

    const secret = JSON.stringify(generationResult.hashedCodes);
    const newMethod = MfaMethod.create(userId, "backup_codes", secret);
    newMethod.activate();

    await this.mfaMethodRepository.save(newMethod);

    await this.auditLogger.record("backup_codes.generated", userId, {
      count: generationResult.hashedCodes.length.toString(),
    });

    return Result.ok(generationResult);
  }
}
