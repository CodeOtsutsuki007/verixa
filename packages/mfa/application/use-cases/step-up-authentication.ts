import { Result, AccountLockedError, ValidationError, asId } from "@verixa/shared-kernel";
import type { MfaMethodRepository } from "../ports/mfa-method-repository.js";
import type { AuditLogger } from "../ports/audit-logger.js";
import type { TotpAlgorithm } from "../../domain/services/totp-algorithm.js";
import { BackupCodeSet } from "../../domain/services/backup-code-set.js";
import type { SessionRepository } from "../../../sessions/application/ports/session-repository.js";
import type { Session, SessionId } from "../../../sessions/domain/entities/session.js";

export interface StepUpAuthenticationCommand {
  readonly sessionId: string;
  readonly userId: string;
  readonly methodType: "totp" | "backup_codes";
  readonly code: string;
  readonly maxAgeMs?: number;
  readonly now?: Date;
}

export type StepUpAuthenticationResult = Result<Session, Error | AccountLockedError | ValidationError>;

/**
 * Requires re-verification of an active MFA method for an already-authenticated session
 * before allowing a sensitive action, issuing a short-lived stepUpVerifiedAt claim.
 */
export class StepUpAuthentication {
  constructor(
    private readonly mfaMethodRepository: MfaMethodRepository,
    private readonly sessionRepository: SessionRepository,
    private readonly totpAlgorithm: TotpAlgorithm,
    private readonly auditLogger: AuditLogger
  ) {}

  async execute(command: StepUpAuthenticationCommand): Promise<StepUpAuthenticationResult> {
    const now = command.now ?? new Date();
    const sessionId = asId<"SessionId">(command.sessionId);
    const userId = command.userId as any;

    // 1. Fetch the session
    const session = await this.sessionRepository.findById(sessionId);
    if (!session || !session.isActiveAt(now)) {
      return Result.err(new ValidationError("Active session not found."));
    }

    if (session.userId !== userId) {
      return Result.err(new ValidationError("Session does not belong to the specified user."));
    }

    // 2. Verify according to method type reusing existing logic
    if (command.methodType === "totp") {
      if (!command.code || command.code.length !== 6) {
        return Result.err(new ValidationError("TOTP code must be 6 digits."));
      }

      const activeMethods = await this.mfaMethodRepository.findActiveByUserId(userId);
      const totpMethod = activeMethods.find(m => m.type === "totp");
      if (!totpMethod || !totpMethod.secret) {
        return Result.err(new Error("No active TOTP method found."));
      }

      if (totpMethod.isLockedAt(now)) {
        return Result.err(new AccountLockedError("MFA verification is rate-limited."));
      }

      const matchedStep = await this.totpAlgorithm.verify(totpMethod.secret, command.code);
      if (matchedStep === null) {
        const updatedMethod = totpMethod.recordFailedAttempt(now);
        await this.mfaMethodRepository.save(updatedMethod);
        await this.auditLogger.record("step_up.failed", userId, { type: "totp" });
        return Result.err(new Error("Invalid TOTP code."));
      }

      // Reset failed attempts on success
      await this.mfaMethodRepository.save(totpMethod);
    } else if (command.methodType === "backup_codes") {
      if (!command.code) {
        return Result.err(new ValidationError("Backup code is required."));
      }

      const activeMethods = await this.mfaMethodRepository.findActiveByUserId(userId);
      const backupMethod = activeMethods.find(m => m.type === "backup_codes");
      if (!backupMethod || !backupMethod.secret) {
        await this.auditLogger.record("step_up.failed", userId, { type: "backup_codes" });
        return Result.err(new Error("Invalid backup code."));
      }

      let hashes: string[];
      try {
        hashes = JSON.parse(backupMethod.secret);
      } catch {
        return Result.err(new Error("Invalid backup code storage."));
      }

      let matchedIndex = -1;
      for (let i = 0; i < hashes.length; i++) {
        const isValid = await BackupCodeSet.verify(command.code, hashes[i]!);
        if (isValid) {
          matchedIndex = i;
          break;
        }
      }

      if (matchedIndex === -1) {
        await this.auditLogger.record("step_up.failed", userId, { type: "backup_codes" });
        return Result.err(new Error("Invalid backup code."));
      }

      hashes.splice(matchedIndex, 1);
      backupMethod.updateSecret(JSON.stringify(hashes));
      await this.mfaMethodRepository.save(backupMethod);
    } else {
      return Result.err(new ValidationError("Unsupported MFA method type for step-up."));
    }

    // 3. Update session with stepUpVerifiedAt
    const steppedUpSession = session.recordStepUp(now);
    await this.sessionRepository.save(steppedUpSession);

    await this.auditLogger.record("step_up.success", userId, { type: command.methodType });

    return Result.ok(steppedUpSession);
import { asId, Result } from "@verixa/shared-kernel";

import { StepUpAssertion } from "../../domain/value-objects/step-up-assertion.js";
import type { MfaMethodType } from "../../domain/entities/mfa-method.js";
import type { AuditLogger } from "../ports/audit-logger.js";
import type { MfaMethodRepository } from "../ports/mfa-method-repository.js";
import type { StepUpAssertionStore } from "../ports/step-up-assertion-store.js";
import type { ConsumeBackupCode } from "./consume-backup-code.js";
import type { VerifyTotpChallenge } from "./verify-totp-challenge.js";

/** How the caller proves presence for a step-up. */
export type StepUpVerificationMethod =
  | { readonly type: "totp"; readonly methodId: string; readonly code: string }
  | { readonly type: "backup_code"; readonly code: string };

export interface StepUpAuthenticationCommand {
  readonly userId: string;
  readonly method: StepUpVerificationMethod;
}

export interface StepUpAuthenticationResult {
  readonly userId: string;
  readonly methodType: MfaMethodType;
  readonly verifiedAt: Date;
  readonly expiresAt: Date;
}

export interface StepUpAuthenticationDeps {
  readonly mfaMethodRepository: MfaMethodRepository;
  readonly verifyTotpChallenge: VerifyTotpChallenge;
  readonly consumeBackupCode: ConsumeBackupCode;
  readonly assertionStore: StepUpAssertionStore;
  readonly auditLogger?: AuditLogger;
  /** Lifetime of the issued assertion; defaults to five minutes. */
  readonly maxAgeSeconds?: number;
}

const DEFAULT_MAX_AGE_SECONDS = 5 * 60;

/**
 * Re-verifies an enrolled MFA method for an already-authenticated user before a
 * sensitive action, issuing a short-lived assertion instead of a new session.
 *
 * The verification itself is **delegated** — TOTP to {@link VerifyTotpChallenge}
 * and backup codes to {@link ConsumeBackupCode} — so replay rejection, lockout,
 * and single-use consumption behave identically to a login challenge. Duplicating
 * that logic here would mean two places to keep in step, and the step-up path is
 * exactly where a divergence would go unnoticed.
 *
 * WebAuthn has no verification use case in this package yet; when one lands it
 * plugs in as another branch of {@link StepUpVerificationMethod} without
 * changing the assertion machinery.
 */
export class StepUpAuthentication {
  private readonly maxAgeSeconds: number;

  constructor(private readonly deps: StepUpAuthenticationDeps) {
    this.maxAgeSeconds = deps.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;
  }

  async execute(
    command: StepUpAuthenticationCommand,
  ): Promise<Result<StepUpAuthenticationResult, Error>> {
    const userId = command.userId;

    const verified =
      command.method.type === "totp"
        ? await this.verifyTotp(userId, command.method.methodId, command.method.code)
        : await this.verifyBackupCode(userId, command.method.code);

    if (Result.isErr(verified)) {
      return Result.err(verified.error);
    }

    const assertion = StepUpAssertion.issue(
      userId,
      command.method.type === "totp" ? "totp" : "backup_codes",
      this.maxAgeSeconds,
    );
    await this.deps.assertionStore.record(assertion);
    await this.deps.auditLogger?.record("mfa.step_up", userId, { method: assertion.methodType });

    return Result.ok({
      userId,
      methodType: assertion.methodType,
      verifiedAt: assertion.verifiedAt,
      expiresAt: assertion.expiresAt,
    });
  }

  /**
   * Returns the user's current step-up assertion when it is still fresh, or an
   * error when the user must step up again. Sensitive handlers call this before
   * acting.
   */
  async requireFresh(
    userId: string,
    now: Date = new Date(),
  ): Promise<Result<StepUpAssertion, Error>> {
    const assertion = await this.deps.assertionStore.findLatest(userId);
    if (!assertion) {
      return Result.err(new Error("No step-up verification on record."));
    }
    if (!assertion.isFreshAt(now)) {
      return Result.err(new Error("Step-up verification has expired."));
    }
    return Result.ok(assertion);
  }

  private async verifyTotp(
    userId: string,
    methodId: string,
    code: string,
  ): Promise<Result<void, Error>> {
    const method = await this.deps.mfaMethodRepository.findById(asId<"MfaMethodId">(methodId));
    // The method must belong to the caller: verifying someone else's method id
    // would let a valid code from another account satisfy this user's step-up.
    if (!method || method.userId !== userId || method.status !== "active") {
      return Result.err(new Error("No active MFA method for this user."));
    }

    const result = await this.deps.verifyTotpChallenge.execute({ methodId, code });
    return Result.isOk(result) ? Result.ok(undefined) : Result.err(result.error);
  }

  private async verifyBackupCode(userId: string, code: string): Promise<Result<void, Error>> {
    const result = await this.deps.consumeBackupCode.execute({ userId, code });
    if (Result.isErr(result)) {
      return Result.err(result.error);
    }
    if (result.value.kind === "failed") {
      return Result.err(new Error("Invalid backup code."));
    }
    return Result.ok(undefined);
  }
}
