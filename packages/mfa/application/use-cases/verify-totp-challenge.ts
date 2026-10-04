import { AccountLockedError, Result, ValidationError, asId } from "@verixa/shared-kernel";

import type { MfaMethodRepository } from "../ports/mfa-method-repository.js";
import type { TotpAlgorithm } from "../../domain/services/totp-algorithm.js";

export interface VerifyTotpChallengeCommand {
  readonly methodId: string;
  readonly code: string;
}

export type VerifyTotpChallengeError = Error | AccountLockedError | ValidationError;

/**
 * Verifies a submitted TOTP code against an active method during login or step-up.
 *
 * Allows a minor configurable clock drift (e.g. �1 step) but strictly rejects
 * code reuse within the same step. On success, updates the method's lastUsedAt
 * and lastUsedStep to prevent replay.
 */
export class VerifyTotpChallenge {
  constructor(
    private readonly mfaMethodRepository: MfaMethodRepository,
    private readonly totpAlgorithm: TotpAlgorithm,
  ) {}

  async execute(
    command: VerifyTotpChallengeCommand,
  ): Promise<Result<void, VerifyTotpChallengeError>> {
    if (!command.code || command.code.length !== 6) {
      return Result.err(new ValidationError("TOTP code must be 6 digits."));
    }

    const methodId = asId<"MfaMethodId">(command.methodId);
    const method = await this.mfaMethodRepository.findById(methodId);

    if (!method) {
      return Result.err(new Error("MFA method not found."));
    }

    if (method.status !== "active") {
      return Result.err(new Error("Method is not active."));
    }

    const now = new Date();
    if (method.isLockedAt(now)) {
      return Result.err(new AccountLockedError("Authentication attempts are rate-limited."));
    }

    if (!method.secret) {
      return Result.err(new Error("MFA method is missing its secret."));
    }

    // Verify code, allowing �1 drift window (30s past or future)
    const matchedStep = await this.totpAlgorithm.verify(method.secret, command.code, 1);

    if (matchedStep === null) {
      const updatedMethod = method.recordFailedAttempt(now);
      await this.mfaMethodRepository.save(updatedMethod);
      return Result.err(new Error("Invalid TOTP code."));
    }

    try {
      // Record use updates lastUsedAt and enforces replay protection against the matchedStep
      const verifiedMethod = method.recordUse(matchedStep, now);
      await this.mfaMethodRepository.save(verifiedMethod);
      return Result.ok(undefined);
    } catch (err) {
      // Replay detected
      const updatedMethod = method.recordFailedAttempt(now);
      await this.mfaMethodRepository.save(updatedMethod);
      return Result.err(new Error("Code has already been used."));
    }
  }
}
