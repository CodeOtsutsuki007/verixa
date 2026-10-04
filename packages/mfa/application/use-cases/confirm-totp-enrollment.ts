import { AccountLockedError, Result, ValidationError, asId } from "@verixa/shared-kernel";

import type { MfaMethodRepository } from "../ports/mfa-method-repository.js";
import type { TotpAlgorithm } from "../../domain/services/totp-algorithm.js";

export interface ConfirmTotpEnrollmentCommand {
  readonly methodId: string;
  readonly code: string;
}

export type ConfirmTotpEnrollmentError = Error | AccountLockedError | ValidationError;

/**
 * Verifies a user-submitted TOTP code against a pending method's secret.
 *
 * If the code matches, the method is transitioned to 'active' and can be used
 * for authentication. If incorrect, the method remains 'pending' and the failure
 * is recorded to enforce rate limits (protecting against guessing attacks in the
 * 30-second TOTP window).
 */
export class ConfirmTotpEnrollment {
  constructor(
    private readonly mfaMethodRepository: MfaMethodRepository,
    private readonly totpAlgorithm: TotpAlgorithm,
  ) {}

  async execute(
    command: ConfirmTotpEnrollmentCommand,
  ): Promise<Result<void, ConfirmTotpEnrollmentError>> {
    // 1. Validate inputs (code length check helps avoid unnecessary crypto work)
    if (!command.code || command.code.length !== 6) {
      return Result.err(new ValidationError("TOTP code must be 6 digits."));
    }

    const methodId = asId<"MfaMethodId">(command.methodId);

    // 2. Fetch the pending method
    const method = await this.mfaMethodRepository.findById(methodId);
    if (!method) {
      return Result.err(new Error("MFA method not found."));
    }

    // 3. Reject if already active (Acceptance Criteria 3)
    if (method.status !== "pending") {
      return Result.err(new Error("Method is not in a pending state."));
    }

    // 4. Rate limiting check (Acceptance Criteria 2)
    const now = new Date();
    if (method.isLockedAt(now)) {
      return Result.err(new AccountLockedError("Confirmation attempts are rate-limited."));
    }

    // 5. Verify code
    // Assuming method.secret is present on a pending TOTP method
    if (!method.secret) {
      return Result.err(new Error("MFA method is missing its secret."));
    }

    const matchedStep = await this.totpAlgorithm.verify(method.secret, command.code);
    if (matchedStep === null) {
      const updatedMethod = method.recordFailedAttempt(now);
      await this.mfaMethodRepository.save(updatedMethod);
      return Result.err(new Error("Invalid TOTP code."));
    }

    // 6. On success, activate and reset attempts (Acceptance Criteria 1)
    const activatedMethod = method.activate(now);
    await this.mfaMethodRepository.save(activatedMethod);

    return Result.ok(undefined);
  }
}
