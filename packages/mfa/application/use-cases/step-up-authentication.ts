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
