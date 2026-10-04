import { Result } from "@verixa/shared-kernel";

import type { UserId } from "../../domain/entities/mfa-method.js";
import type { AuditLogger } from "../ports/audit-logger.js";
import type { MfaMethodRepository } from "../ports/mfa-method-repository.js";
import type { MfaRecoveryAuthorizer } from "../ports/mfa-recovery-authorizer.js";
import type { SessionRevoker } from "../ports/session-revoker.js";

export interface RecoverMfaAccessCommand {
  /** The user who has lost access to every enrolled factor and backup code. */
  readonly targetUserId: string;
  /** The elevated actor performing the recovery. */
  readonly actorId: string;
  /** Free-text justification, recorded in the audit log. */
  readonly reason: string;
}

export interface RecoverMfaAccessResult {
  readonly methodsCleared: number;
  readonly sessionsRevoked: number;
}

export interface RecoverMfaAccessDeps {
  readonly mfaMethodRepository: MfaMethodRepository;
  readonly sessionRevoker: SessionRevoker;
  readonly authorizer: MfaRecoveryAuthorizer;
  readonly auditLogger: AuditLogger;
}

/**
 * Last-resort recovery for a user who has lost access to all enrolled MFA
 * methods and exhausted their backup codes.
 *
 * ## Why this is not self-service
 *
 * Every MFA recovery path is a potential MFA bypass in disguise. The classic
 * real-world attack is social-engineering a support agent into "helping" an
 * attacker recover access, so this flow deliberately requires a strongly
 * authorized, audit-logged action by a *different* principal rather than a
 * convenient unauthenticated reset. The authorization check is a port
 * (`MfaRecoveryAuthorizer`), and the actor identity is always recorded.
 *
 * ## What recovery does — and does not do
 *
 * 1. **Clears every enrolled method** (active, pending, and disabled) instead of
 *    silently reactivating or deleting only the active ones. A leftover pending
 *    method whose secret the attacker already saw would otherwise survive.
 * 2. **Revokes all active sessions** as a precaution: the lost device may still
 *    hold a live session, and recovery must not leave it usable.
 * 3. **Returns the user to a re-enrollment state.** Because no method remains,
 *    an enforcement policy of `required` (see `MfaEnforcementPolicy`) reports
 *    `requiresEnrollment`, forcing re-enrollment on next login — recovery
 *    cannot be used to end up with *less* MFA than before.
 */
export class RecoverMfaAccess {
  constructor(private readonly deps: RecoverMfaAccessDeps) {}

  async execute(command: RecoverMfaAccessCommand): Promise<Result<RecoverMfaAccessResult, Error>> {
    // A user cannot recover their own access this way; that would make the
    // authorization gate meaningless for anyone who has a valid session.
    if (command.actorId === command.targetUserId) {
      return Result.err(new Error("MFA recovery cannot be self-triggered."));
    }

    const authorized = await this.deps.authorizer.canRecoverMfaAccess(command.actorId);
    if (!authorized) {
      return Result.err(new Error("Actor is not authorized to recover MFA access."));
    }

    const targetUserId = command.targetUserId as UserId;
    const methods = await this.deps.mfaMethodRepository.findAllByUserId(targetUserId);
    for (const method of methods) {
      await this.deps.mfaMethodRepository.delete(method.id);
    }

    const sessionsRevoked = await this.deps.sessionRevoker.revokeAllForUser(command.targetUserId);

    await this.deps.auditLogger.record("mfa.recovery.performed", command.actorId, {
      targetUserId: command.targetUserId,
      reason: command.reason,
      methodsCleared: String(methods.length),
      sessionsRevoked: String(sessionsRevoked),
    });

    return Result.ok({ methodsCleared: methods.length, sessionsRevoked });
  }
}
