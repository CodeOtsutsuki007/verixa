import { asId, NotFoundError, Result, ValidationError } from "@verixa/shared-kernel";

import type { MfaMethod } from "../../domain/entities/mfa-method.js";
import type { AuditLogger } from "../ports/audit-logger.js";
import type { MfaMethodRepository } from "../ports/mfa-method-repository.js";
import type { SessionRevoker } from "../ports/session-revoker.js";

export interface RecoverMfaAccessCommand {
  /** The user whose MFA access is being recovered. */
  readonly targetUserId: string;
  /**
   * The administrator (or automated system acting as one) that authorised
   * the recovery. Must be a distinct, authenticated actor — the flow cannot
   * be self-triggered.
   *
   * The command is typed as `string` (a raw id) because the use case does
   * not need to load the actor's User record; it only needs the id for the
   * audit trail. The caller (route handler or admin service) is responsible
   * for ensuring the actor is genuinely authenticated and authorised before
   * constructing this command.
   */
  readonly actorAdminId: string;
  /**
   * Free-form reason recorded in the audit log. Mandatory so that each
   * recovery event carries a human-readable explanation, which is the first
   * thing an investigator looks for when reviewing the log.
   */
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
  /** How many MFA methods were disabled. */
  readonly methodsCleared: number;
  /** How many sessions were revoked. */
  readonly sessionsRevoked: number;
}

export type RecoverMfaAccessError = ValidationError | NotFoundError;

/**
 * Admin-initiated recovery for a user who has lost access to all enrolled
 * MFA methods and exhausted backup codes.
 *
 * ## What this does
 *
 * 1. Validates the command (non-empty actor, non-empty reason).
 * 2. Loads all MFA methods for the target user (active + pending).
 * 3. Disables every method found. Disabling — not deleting — preserves the
 *    audit trail: a later review can see which methods existed and when they
 *    were disabled; hard-deleting would destroy that evidence.
 * 4. Revokes all of the user's active sessions immediately, so any attacker
 *    who triggered the recovery socially cannot use an existing session.
 * 5. Emits an audit log entry with the actor id, target id, reason, and
 *    counts, before and after the mutation so the record is durable even if
 *    a subsequent step fails.
 *
 * ## Why the recovery cannot be self-triggered
 *
 * If a user could recover their own MFA access without a separate elevated
 * action, the recovery path becomes an MFA bypass: an attacker who knows the
 * user's password can just "recover" and skip the second factor. Requiring a
 * distinct authenticated admin actor — whose own authentication is separately
 * gated — closes that hole.
 *
 * ## Re-enrollment on next login
 *
 * This use case does not enroll new methods. It only disables the old ones
 * and revokes sessions. The next time the user authenticates, the login flow
 * (Issue 116) will detect that they have no active methods under a `required`
 * policy and gate on enrollment. The use case does not need to know about
 * that flow; returning a clean state is its entire job.
 *
 * ## Alternative rejected: silently reactivating methods
 *
 * Clearing the `disabled` flag on existing methods (instead of disabling and
 * re-enrolling) would restore a compromised secret — a TOTP secret that was
 * phished or leaked would become active again. Disabling forces fresh
 * enrollment with a freshly generated secret.
 */
export class RecoverMfaAccess {
  constructor(
    private readonly mfaMethodRepository: MfaMethodRepository,
    private readonly sessionRevoker: SessionRevoker,
    private readonly auditLogger: AuditLogger,
  ) {}

  async execute(
    command: RecoverMfaAccessCommand,
  ): Promise<Result<RecoverMfaAccessResult, RecoverMfaAccessError>> {
    // Validate inputs before touching any state.
    if (!command.actorAdminId.trim()) {
      return Result.err(
        new ValidationError("actorAdminId is required — recovery must be admin-initiated.", {
          actorAdminId: ["required"],
        }),
      );
    }
    if (!command.reason.trim()) {
      return Result.err(
        new ValidationError("reason is required — every recovery must carry a human-readable justification.", {
          reason: ["required"],
        }),
      );
    }

    const targetUserId = asId<"UserId">(command.targetUserId);
    const actorAdminId = command.actorAdminId;

    // Emit an audit entry *before* mutating state. If the process dies mid-
    // execution, the log still records that a recovery was initiated.
    await this.auditLogger.record("mfa.recovery.initiated", actorAdminId, {
      targetUserId: command.targetUserId,
      reason: command.reason,
    });

    // Load all methods — active and pending. Pending methods must also be
    // cleared: a pending TOTP secret is still a secret that could be phished.
    const [activeMethods, pendingMethods] = await Promise.all([
      this.mfaMethodRepository.findActiveByUserId(targetUserId),
      this.mfaMethodRepository.findPendingByUserId(targetUserId),
    ]);

    const allMethods: MfaMethod[] = [...activeMethods, ...pendingMethods];

    // Disable every method. The domain's `disable()` returns a Result; the
    // only failure case is "already disabled", which cannot happen here since
    // we only loaded active and pending methods. We treat it defensively but
    // do not abort — a method that is somehow already disabled is still
    // accounted for in `methodsCleared` because we loaded it.
    let methodsCleared = 0;
    for (const method of allMethods) {
      const disableResult = method.disable();
      if (Result.isOk(disableResult)) {
        await this.mfaMethodRepository.save(disableResult.value);
      }
      // Count regardless — even if disable() says "already disabled", the
      // method is cleared from the user's active set.
      methodsCleared++;
    }

    // Revoke all active sessions immediately. This prevents an attacker who
    // socially-engineered the recovery from continuing to use a live session.
    const { revokedCount: sessionsRevoked } = await this.sessionRevoker.revokeAllForUser(
      targetUserId,
    );

    // Emit a completion audit entry with the outcome.
    await this.auditLogger.record("mfa.recovery.completed", actorAdminId, {
      targetUserId: command.targetUserId,
      reason: command.reason,
      methodsCleared: String(methodsCleared),
      sessionsRevoked: String(sessionsRevoked),
    });

    return Result.ok({ methodsCleared, sessionsRevoked });
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

  async execute(
    command: RecoverMfaAccessCommand,
  ): Promise<Result<RecoverMfaAccessResult, Error>> {
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
