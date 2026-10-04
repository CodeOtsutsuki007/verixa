import type { User } from "@verixa/identity";
import { Result, ValidationError } from "@verixa/shared-kernel";
import type { RateLimiter, RateLimitKey } from "@verixa/shared-kernel";

import { Credential } from "../../domain/entities/credential.js";
import { PasswordResetToken } from "../../domain/entities/password-reset-token.js";
import {
  type PasswordHistoryPolicy,
  DEFAULT_PASSWORD_HISTORY_POLICY,
} from "../../domain/value-objects/password-history-policy.js";
import { type PasswordPolicy, RawPassword } from "../../domain/value-objects/raw-password.js";
import type { CredentialsUnitOfWork } from "../ports/credentials-unit-of-work.js";
import type { PasswordHasher } from "../ports/password-hasher.js";
import type { SessionRevoker } from "../ports/session-revoker.js";

export interface ConfirmPasswordResetCommand {
  readonly token: string;
  readonly newPassword: string;
}

export interface ConfirmPasswordResetResult {
  readonly user: User;
}

/**
 * Completes a password reset: validates the token, enforces the password
 * policy, replaces the credential, and revokes every existing session.
 *
 * ## The step everyone forgets
 *
 * **Revoking sessions is not cleanup.** It is the reason the flow exists.
 *
 * The scenario a reset is for is "someone else has my account". If they got
 * in, they are holding a session. Replacing the password revokes their
 * knowledge of the *credential* and does precisely nothing about the session
 * they already have — they stay signed in, indefinitely, while the user
 * believes they have just locked them out.
 *
 * The danger is not that the reset is insecure. It is that it is *believed to
 * have worked*. A user who knows they are still compromised takes further
 * action; one who thinks they are safe does not.
 *
 * Sessions are Phase 05, so `SessionRevoker` has no real implementation yet.
 * The call is here anyway, against a port, because the alternative is a
 * comment saying "remember to revoke sessions when Phase 05 lands" — and that
 * is the comment nobody reads.
 *
 * ## Rate limiting
 *
 * The rate limiter is consulted at the start via the {@link RateLimiter} port
 * to prevent abuse of the confirmation endpoint. On successful confirmation,
 * the limit is reset to allow the user to make another attempt if needed.
 *
 * ## Ordering
 *
 * Token consumed → credential replaced → sessions revoked, all inside one
 * transaction except the revocation, which cannot be (it is an external
 * system). The consequence is stated rather than hidden: if revocation fails,
 * the password has still changed. That is the right way round — a user whose
 * password changed but whose old sessions survive is better off than one
 * whose reset silently did nothing — but it is a real partial failure, and
 * the error says so instead of reporting success.
 */
export class ConfirmPasswordReset {
  constructor(
    private readonly unitOfWork: CredentialsUnitOfWork,
    private readonly passwordHasher: PasswordHasher,
    private readonly sessionRevoker: SessionRevoker,
    private readonly rateLimiter: RateLimiter,
    private readonly passwordPolicy?: PasswordPolicy,
    private readonly passwordHistoryPolicy: PasswordHistoryPolicy = DEFAULT_PASSWORD_HISTORY_POLICY,
  ) {}

  async execute(
    command: ConfirmPasswordResetCommand,
  ): Promise<Result<ConfirmPasswordResetResult, ValidationError>> {
    // 1. Check rate limit BEFORE any other logic
    const rateLimitKey: RateLimitKey = {
      action: "password-reset",
      identifier: command.token,
    };

    const limitResult = await this.rateLimiter.check(rateLimitKey);
    if (!limitResult.allowed) {
      throw new Error(
        `Rate limit exceeded for ${rateLimitKey.action} on ${rateLimitKey.identifier}. ` +
          `Resets at ${new Date(limitResult.resetAt).toISOString()}`,
      );
    }

    // Policy first, before the token is looked up and before anything is
    // hashed. A rejected password should not consume the user's one-time
    // link — otherwise choosing a too-short password burns the reset and
    // sends them back to their inbox for another email.
    const passwordResult = RawPassword.create(command.newPassword, this.passwordPolicy);
    if (Result.isErr(passwordResult)) {
      return passwordResult;
    }

    const now = new Date();
    const tokenHash = PasswordResetToken.hashToken(command.token);

    // Hashed outside the transaction: it is the slowest thing here and needs
    // no database. Same reasoning as `RegisterUserWithPassword`.
    //
    // It does mean an invalid token still pays for a hash, which is a
    // deliberate trade in the other direction from usual — it costs a little
    // CPU on a bad request, and it keeps a valid token's transaction short.
    const newHash = await this.passwordHasher.hash(passwordResult.value.reveal());

    const outcome = await this.unitOfWork.run(async (repositories) => {
      const token = await repositories.passwordResetTokens.findByTokenHash(tokenHash);
      if (token === undefined || !token.matchesToken(command.token)) {
        return { kind: "invalid" as const };
      }

      const consumed = token.consume(now);
      if (Result.isErr(consumed)) {
        // The domain distinguishes expired from already-used. The caller does
        // not get that distinction here, unlike email verification, and the
        // difference is the stakes: an attacker holding a *used* reset token
        // learns from "already used" that it was real and that the account
        // exists. "Expired" leaks the same. One message for both.
        return { kind: "invalid" as const };
      }

      const user = await repositories.users.findById(token.userId);
      if (user === undefined) {
        return { kind: "invalid" as const };
      }

      await repositories.passwordResetTokens.save(consumed.value);

      // Upsert rather than requiring an existing row. The credential should
      // exist — `RequestPasswordReset` refuses to issue a token without one —
      // but a credential deleted between request and confirmation would
      // otherwise strand a valid token against a missing row.
      const existing = await repositories.credentials.findByUserId(user.id);

      // Check for password reuse before updating (Issue 072)
      if (existing !== undefined) {
        const isReused = await existing.isPasswordReused(command.newPassword, (plain, hash) =>
          this.passwordHasher.verify(plain, hash),
        );
        if (isReused) {
          return { kind: "password_reused" as const };
        }
      }

      const credential =
        existing === undefined
          ? Credential.create({ userId: user.id, passwordHash: newHash })
          : // `rotatePassword` maintains history and clears the lockout, which
            // matters exactly here: the failures that locked the account were not
            // the owner's, and after a reset they have no way to wait one out.
            existing.rotatePassword(newHash, this.passwordHistoryPolicy);

      await repositories.credentials.save(credential);

      return { kind: "ok" as const, user };
    });

    if (outcome.kind === "invalid") {
      return Result.err(
        new ValidationError("This reset link is not valid.", { token: ["invalid"] }),
      );
    }

    if (outcome.kind === "password_reused") {
      return Result.err(
        new ValidationError(
          `Password was recently used. Please choose a password not used in your last ${this.passwordHistoryPolicy.depth} passwords.`,
          { password: ["reused"] },
        ),
      );
    }

    // Outside the transaction because it is an external system — a session
    // store, not this database. Inside, a slow or unavailable session service
    // would hold a database transaction open behind it.
    try {
      await this.sessionRevoker.revokeAllForUser(outcome.user.id);
    } catch {
      // Reported, not swallowed. Unlike a failed notification — where the
      // worst case is an email nobody received — a failed revocation means
      // the user believes they have locked an attacker out and they have not.
      // Silence here is the specific failure this use case exists to prevent.
      return Result.err(
        new ValidationError(
          "Your password was changed, but existing sessions could not be signed out. " +
            "Sign out of all devices manually.",
          { sessions: ["revocation_failed"] },
        ),
      );
    }

    // Reset rate limit counter on successful password reset confirmation
    await this.rateLimiter.reset(rateLimitKey);

    return Result.ok({ user: outcome.user });
  }
}
