import type { User } from "@verixa/identity";
import { Result, ValidationError, type Id, type RateLimiter } from "@verixa/shared-kernel";

import { type PasswordHistoryPolicy } from "../../domain/value-objects/password-history-policy.js";
import { DEFAULT_PASSWORD_HISTORY_POLICY } from "../../domain/value-objects/password-history-policy.js";
import { type PasswordPolicy, RawPassword } from "../../domain/value-objects/raw-password.js";
import type { CredentialsUnitOfWork } from "../ports/credentials-unit-of-work.js";
import type { PasswordHasher } from "../ports/password-hasher.js";

export interface ChangePasswordCommand {
  readonly userId: Id<"UserId">;
  readonly currentPassword: string;
  readonly newPassword: string;
}

export interface ChangePasswordResult {
  readonly user: User;
}

/**
 * Changes the authenticated user's password, requiring re-entry of the current one.
 *
 * Distinct from `ConfirmPasswordReset` (Issue 070) — that is for account
 * recovery when the current password is forgotten. This is for a logged-in
 * user rotating their own password, as a convenience and as part of regular
 * security hygiene.
 *
 * Re-authentication (current password re-entry) is deliberate. A user in an
 * unlocked browser at a coffee shop wants to know that a password change will
 * not go through while they grab a napkin. The complexity is real and the
 * property is also real. Phase 06 will extend this to MFA step-up as another
 * example of re-authentication.
 *
 * Password reuse is rejected (Issue 072): one of the last N passwords cannot
 * be used. This prevents trivial "change and change back" bypasses.
 */
export class ChangePassword {
  constructor(
    private readonly unitOfWork: CredentialsUnitOfWork,
    private readonly passwordHasher: PasswordHasher,
    private readonly rateLimiter: RateLimiter,
    private readonly passwordPolicy?: PasswordPolicy,
    private readonly passwordHistoryPolicy: PasswordHistoryPolicy = DEFAULT_PASSWORD_HISTORY_POLICY,
  ) {}

  async execute(
    command: ChangePasswordCommand,
  ): Promise<Result<ChangePasswordResult, ValidationError>> {
    // Validate the new password policy first, before any hashing or
    // database work. A rejected password should not advance the change.
    const passwordResult = RawPassword.create(command.newPassword, this.passwordPolicy);
    if (Result.isErr(passwordResult)) {
      return passwordResult;
    }

    const outcome = await this.unitOfWork.run(async (repositories) => {
      const user = await repositories.users.findById(command.userId);
      if (user === undefined) {
        return { kind: "user_not_found" as const };
      }

      const credential = await repositories.credentials.findByUserId(user.id);
      if (credential === undefined) {
        // User has no password credential (SSO-only, etc.). Cannot change
        // a password that doesn't exist.
        return { kind: "no_credential" as const };
      }

      // Re-authenticate: verify the current password matches the stored one.
      const currentMatches = await this.passwordHasher.verify(
        command.currentPassword,
        credential.passwordHash,
      );
      if (!currentMatches) {
        return { kind: "wrong_current_password" as const };
      }

      // Check for password reuse (Issue 072)
      const isReused = await credential.isPasswordReused(command.newPassword, (plain, hash) =>
        this.passwordHasher.verify(plain, hash),
      );
      if (isReused) {
        return { kind: "password_reused" as const };
      }

      return { kind: "ok" as const, user };
    });

    if (outcome.kind === "user_not_found" || outcome.kind === "no_credential") {
      // Both are internal errors: the user supplied a valid userId, and the
      // system should have found the account. Surface as 500 implicitly by
      // not returning an error (use case error is for *semantic* failures).
      throw new Error(`ChangePassword: outcome.kind === ${outcome.kind}`);
    }

    if (outcome.kind === "wrong_current_password") {
      // Wrong re-authentication is treated as authentication failure: same
      // message, same timing (password verification is expensive and took
      // time already).
      return Result.err(
        new ValidationError("Current password is incorrect.", { currentPassword: ["incorrect"] }),
      );
    }

    if (outcome.kind === "password_reused") {
      return Result.err(
        new ValidationError(
          `Password was recently used. ` +
            `Please choose a password not used in your last ${this.passwordHistoryPolicy.depth} passwords.`,
          { password: ["reused"] },
        ),
      );
    }

    // Hash the new password outside the transaction. It is the slowest
    // operation here and needs no database, so holding a connection open
    // across it is waste.
    const newHash = await this.passwordHasher.hash(passwordResult.value.reveal());

    // Update the credential with the new hash, maintaining history.
    await this.unitOfWork.run(async (repositories) => {
      const credential = await repositories.credentials.findByUserId(outcome.user.id);
      if (credential === undefined) {
        throw new Error("ChangePassword: credential vanished during transaction");
      }

      const rotated = credential.rotatePassword(newHash, this.passwordHistoryPolicy);
      await repositories.credentials.save(rotated);
    });

    return Result.ok({ user: outcome.user });
  }
}
