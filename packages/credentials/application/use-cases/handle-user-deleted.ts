import type { UserStatusChanged } from "@verixa/identity";

import type { CredentialUserId } from "../../domain/entities/credential.js";
import type { CredentialsUnitOfWork } from "../ports/credentials-unit-of-work.js";

/**
 * HandleUserDeleted
 *
 * Reacts to the UserStatusChanged domain event from the identity context,
 * specifically when a user transitions to `deleted` status.
 *
 * Invalidates all credentials and outstanding tokens for the deleted user so:
 * - The account cannot authenticate with a retained password
 * - Verification and reset tokens cannot be replayed
 * - Login attempts fail cleanly (credential invalid, not password mismatch)
 *
 * This is a cross-context event handler:
 *   Identity context emits UserStatusChanged (including deletions)
 *   Credentials context reacts by cleaning up its own data
 *
 * Neither context imports the other directly — they are decoupled through events.
 *
 * @see docs/guides/domain-events.md — cross-context event handling
 * @see Issue 075 — credential deletion on account deletion
 */
export class HandleUserDeleted {
  constructor(private readonly unitOfWork: CredentialsUnitOfWork) {}

  async handle(event: UserStatusChanged): Promise<void> {
    // Only react to deletion events, ignore all other status transitions.
    if (event.newStatus !== "deleted") {
      return;
    }

    const userId = event.aggregateId as unknown as CredentialUserId;
    const now = new Date();

    await this.unitOfWork.run(async (repositories) => {
      // 1. Find the credential for this user
      const credential = await repositories.credentials.findByUserId(userId);

      if (!credential) {
        // User had no credential record — nothing to clean up.
        // This is ordinary: SSO-only users and passkey-only users have no credential.
        // No need to throw or log an error; the operation is logically complete.
        return;
      }

      // 2. Invalidate all outstanding verification tokens
      //    These mark any unspent tokens as consumed, so they cannot be replayed.
      await repositories.emailVerificationTokens.invalidateOutstandingForUser(userId, now);

      // 3. Invalidate all outstanding password reset tokens
      //    Same reasoning: prevent account takeover via retained reset links.
      await repositories.passwordResetTokens.invalidateOutstandingForUser(userId, now);

      // 4. Mark the credential itself as permanently unusable
      //    Clears the failure counter and lock. A deleted account cannot log in anyway,
      //    and there is no way to recover from a lock, so carrying state forward
      //    complicates observability without benefit.
      const invalidated = credential.invalidateForDeletedUser(now);

      // 5. Persist the changes
      await repositories.credentials.save(invalidated);

      // Structured event for observability:
      // The fact that we reached here means both the credential and its tokens
      // have been invalidated. An operator tracking this context will correlate
      // this user's ID with the UserDeleted event from the identity context.
    });
  }
}
