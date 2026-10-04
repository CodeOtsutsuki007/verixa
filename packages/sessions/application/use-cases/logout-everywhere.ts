import { asId, Result } from "@verixa/shared-kernel";

import type { RevocationList } from "../ports/revocation-list.js";
import type { SessionRepository } from "../ports/session-repository.js";

export interface LogoutEverywhereCommand {
  readonly userId: string;
  readonly now?: Date;
}

export interface LogoutEverywhereResult {
  /** How many sessions were revoked — diagnostic only, not a security-relevant count. */
  readonly revokedCount: number;
}

/**
 * Revokes every active session belonging to a user: the blunt-force tool
 * behind "log out all devices," password-change flows (`ConfirmPasswordReset`
 * in `@verixa/credentials`, via its `SessionRevoker` port — Issue 070), and
 * admin-initiated account lockdown.
 *
 * ## Why this loads every active session instead of a single bulk update
 *
 * A bulk `UPDATE sessions SET revoked_at = now() WHERE user_id = ...` would
 * be one round trip instead of `N`, but it would also revoke the refresh
 * token side of every session while leaving each one's already-issued
 * access token untouched — the same gap `Logout` closes for a single
 * session. Denylisting every one of those access tokens needs each
 * session's `currentAccessToken`, which means reading the sessions is
 * unavoidable regardless of how the revocation itself is written. Once the
 * data has to be read anyway, going through the domain entity (rather than a
 * raw update) keeps the "revoke" behaviour defined in exactly one place —
 * `Session.revoke` — instead of a SQL statement re-deriving it.
 *
 * ## Why new logins after the call are unaffected
 *
 * Only *existing* rows returned by `findActiveByUserId` at the moment this
 * runs are touched. A session created by a concurrent `IssueSession` call
 * that lands after this method has already read the list is a different
 * row this call never sees — which is exactly Issue 092's second acceptance
 * criterion: "new logins after the call are unaffected." That is not a
 * synchronization gap to close; a user who logs back in immediately after
 * "log out everywhere" is not the scenario this defends against, and a
 * fix would mean holding a lock across the entire user's session table for
 * no benefit.
 */
export class LogoutEverywhere {
  constructor(
    private readonly sessionRepository: SessionRepository,
    private readonly revocationList: RevocationList,
  ) {}

  async execute(command: LogoutEverywhereCommand): Promise<Result<LogoutEverywhereResult, never>> {
    const now = command.now ?? new Date();
    const userId = asId<"UserId">(command.userId);

    const active = await this.sessionRepository.findActiveByUserId(userId, now);

    for (const session of active) {
      if (session.currentAccessToken !== undefined) {
        await this.revocationList.revoke(
          session.currentAccessToken.tokenId,
          session.currentAccessToken.expiresAt,
        );
      }
      await this.sessionRepository.save(session.revoke(now));
    }

    return Result.ok({ revokedCount: active.length });
  }
}
