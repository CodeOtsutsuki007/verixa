import { asId, Result } from "@verixa/shared-kernel";

import type { RevocationList } from "../ports/revocation-list.js";
import type { SessionRepository } from "../ports/session-repository.js";

export interface LogoutCommand {
  readonly sessionId: string;
  readonly now?: Date;
}

/**
 * Revokes one session: the current refresh token stops working, and the
 * session's current access token is denylisted so it stops working too,
 * before it would otherwise expire on its own.
 *
 * ## Why both tokens have to be handled, not just one
 *
 * Verixa's access tokens are stateless JWTs — accepted on their signature
 * alone, without a database or Redis round trip, which is the entire reason
 * to use them. Revoking only the refresh token would leave the access token
 * fully functional for however long its remaining lifetime is: "log out"
 * would not actually log anyone out, it would just prevent the *next*
 * token. Revoking only the access token (denylisting it) would stop the
 * current token but leave the refresh token able to mint a fresh,
 * non-denylisted one moments later.
 *
 * So this revokes the session (kills the refresh token) *and* denylists
 * `currentAccessToken` (kills the access token already issued), which
 * together are what Issue 091's acceptance criterion asks for: "the access
 * token fails `isRevoked` checks and the refresh token can no longer be used
 * to refresh." See `docs/security/authentication-flows.md`.
 *
 * ## Idempotence
 *
 * Logging out twice, or logging out a session that never existed, both
 * succeed rather than erroring. A logout failing because the user is
 * "already logged out" is not a state worth surfacing to a client whose
 * only intent was "make sure I am not signed in" — the property that
 * matters is achieved either way.
 */
export class Logout {
  constructor(
    private readonly sessionRepository: SessionRepository,
    private readonly revocationList: RevocationList,
  ) {}

  async execute(command: LogoutCommand): Promise<Result<void, never>> {
    const now = command.now ?? new Date();

    const session = await this.sessionRepository.findById(asId<"SessionId">(command.sessionId));
    if (session === undefined) {
      return Result.ok(undefined);
    }

    if (session.currentAccessToken !== undefined) {
      await this.revocationList.revoke(
        session.currentAccessToken.tokenId,
        session.currentAccessToken.expiresAt,
      );
    }

    await this.sessionRepository.save(session.revoke(now));

    return Result.ok(undefined);
  }
}
