import { asId, Result } from "@verixa/shared-kernel";

import {
  Session,
  type SessionMetadata,
  type SessionUserId,
} from "../../domain/entities/session.js";
import type { RevocationList } from "../ports/revocation-list.js";
import type { SessionAuditLogger } from "../ports/session-audit-logger.js";
import type { SessionRepository } from "../ports/session-repository.js";
import type { TokenSigner } from "../ports/token-signer.js";

export interface IssueSessionCommand {
  readonly userId: string;
  readonly metadata: SessionMetadata;
  readonly now?: Date;
}

export interface IssueSessionResult {
  readonly session: Session;
  readonly accessToken: string;
  readonly rawRefreshToken: string;
}

/**
 * Zero (the default) disables enforcement — see Issue 094's acceptance
 * criterion "limit of 0/unset disables enforcement." Sizing this above zero
 * is a per-deployment product decision (banking apps tend to pick 1–3;
 * consumer SaaS often skips it entirely), which is why it is a constructor
 * parameter here rather than a constant: the composition root reads it from
 * `@verixa/config` and this use case stays ignorant of environment
 * variables entirely.
 */
const DEFAULT_MAX_CONCURRENT_SESSIONS = 0;

/**
 * Issues a new session for a user who just authenticated: signs an access
 * token, mints a session (capturing the login's device/IP/user-agent per
 * Issue 093), and — this is Issue 094 — evicts the least-recently-active
 * existing session first if the login would otherwise exceed the
 * configured concurrent-session limit.
 *
 * ## Why eviction happens before the new session is created, not after
 *
 * If the new session were saved first, a limit of `N` would briefly allow
 * `N + 1` live sessions to exist, and a crash between the save and the
 * eviction would leave that extra session behind permanently — the bound
 * this use case exists to enforce would be violated by the very code
 * enforcing it. Evicting first means the invariant ("at most N active
 * sessions") holds after every step, not just at the end of a successful
 * run.
 *
 * ## Why only one eviction happens per call, in a loop
 *
 * A single login should only ever be pushing the count over the limit by
 * one. Looping rather than special-casing "evict exactly one" is what keeps
 * this correct even if the limit was lowered by an admin since the last
 * login and several existing sessions now exceed it — this call brings the
 * account back under the limit rather than merely not making it worse.
 *
 * ## Why an evicted session's access token is denylisted too
 *
 * `Session.revoke` only stops the *refresh* token from working. Its access
 * token is a self-contained JWT that would otherwise keep authenticating
 * requests until its own `exp` — an evicted session that is still, in
 * effect, logged in for a few more minutes. Denylisting
 * `currentAccessToken` through the `RevocationList` closes that gap, the
 * same way `Logout` does for a user-initiated sign-out.
 */
export class IssueSession {
  constructor(
    private readonly sessionRepository: SessionRepository,
    private readonly tokenSigner: TokenSigner,
    private readonly revocationList: RevocationList,
    private readonly sessionAuditLogger: SessionAuditLogger,
    private readonly maxConcurrentSessions: number = DEFAULT_MAX_CONCURRENT_SESSIONS,
  ) {}

  async execute(command: IssueSessionCommand): Promise<Result<IssueSessionResult, never>> {
    const now = command.now ?? new Date();
    const userId = asId<"UserId">(command.userId);

    if (this.maxConcurrentSessions > 0) {
      await this.evictOldestUntilUnderLimit(userId, now);
    }

    // Signed before the session exists so the session can be constructed in
    // one step with a fully-formed `currentAccessToken`, rather than issued
    // and then immediately patched. See `TokenSigner` for why this needs no
    // session id.
    const accessToken = await this.tokenSigner.issueAccessToken({ userId, now });

    const issued = Session.issue({
      userId,
      metadata: command.metadata,
      accessToken: { tokenId: accessToken.tokenId, expiresAt: accessToken.expiresAt },
      now,
    });

    await this.sessionRepository.save(issued.session);

    return Result.ok({
      session: issued.session,
      accessToken: accessToken.token,
      rawRefreshToken: issued.rawRefreshToken,
    });
  }

  private async evictOldestUntilUnderLimit(userId: SessionUserId, now: Date): Promise<void> {
    // The new session is not saved yet, so "at the limit" (not "over it") is
    // the trigger: adding one more would make `active.length + 1` exceed
    // `maxConcurrentSessions` unless one is evicted first.
    for (;;) {
      const active = await this.sessionRepository.findActiveByUserId(userId, now);
      if (active.length < this.maxConcurrentSessions) {
        return;
      }

      // `findActiveByUserId` is documented to return oldest-`lastActiveAt`
      // first; the eviction target is therefore always `active[0]`.
      const oldest = active[0]!;
      await this.sessionRepository.save(oldest.revoke(now));
      if (oldest.currentAccessToken !== undefined) {
        await this.revocationList.revoke(
          oldest.currentAccessToken.tokenId,
          oldest.currentAccessToken.expiresAt,
        );
      }
      await this.sessionAuditLogger.record("session.evicted", userId, {
        evictedSessionId: oldest.id,
        reason: "concurrent_session_limit",
      });
    }
  }
}
