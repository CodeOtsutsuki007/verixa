import { asId, AuthenticationError, Result } from "@verixa/shared-kernel";

import type { Session, SessionMetadata } from "../../domain/entities/session.js";
import type { SessionRepository } from "../ports/session-repository.js";
import type { TokenSigner } from "../ports/token-signer.js";

export interface RefreshAccessTokenCommand {
  readonly sessionId: string;
  readonly refreshToken: string;
  /** What the client presents on *this* request — compared against what the session last saw. */
  readonly metadata: SessionMetadata;
  readonly now?: Date;
}

export interface RefreshAccessTokenResult {
  readonly session: Session;
  readonly accessToken: string;
}

/**
 * Exchanges a refresh token for a new access token, and — this is Issue
 * 093's other half — updates the session's metadata history if what the
 * client presents this time differs from what it presented last.
 *
 * ## Why a wrong or expired refresh token gets the same error as a wrong
 * session id
 *
 * Same reasoning as `AuthenticateWithPassword`: "no such session", "session
 * revoked", "session expired", and "refresh token does not match" are all
 * `AuthenticationError` to the caller. A client holding a stale or stolen
 * refresh token learns nothing about *which* of those is true, which is what
 * keeps a leaked refresh token from being a probe for session ids.
 *
 * ## Rotation and reuse detection are explicitly not this use case's job
 *
 * `RefreshToken` and `RefreshTokenReuseDetected` exist elsewhere in this
 * package as their own, still-unimplemented pieces (a separate roadmap
 * item). Detecting reuse of an already-rotated refresh token needs the
 * refresh token itself to be a tracked, single-use entity — which is a
 * bigger change than Issue 093 asks for and would be scope creep on a "just
 * capture the metadata" ticket. This use case therefore verifies the
 * session's *current* refresh token hash and re-signs the access token,
 * without rotating the refresh token. Rotation can be layered on top of this
 * later without touching the metadata-capture behaviour this issue is for.
 */
export class RefreshAccessToken {
  constructor(
    private readonly sessionRepository: SessionRepository,
    private readonly tokenSigner: TokenSigner,
  ) {}

  async execute(
    command: RefreshAccessTokenCommand,
  ): Promise<Result<RefreshAccessTokenResult, AuthenticationError>> {
    const now = command.now ?? new Date();

    const session = await this.sessionRepository.findById(asId<"SessionId">(command.sessionId));
    if (session === undefined) {
      return Result.err(new AuthenticationError("Invalid or expired session."));
    }

    if (!session.isActiveAt(now) || !session.matchesRefreshToken(command.refreshToken)) {
      return Result.err(new AuthenticationError("Invalid or expired session."));
    }

    const accessToken = await this.tokenSigner.issueAccessToken({ userId: session.userId, now });

    const refreshed = session.recordActivity({
      metadata: command.metadata,
      accessToken: { tokenId: accessToken.tokenId, expiresAt: accessToken.expiresAt },
      now,
    });

    await this.sessionRepository.save(refreshed);

    return Result.ok({ session: refreshed, accessToken: accessToken.token });
  }
}
