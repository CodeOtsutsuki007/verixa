import { randomUUID } from "node:crypto";

import type { IssuedAccessToken, TokenSigner } from "../../application/ports/token-signer.js";
import type { SessionUserId } from "../../domain/entities/session.js";

/**
 * A `TokenSigner` that produces deterministic-shaped, unsigned tokens
 * instead of real JWTs, satisfying the exact same port a real (Phase 05,
 * `jose`-backed) adapter will. Exists so `IssueSession`, `Logout`, and
 * `RefreshAccessToken` never need a real signing key in their unit tests —
 * only that every issued token carries a unique `tokenId` and the requested
 * expiry, which is all these use cases observe about a token.
 */
export class InMemoryTokenSigner implements TokenSigner {
  constructor(private readonly accessTokenTtlMs: number = 15 * 60 * 1000) {}

  issueAccessToken(params: { userId: SessionUserId; now: Date }): Promise<IssuedAccessToken> {
    const tokenId = randomUUID();
    const expiresAt = new Date(params.now.getTime() + this.accessTokenTtlMs);
    return Promise.resolve({
      token: `fake.${params.userId}.${tokenId}`,
      tokenId,
      expiresAt,
    });
  }
}
