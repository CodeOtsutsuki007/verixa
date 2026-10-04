import { type Id } from "@verixa/shared-kernel";

export type SessionId = Id<"SessionId">;
export type UserId = Id<"UserId">;
export type OrganizationId = Id<"OrganizationId">;

/**
 * Access token claim set.
 *
 * Represents the payload of a JWT access token. These claims are embedded
 * in the token itself and can be verified and read by any service holding
 * the public signing key, without requiring a database lookup.
 *
 * **Design principles:**
 * - **Minimal:** Only includes claims necessary for token verification and
 *   basic authorization decisions. Additional claims (permissions, roles) are
 *   kept deliberately minimal — fine-grained authorization is deferred to a
 *   policy engine (Phase 08) that fetches fresh data rather than relying on
 *   potentially stale token claims.
 * - **Short-lived:** Expires quickly (typically 15 minutes). Revocation is
 *   cheap via a Redis deny-list since the token's lifetime is bounded.
 * - **Stateless-verifiable:** No database lookup required to verify the token.
 *   Revocation is handled out-of-band via the revocation service (Issue 088).
 *
 * **Field breakdown:**
 * - `sub` (subject): The user ID. Standard JWT claim.
 * - `sid` (session ID): Links the token to a specific session. Allows
 *   revoking all tokens from a session without waiting for expiry.
 * - `orgId` (organization ID): Multi-tenancy hint. Allows downstream services
 *   to scope database queries or make quick authorization checks without
 *   decoding the full token.
 * - `iat` (issued at): Timestamp when the token was signed. Standard JWT claim.
 * - `exp` (expiration): Timestamp when the token becomes invalid. Standard JWT claim.
 * - `kid` (key ID): Identifies which signing key was used. Allows key rotation
 *   without breaking tokens issued moments before rotation (Issue 085).
 */
export interface AccessTokenClaims {
  /** Subject (user ID) */
  sub: string;

  /** Session ID */
  sid: string;

  /** Organization ID (multi-tenancy) */
  orgId: string;

  /** Issued at (Unix timestamp) */
  iat: number;

  /** Expiration (Unix timestamp) */
  exp: number;

  /** Key ID (for key rotation support, Issue 085) */
  kid: string;
}

/**
 * A signed access token.
 *
 * Represents a JWT that has been cryptographically signed and can be
 * transmitted to and verified by downstream services.
 *
 * The raw token is a string containing the three base64-encoded JWT components
 * (header.payload.signature). It is stateless: verification requires only the
 * public signing key and a revocation check (if the service maintains one).
 */
export interface SignedAccessToken {
  /** The raw JWT string (header.payload.signature) */
  token: string;

  /** The decoded claims (for convenience; also embedded in the token) */
  claims: AccessTokenClaims;

  /** When this token expires */
  expiresAt: Date;
}

/**
 * Parameters for issuing a new access token.
 *
 * Used by the `IssueSession` use case (Issue 087) to request a token with
 * the specified claims and TTL.
 */
export interface IssueAccessTokenParams {
  userId: UserId;
  sessionId: SessionId;
  organizationId: OrganizationId;
  expiresAt: Date;
}
