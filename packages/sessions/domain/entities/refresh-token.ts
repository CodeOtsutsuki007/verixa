import { createHash, randomBytes } from "node:crypto";

import { createId, type Id } from "@verixa/shared-kernel";

import type { SessionId } from "./session.js";

export type RefreshTokenId = Id<"RefreshTokenId">;

/**
 * Default TTL for refresh tokens: 7 days in milliseconds.
 *
 * Refresh tokens are long-lived (compared to access tokens) to avoid frequent
 * re-authentication, but bounded by a hard expiry. This ensures that:
 * - A stolen token's usefulness is limited to 7 days.
 * - Reuse detection (Issue 090) has time to catch rotation-chain compromises.
 */
const DEFAULT_REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

/**
 * Byte length for the opaque refresh token's raw value.
 *
 * **256 bits (32 bytes) was chosen for the following reasons:**
 *
 * 1. **Security:** Exceeds the OWASP 128-bit minimum entropy recommendation
 *    (RFC 6819, §5.2.2) for long-lived bearer tokens. Long-lived tokens are
 *    higher-value targets, so higher entropy is justified.
 *
 * 2. **Guessing resistance:** 256 bits = 2^256 possible values. Even with
 *    (unrealistic) 1 billion guesses/second, exhausting the space takes
 *    ~10^66 seconds — far beyond practical attack timescales.
 *
 * 3. **Practicality:** 32 bytes base64-encoded = 44 characters, fits comfortably
 *    in standard HTTP headers and cookies. The additional 16 bytes (vs. 128-bit
 *    alternatives) cost negligible storage and transmission overhead.
 *
 * 4. **Precedent:** OAuth 2.0 and similar standards recommend this range for
 *    long-lived bearer tokens. Using it aligns with industry practice.
 *
 * **Rejected alternative: 16 bytes (128 bits)**
 * - Meets OWASP minimum but leaves room for improvement.
 * - 16 additional bytes to transport and store is trivial.
 * - Better security posture for a 7-day token.
 */
const REFRESH_TOKEN_BYTE_LENGTH = 32;

interface RefreshTokenProps {
  readonly id: RefreshTokenId;
  readonly sessionId: SessionId;
  readonly hash: string;
  readonly familyId?: string | undefined;
  readonly expiresAt: Date;
  readonly createdAt: Date;
  readonly revokedAt?: Date | undefined;
}

/**
 * The raw token plus its RefreshToken entity.
 *
 * The token is **only ever present in this return value**. Once returned
 * from `RefreshToken.create()`, the raw token is inaccessible — the entity
 * stores only the hash. This structural guarantee makes it impossible to
 * accidentally persist or expose the raw token.
 */
export interface IssuedRefreshToken {
  readonly refreshToken: RefreshToken;
  readonly token: string;
}

/**
 * A refresh token: an opaque, hashed bearer credential for obtaining new
 * access tokens.
 *
 * **Design Philosophy**
 *
 * Refresh tokens are fundamentally different from access tokens:
 *
 * - **Access tokens** are short-lived (15 min) JWTs, verifiable without a
 *   database lookup. They must be stateless.
 *
 * - **Refresh tokens** are long-lived (7 days) opaque strings, revocable
 *   immediately. They must be stateful (stored in the database) so revocation
 *   is instant, and opaque (not JWTs) so a database leak doesn't expose
 *   unencrypted claims.
 *
 * **Hash-Only Storage**
 *
 * This entity stores only the hash of the token, never the raw value. This
 * mirrors password storage (Issue 061): a stolen database dump yields hashes,
 * not usable credentials. The raw token is only ever constructed in
 * `RefreshToken.create()` and discarded once returned — making it structurally
 * impossible to leak.
 *
 * **Immutability and State Transitions**
 *
 * Like `User`, `Organization`, and other domain entities, RefreshToken is
 * immutable: methods return a new instance or the same instance unchanged.
 * The only meaningful state change is revocation (via `revoke()`).
 *
 * **Token Family (Issue 090)**
 *
 * The optional `familyId` links a token to its rotation chain. Issue 090
 * (reuse detection) uses this to detect theft: if a superseded token is
 * presented again, the entire family is revoked. This entity only carries
 * the ID; the actual chain logic is built in Issue 090's use case layer.
 */
export class RefreshToken {
  readonly id: RefreshTokenId;
  readonly sessionId: SessionId;
  readonly hash: string;
  readonly familyId: string | undefined;
  readonly expiresAt: Date;
  readonly createdAt: Date;
  readonly revokedAt: Date | undefined;

  private constructor(props: RefreshTokenProps) {
    this.id = props.id;
    this.sessionId = props.sessionId;
    this.hash = props.hash;
    this.familyId = props.familyId;
    this.expiresAt = props.expiresAt;
    this.createdAt = props.createdAt;
    this.revokedAt = props.revokedAt;
  }

  /**
   * Generate a cryptographically strong opaque token.
   *
   * Uses `crypto.randomBytes()` (Node's CSPRNG) to generate 32 bytes of
   * high-entropy random data, then base64-encodes it for safe transmission
   * and storage in headers/cookies.
   *
   * Each call is guaranteed to produce a unique token.
   */
  private static generateToken(): string {
    return randomBytes(REFRESH_TOKEN_BYTE_LENGTH).toString("base64");
  }

  /**
   * SHA-256 hash of a raw token, hex-encoded.
   *
   * This is the only form ever stored in the database. The raw token is
   * never persisted, ensuring that a database leak doesn't yield usable
   * credentials.
   */
  private static hashToken(token: string): string {
    return createHash("sha256").update(token, "utf8").digest("hex");
  }

  /**
   * Create a new refresh token.
   *
   * Returns the raw token **alongside** the entity, because this is the only
   * moment the raw token exists. Once this return value is discarded, the
   * token is unrecoverable from the system.
   *
   * The token is structurally distinct from `id` on purpose:
   * - `id` is an ordinary database key, may appear in URLs and logs
   * - `token` is a bearer credential, a secret that proves session validity
   */
  static create(params: {
    sessionId: SessionId;
    familyId?: string;
    expiryMs?: number;
    createdAt?: Date;
  }): IssuedRefreshToken {
    const now = params.createdAt ?? new Date();
    const id = createId<"RefreshTokenId">();
    const token = RefreshToken.generateToken();

    const refreshToken = new RefreshToken({
      id,
      sessionId: params.sessionId,
      hash: RefreshToken.hashToken(token),
      familyId: params.familyId,
      expiresAt: new Date(now.getTime() + (params.expiryMs ?? DEFAULT_REFRESH_TOKEN_TTL_MS)),
      createdAt: now,
      revokedAt: undefined,
    });

    return { refreshToken, token };
  }

  /**
   * Rebuild a RefreshToken from already-trusted data (e.g., a database row).
   *
   * Does not re-run validation: the data is assumed to be already-valid.
   */
  static reconstitute(props: RefreshTokenProps): RefreshToken {
    return new RefreshToken(props);
  }

  /**
   * Is this refresh token no longer valid?
   *
   * True if either expired or explicitly revoked. Once either is true, a
   * new token must be issued (there is no "unrevoking" or extending expiry).
   */
  isValid(asOf: Date = new Date()): boolean {
    return !this.isExpired(asOf) && !this.isRevoked();
  }

  /**
   * Is the token's `expiresAt` timestamp in the past?
   */
  isExpired(asOf: Date = new Date()): boolean {
    return asOf.getTime() >= this.expiresAt.getTime();
  }

  /**
   * Has this token been explicitly revoked?
   */
  isRevoked(): boolean {
    return this.revokedAt !== undefined;
  }

  /**
   * Explicitly revoke this token.
   *
   * Returns a new RefreshToken with `revokedAt` set. Idempotent: revoking an
   * already-revoked token returns an equivalent result.
   */
  revoke(revokedAt: Date = new Date()): RefreshToken {
    return new RefreshToken({
      id: this.id,
      sessionId: this.sessionId,
      hash: this.hash,
      familyId: this.familyId,
      expiresAt: this.expiresAt,
      createdAt: this.createdAt,
      revokedAt,
    });
  }
}
