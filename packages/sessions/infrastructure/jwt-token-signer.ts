import { createPrivateKey, createPublicKey } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";

import { ok, err, type Result } from "@verixa/shared-kernel";

import type {
  AccessTokenClaims,
  IssueAccessTokenParams,
  SignedAccessToken,
  TokenSigner,
} from "../application/ports/token-signer.js";
import {
  ExpiredTokenError,
  InvalidSignatureError,
  MalformedTokenError,
  SigningError,
} from "../application/ports/token-signer.js";

/**
 * JWT access token signer using RS256 (RSA asymmetric signing).
 *
 * This implementation uses Node's native `crypto` module (via the `jose`
 * library, which wraps it) to sign tokens with a private RSA key and verify
 * them with a public RSA key. Both keys are expected in PEM format (PKCS#8
 * for private keys, SPKI for public keys).
 *
 * **Key Caching:**
 * RSA key import (parsing PEM, converting to the crypto API's internal format)
 * is an expensive operation. On first use, this signer imports both keys and
 * caches them, so subsequent calls reuse the cached versions. This is safe:
 * crypto key objects are immutable.
 *
 * **Thread Safety:**
 * This implementation is stateless and thread-safe. Multiple concurrent
 * sign() and verify() calls do not interfere with each other.
 */
export class JwtTokenSigner implements TokenSigner {
  private cachedPrivateKey: ReturnType<typeof createPrivateKey> | null = null;
  private cachedPublicKey: ReturnType<typeof createPublicKey> | null = null;

  /**
   * Create a new JWT token signer.
   *
   * @param privateKeyPem - RSA private key in PKCS#8 PEM format. Must contain
   *   the "-----BEGIN PRIVATE KEY-----" and "-----END PRIVATE KEY-----" markers.
   * @param publicKeyPem - RSA public key in SPKI PEM format. Must contain the
   *   "-----BEGIN PUBLIC KEY-----" and "-----END PUBLIC KEY-----" markers.
   * @param keyId - A short identifier for this key pair (e.g., "2024-01-15-v1").
   *   Embedded in each token's header as the `kid` claim. Used for key rotation
   *   (Issue 085): when a new key pair is created, this ID changes, but the old
   *   public key is kept for verifying tokens issued moments before the rotation.
   */
  constructor(
    private readonly privateKeyPem: string,
    private readonly publicKeyPem: string,
    private readonly keyId: string,
  ) {}

  /**
   * Lazily import and cache the private key.
   * Repeated calls return the same cached instance.
   */
  private getPrivateKey(): ReturnType<typeof createPrivateKey> {
    if (!this.cachedPrivateKey) {
      try {
        this.cachedPrivateKey = createPrivateKey(this.privateKeyPem);
      } catch (error) {
        throw new SigningError(
          `Failed to import private key: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    return this.cachedPrivateKey;
  }

  /**
   * Lazily import and cache the public key.
   * Repeated calls return the same cached instance.
   */
  private getPublicKey(): ReturnType<typeof createPublicKey> {
    if (!this.cachedPublicKey) {
      try {
        this.cachedPublicKey = createPublicKey(this.publicKeyPem);
      } catch (error) {
        throw new SigningError(
          `Failed to import public key: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    return this.cachedPublicKey;
  }

  async sign(
    params: IssueAccessTokenParams,
  ): Promise<Result<SignedAccessToken, SigningError>> {
    try {
      const now = Math.floor(Date.now() / 1000);
      const expiresAt = Math.floor(params.expiresAt.getTime() / 1000);

      // Reject if expiration is not in the future.
      if (expiresAt <= now) {
        return err(new SigningError("Token expiration must be in the future"));
      }

      const claims: AccessTokenClaims = {
        sub: params.userId,
        sid: params.sessionId,
        orgId: params.organizationId,
        iat: now,
        exp: expiresAt,
        kid: this.keyId,
      };

      const privateKey = this.getPrivateKey();

      const token = await new SignJWT(claims)
        .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: this.keyId })
        .setIssuedAt(now)
        .setExpirationTime(expiresAt)
        .sign(privateKey);

      return ok({
        token,
        claims,
        expiresAt: params.expiresAt,
      });
    } catch (error) {
      if (error instanceof SigningError) {
        return err(error);
      }
      return err(
        new SigningError(
          `Failed to sign token: ${error instanceof Error ? error.message : String(error)}`,
        ),
      );
    }
  }

  async verify(token: string): Promise<AccessTokenClaims> {
    try {
      const publicKey = this.getPublicKey();

      // jwtVerify checks signature and expiration.
      const result = await jwtVerify(token, publicKey);
      const payload = result.payload;

      // Validate required claims are present.
      if (
        !payload.sub ||
        !payload.sid ||
        !payload.orgId ||
        typeof payload.iat !== "number" ||
        typeof payload.exp !== "number" ||
        !payload.kid
      ) {
        throw new MalformedTokenError("Token is missing required claims");
      }

      return {
        sub: payload.sub as any,
        sid: payload.sid as any,
        orgId: payload.orgId as any,
        iat: payload.iat,
        exp: payload.exp,
        kid: payload.kid as string,
      };
    } catch (error) {
      // Map specific error types.
      if (error instanceof MalformedTokenError) {
        throw error;
      }

      const message = error instanceof Error ? error.message : String(error);

      // jose throws with "exp claim expired" or similar for expiry.
      if (message.includes("exp") || message.includes("expired")) {
        throw new ExpiredTokenError(message);
      }

      // Signature failures include "invalid signature" or "verification failed".
      if (
        message.includes("signature") ||
        message.includes("verify") ||
        message.includes("invalid")
      ) {
        throw new InvalidSignatureError(message);
      }

      // Default to malformed for any other parse/validation error.
      throw new MalformedTokenError(`Token verification failed: ${message}`);
    }
  }
}
import { Result } from "@verixa/shared-kernel";
import { errors, type JWTPayload, jwtVerify, SignJWT } from "jose";

import type {
  AccessTokenInput,
  TokenSigner,
  VerifiedAccessToken,
} from "../application/ports/token-signer.js";
import { TokenVerificationError } from "../domain/errors/token-verification-error.js";
import { asSessionId } from "../domain/value-objects/session-id.js";

import type { SigningKeyProvider } from "./signing-key-provider.js";

export interface JwtTokenSignerOptions {
  /**
   * How long a minted access token stays valid, in seconds.
   *
   * Short on purpose — minutes, not days. A stateless access token cannot be
   * un-issued (that is what the deny-list in Issue 088 is for, and even that is
   * bounded by this number), so its lifetime *is* the worst-case window a
   * leaked one keeps working. Long refresh tokens (Issue 086) restore the
   * seamless-session experience without widening that window.
   */
  readonly accessTokenTtlSeconds: number;
  /** Optional `iss` claim, set on signing and required on verification when present. */
  readonly issuer?: string;
  /** Optional `aud` claim, set on signing and required on verification when present. */
  readonly audience?: string;
  /**
   * Clock used to stamp `iat`/`exp`, injectable so tests can mint a token that
   * is already expired without waiting for wall-clock time to pass. Verification
   * always uses the real current time (jose's default), which is the point: a
   * token stamped in the past by this clock is genuinely expired to a verifier.
   */
  readonly now?: () => Date;
}

/**
 * A {@link TokenSigner} that mints and verifies RFC 7519 JWTs, delegating all
 * key selection to a {@link SigningKeyProvider}.
 *
 * The division of labor is deliberate: this class knows the *token format*
 * (which claims, how they map, what the header looks like) and the provider
 * knows the *keys* (which is current, which are retired, which `kid` resolves to
 * what). That is why rotation needs no change here — swap the provider's current
 * key and this signer starts stamping the new `kid` and keeps verifying the old
 * one, with not a line of format code touched.
 */
export class JwtTokenSigner implements TokenSigner {
  private readonly now: () => Date;

  constructor(
    private readonly keyProvider: SigningKeyProvider,
    private readonly options: JwtTokenSignerOptions,
  ) {
    this.now = options.now ?? (() => new Date());
  }

  async sign(input: AccessTokenInput): Promise<string> {
    const key = this.keyProvider.signingKey();
    const issuedAtSeconds = Math.floor(this.now().getTime() / 1000);

    const payload: JWTPayload = { sid: input.sessionId };
    if (input.organizationId !== undefined) {
      payload["orgId"] = input.organizationId;
    }
    if (input.roles !== undefined && input.roles.length > 0) {
      payload["roles"] = [...input.roles];
    }

    const builder = new SignJWT(payload)
      // The `kid` is what makes rotation work — it is read back on verification
      // to pick this exact key out of the provider's set.
      .setProtectedHeader({ alg: key.algorithm, kid: key.kid })
      .setSubject(input.subject)
      .setIssuedAt(issuedAtSeconds)
      .setExpirationTime(issuedAtSeconds + this.options.accessTokenTtlSeconds);

    if (this.options.issuer !== undefined) {
      builder.setIssuer(this.options.issuer);
    }
    if (this.options.audience !== undefined) {
      builder.setAudience(this.options.audience);
    }

    return builder.sign(key.privateKey);
  }

  async verify(token: string): Promise<Result<VerifiedAccessToken, TokenVerificationError>> {
    try {
      const { payload, protectedHeader } = await jwtVerify(
        token,
        (header) => {
          const kid = header.kid;
          if (kid === undefined) {
            // A token with no `kid` cannot be routed to a key. We only ever mint
            // tokens with one, so this is a foreign or forged token.
            throw TokenVerificationError.unknownKey("(none)");
          }
          const verificationKey = this.keyProvider.verificationKey(kid);
          if (verificationKey === undefined) {
            // The rotation boundary: a `kid` the provider no longer holds — a
            // key removed after its last token expired, or one that never
            // existed here. Retired-but-held keys never reach this branch.
            throw TokenVerificationError.unknownKey(kid);
          }
          return verificationKey.publicKey;
        },
        {
          algorithms: [...this.keyProvider.algorithms()],
          ...(this.options.issuer !== undefined ? { issuer: this.options.issuer } : {}),
          ...(this.options.audience !== undefined ? { audience: this.options.audience } : {}),
        },
      );

      return this.toVerifiedToken(payload, protectedHeader.kid);
    } catch (error) {
      return Result.err(toVerificationError(error));
    }
  }

  private toVerifiedToken(
    payload: JWTPayload,
    keyId: string | undefined,
  ): Result<VerifiedAccessToken, TokenVerificationError> {
    const sid = payload.sid;
    if (payload.sub === undefined || typeof sid !== "string" || keyId === undefined) {
      // Correctly signed by a trusted key, but missing claims every token this
      // system issues carries. That means it was minted by something else that
      // happens to share our keys, or by an older format — either way it is not
      // a valid access token, and treating it as well-formed would let a
      // stripped-down token through.
      return Result.err(
        TokenVerificationError.malformed("Access token is missing required claims."),
      );
    }

    const roles = Array.isArray(payload["roles"])
      ? payload["roles"].filter((role): role is string => typeof role === "string")
      : [];

    const verified: VerifiedAccessToken = {
      subject: payload.sub,
      sessionId: asSessionId(sid),
      roles,
      keyId,
      issuedAt: new Date((payload.iat ?? 0) * 1000),
      expiresAt: new Date((payload.exp ?? 0) * 1000),
      ...(typeof payload["orgId"] === "string" ? { organizationId: payload["orgId"] } : {}),
    };
    return Result.ok(verified);
  }
}

/** Maps jose's thrown errors (and our own) onto the domain's rejection reasons. */
function toVerificationError(error: unknown): TokenVerificationError {
  if (error instanceof TokenVerificationError) {
    // Thrown from the key resolver (unknown/absent kid) — already precise.
    return error;
  }
  if (error instanceof errors.JWTExpired) {
    return TokenVerificationError.expired();
  }
  if (error instanceof errors.JWSSignatureVerificationFailed) {
    return TokenVerificationError.invalidSignature();
  }
  if (error instanceof errors.JWTClaimValidationFailed) {
    // Wrong issuer or audience: a real, correctly-signed token, but not one
    // meant for us. Refused, and deliberately not distinguished on the wire.
    return TokenVerificationError.invalidSignature("Access token claims are not accepted here.");
  }
  if (error instanceof errors.JOSEError) {
    // Undecodable header, wrong segment count, unsupported alg, etc. — it never
    // got far enough to be about a key.
    return TokenVerificationError.malformed();
  }
  // Not a jose error at all. Fail closed on the safe side: reject rather than
  // risk treating an unexpected failure as a valid token.
  return TokenVerificationError.malformed("Access token could not be verified.", { cause: error });
}
﻿export class JwtTokenSigner {}
