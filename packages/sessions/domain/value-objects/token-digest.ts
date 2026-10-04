import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Issuing and checking the refresh token's bearer secret.
 *
 * Deliberately not imported from `@verixa/credentials`, even though that
 * package exposes the identical three functions for its own single-use
 * tokens (email verification, password reset). Sessions is not allowed to
 * depend on credentials — the two are siblings, not a hierarchy — and the
 * mechanism here is generic enough that copying it is the intended move.
 * See `docs/guides/domain-modeling.md` ("Package encapsulation") and the
 * codebase-wide note that repetition of this shape is encouraged over a
 * shared abstraction that would need its own cross-cutting package.
 *
 * See `docs/security/token-storage.md`.
 */

/** Bytes of entropy in an issued refresh token. */
const TOKEN_BYTES = 32;

/**
 * Generates a raw bearer token: 256 bits from a CSPRNG, base64url-encoded so
 * it is safe in a cookie or header without escaping.
 */
export function generateToken(): string {
  return randomBytes(TOKEN_BYTES).toString("base64url");
}

/**
 * SHA-256 of a raw token, hex-encoded. The only form ever persisted.
 *
 * A plain hash rather than a slow KDF: the token is 256 random bits with no
 * dictionary to try, so a slow hash would only cost latency on every refresh
 * without buying any resistance to guessing. What it does buy, same as for
 * any other bearer token in this codebase, is that a leaked sessions table
 * does not hand over usable refresh tokens.
 */
export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Whether `token` hashes to `digest`, compared in constant time so a naive
 * `===` cannot leak the digest one character at a time through timing.
 */
export function tokenMatchesDigest(token: string, digest: string): boolean {
  const candidate = Buffer.from(hashToken(token), "hex");
  const actual = Buffer.from(digest, "hex");

  if (candidate.length !== actual.length) {
    return false;
  }

  return timingSafeEqual(candidate, actual);
}
