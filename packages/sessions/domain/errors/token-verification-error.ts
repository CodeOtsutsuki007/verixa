import { DomainError } from "@verixa/shared-kernel";

/**
 * Why an access token failed verification.
 *
 * These are kept internal — a distinct signal for logs, metrics, and the
 * caller's own branching — but they are deliberately *not* meant to be handed
 * back to the client verbatim. Telling an attacker "unknown_key" versus
 * "invalid_signature" versus "expired" narrows their guessing, the same
 * reasoning that collapses every login failure into one {@link
 * https://owasp.org/www-community/attacks/Credential_stuffing | generic}
 * message. The HTTP layer maps all of these to one 401.
 *
 * - `malformed` — not a well-formed JWS at all (truncated, wrong segment
 *   count, undecodable header). Never reached a key.
 * - `unknown_key` — the token's `kid` names a key this verifier does not hold.
 *   The rotation case that Issue 085 exists to get right: a token minted under
 *   a key that has since been *removed entirely* (not merely retired) lands
 *   here, and so does a forged `kid`.
 * - `invalid_signature` — a known key, but the signature does not check out.
 *   Tampering, or a token signed by a different key that happens to reuse a
 *   `kid`.
 * - `expired` — well-formed, correctly signed, past its `exp`.
 */
export type TokenVerificationFailure =
  "malformed" | "unknown_key" | "invalid_signature" | "expired";

/**
 * An access token was rejected during verification. Carries a machine-readable
 * {@link reason} so the application layer can distinguish, say, an expired
 * token (refresh it) from a forged one (a security event worth recording)
 * without re-parsing the token or string-matching an error message.
 */
export class TokenVerificationError extends DomainError {
  readonly code = "TOKEN_VERIFICATION_FAILED";
  readonly httpStatusHint = 401;
  readonly reason: TokenVerificationFailure;

  constructor(reason: TokenVerificationFailure, message: string, options?: ErrorOptions) {
    super(message, options);
    this.reason = reason;
  }

  static malformed(
    message = "Access token is malformed.",
    options?: ErrorOptions,
  ): TokenVerificationError {
    return new TokenVerificationError("malformed", message, options);
  }

  static unknownKey(kid: string, options?: ErrorOptions): TokenVerificationError {
    return new TokenVerificationError(
      "unknown_key",
      `Access token was signed with an unrecognized key id "${kid}".`,
      options,
    );
  }

  static invalidSignature(
    message = "Access token signature is invalid.",
    options?: ErrorOptions,
  ): TokenVerificationError {
    return new TokenVerificationError("invalid_signature", message, options);
  }

  static expired(
    message = "Access token has expired.",
    options?: ErrorOptions,
  ): TokenVerificationError {
    return new TokenVerificationError("expired", message, options);
  }

  override toJSON(): ReturnType<DomainError["toJSON"]> & { reason: TokenVerificationFailure } {
    return { ...super.toJSON(), reason: this.reason };
  }
}
