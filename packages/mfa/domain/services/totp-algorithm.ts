/**
 * Port for generating and verifying time-based one-time passwords.
 *
 * The application layer depends on this interface rather than the concrete
 * RFC 6238 implementation ({@link Rfc6238TotpAlgorithm}) so use cases can be
 * tested without real cryptography, and so the algorithm can be swapped
 * without touching the domain.
 */
export interface TotpSecretLike {
  readonly value: string;
  readonly provisioningUri: string;
}

export interface TotpAlgorithm {
  /**
   * Generates a new CSPRNG secret and its `otpauth://` provisioning URI.
   */
  generateSecret(accountName: string, issuer?: string): Promise<TotpSecretLike>;

  /**
   * Verifies a 6-digit code against a base32 secret, tolerating a small clock
   * skew window.
   *
   * Returns the matched time step when valid — the caller persists it to
   * reject replays — or `null` when the code is invalid or outside the window.
   */
  verify(secret: string, code: string, driftWindow?: number): Promise<number | null>;
}
