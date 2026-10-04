/**
 * Thrown whenever configuration — environment variables, signing-key material,
 * anything read at startup — is missing or malformed.
 *
 * Extracted into its own module so both {@link import("./index.js").loadConfig}
 * and {@link import("./signing-keys.js").loadSigningKeys} can throw the same
 * type without importing each other (that would be a circular import between
 * `index.ts` and `signing-keys.ts`).
 */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}
