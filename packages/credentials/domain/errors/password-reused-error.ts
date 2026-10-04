/**
 * Thrown when a user attempts to reuse one of their previous passwords
 * during password change or reset.
 *
 * This is a domain error, not an HTTP error — use cases catch it and
 * convert to a ValidationError with appropriate field errors.
 *
 * Accepts history depth for better error messaging.
 */
export class PasswordReusedError extends Error {
  constructor(historyDepth: number = 5) {
    super(
      `Password was recently used. ` +
        `Please choose a password not used in your last ${historyDepth} passwords.`,
    );
    this.name = "PasswordReusedError";
    Object.setPrototypeOf(this, PasswordReusedError.prototype);
  }
}
