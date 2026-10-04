import { Result, ValidationError } from "@verixa/shared-kernel";
import crypto from "node:crypto";
import { base32 } from "../services/base32.js";

export class TotpSecret {
  private readonly _secretBase32: string;

  private constructor(secretBase32: string) {
    this._secretBase32 = secretBase32;
  }

  static generate(byteLength = 20): TotpSecret {
    const buffer = crypto.randomBytes(byteLength);
    return new TotpSecret(base32.encode(buffer));
  }

  static fromString(secret: string): Result<TotpSecret, ValidationError> {
    try {
      base32.decode(secret);
      return Result.ok(new TotpSecret(secret));
    } catch {
      return Result.err(
        new ValidationError("Invalid TOTP secret format.", {
          secret: ["invalid_base32"],
        }),
      );
    }
  }

  get value(): string {
    return this._secretBase32;
  }

  getProvisioningUri(accountName: string, issuer: string): string {
    const encodedIssuer = encodeURIComponent(issuer);
    const encodedAccount = encodeURIComponent(accountName);
    return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${this._secretBase32}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
  }

  // Prevent secret from leaking in logs/serialization
  toJSON() {
    return "<redacted>";
  }

  toString() {
    return "<redacted>";
  }

  [Symbol.for("nodejs.util.inspect.custom")]() {
    return "TotpSecret { <redacted> }";
  }
}
