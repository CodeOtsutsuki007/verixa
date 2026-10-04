import crypto from "node:crypto";

import { Result } from "@verixa/shared-kernel";

import type { TotpAlgorithm, TotpSecretLike } from "./totp-algorithm.js";
import { base32 } from "./base32.js";
import { TotpSecret } from "../value-objects/totp-secret.js";

const PERIOD_SECONDS = 30;
const DIGITS = 6;

/**
 * The concrete RFC 6238 TOTP implementation.
 *
 * The static helpers are pure and synchronous, and are tested directly against
 * the RFC's published vectors. The instance methods adapt that logic to the
 * asynchronous {@link TotpAlgorithm} port consumed by the use cases.
 */
export class Rfc6238TotpAlgorithm implements TotpAlgorithm {
  async generateSecret(accountName: string, issuer = "Verixa"): Promise<TotpSecretLike> {
    const secret = TotpSecret.generate();
    return {
      value: secret.value,
      provisioningUri: secret.getProvisioningUri(accountName, issuer),
    };
  }

  async verify(secretValue: string, code: string, driftWindow = 1): Promise<number | null> {
    const secret = TotpSecret.fromString(secretValue);
    if (!Result.isOk(secret)) {
      return null;
    }

    const now = Date.now();
    for (let offset = -driftWindow; offset <= driftWindow; offset += 1) {
      const timestamp = now + offset * PERIOD_SECONDS * 1_000;
      if (Rfc6238TotpAlgorithm.generate(secret.value, timestamp) === code) {
        return Math.floor(timestamp / 1_000 / PERIOD_SECONDS);
      }
    }
    return null;
  }

  /** Generates the 6-digit code for a secret at a given instant. */
  static generate(secret: TotpSecret, timestamp: number = Date.now()): string {
    const timeStep = Math.floor(timestamp / 1_000 / PERIOD_SECONDS);

    const buffer = Buffer.alloc(8);
    const high = Math.floor(timeStep / 0x1_0000_0000);
    const low = timeStep & 0xffff_ffff;
    buffer.writeUInt32BE(high, 0);
    buffer.writeUInt32BE(low, 4);

    const secretBytes = base32.decode(secret.value);
    const hmac = crypto.createHmac("sha1", secretBytes).update(buffer).digest();

    const offset = hmac[hmac.length - 1]! & 0xf;
    const code =
      ((hmac[offset]! & 0x7f) << 24) |
      ((hmac[offset + 1]! & 0xff) << 16) |
      ((hmac[offset + 2]! & 0xff) << 8) |
      (hmac[offset + 3]! & 0xff);

    const otp = code % 10 ** DIGITS;
    return otp.toString().padStart(DIGITS, "0");
  }

  /** Boolean form of {@link verify}, used by the RFC vector tests. */
  static isValid(
    secret: TotpSecret,
    code: string,
    options?: { timestamp?: number; window?: number },
  ): boolean {
    const timestamp = options?.timestamp ?? Date.now();
    const window = options?.window ?? 1;

    for (let offset = -window; offset <= window; offset += 1) {
      const ts = timestamp + offset * PERIOD_SECONDS * 1_000;
      const generated = this.generate(secret, ts);
      if (crypto.timingSafeEqual(Buffer.from(generated), Buffer.from(code))) {
        return true;
      }
    }
    return false;
  }
}
