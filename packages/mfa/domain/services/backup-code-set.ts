import { randomBytes } from "crypto";

import { hash as argon2Hash, verify as argon2Verify } from "@node-rs/argon2";

export interface BackupCodeGenerationResult {
  /** The plaintext codes to show the user EXACTLY ONCE. */
  rawCodes: string[];
  /** The hashed codes to store in the database. */
  hashedCodes: string[];
}

export class BackupCodeSet {
  private static readonly CODE_COUNT = 10;
  private static readonly CODE_LENGTH = 10;

  // Character set avoiding ambiguous characters like 0/O, 1/I/l
  private static readonly CHARSET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

  /**
   * Generates a new set of backup codes.
   * Returns the plaintext codes for immediate display to the user,
   * along with the salted hashes to be persisted.
   */
  public static async generate(
    count: number = this.CODE_COUNT,
  ): Promise<BackupCodeGenerationResult> {
    const rawCodes: string[] = [];
    const hashedCodes: string[] = [];

    for (let i = 0; i < count; i++) {
      const code = this.generateSingleCode();
      rawCodes.push(code);

      // Hash using Argon2. We use standard parameters (Issue 061).
      // Since backup codes are basically passwords, Argon2 provides protection against offline brute force.
      const hash = await argon2Hash(code, {
        memoryCost: 19456, // 19 MiB
        timeCost: 2,
        outputLen: 32,
        parallelism: 1,
      });
      hashedCodes.push(hash);
    }

    return { rawCodes, hashedCodes };
  }

  /**
   * Generates a single high-entropy, human-readable backup code.
   * E.g. "A4K9-7M2P-9Q" or just a 10-char string. Let's do 10 chars separated by a dash: "ABCDE-FGHIJ"
   */
  private static generateSingleCode(): string {
    const randomBuffer = randomBytes(this.CODE_LENGTH);
    let code = "";
    for (let i = 0; i < this.CODE_LENGTH; i++) {
      code += this.CHARSET[randomBuffer[i]! % this.CHARSET.length];
    }
    // Format as XXXXX-XXXXX
    return code.slice(0, 5) + "-" + code.slice(5);
  }

  /**
   * Verifies a raw backup code against a stored hash.
   */
  public static async verify(rawCode: string, hash: string): Promise<boolean> {
    // Normalize user input (uppercase, remove spaces/dashes)
    // Actually, verify shouldn't mutate unless we stored it mutated.
    // The generateSingleCode formats with a dash. We should expect the user to input with or without dash.
    // To keep it simple, we'll verify against the exact raw code. If the controller strips dashes, it should do it before hashing.
    // Let's just normalize for robustness:
    const normalizedRaw = rawCode.toUpperCase().replace(/[^A-Z0-9]/g, "");
    const expectedFormat = normalizedRaw.slice(0, 5) + "-" + normalizedRaw.slice(5);

    return argon2Verify(hash, expectedFormat);
  }
}
