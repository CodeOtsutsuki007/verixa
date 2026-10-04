import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";
import { TotpSecret } from "../value-objects/totp-secret.js";
import { Rfc6238TotpAlgorithm } from "./rfc-totp-algorithm.js";

describe("Rfc6238TotpAlgorithm", () => {
  // RFC 6238 test vectors for HMAC-SHA1
  // Secret is "12345678901234567890" in ASCII, which encodes to:
  const rfcSecretString = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

  const vectors = [
    { time: 59, code: "287082" },
    { time: 1111111109, code: "081804" },
    { time: 1111111111, code: "050471" },
    { time: 1234567890, code: "005924" },
    { time: 2000000000, code: "279037" },
    { time: 20000000000, code: "353130" },
  ];

  it("generates codes matching RFC 6238 test vectors", () => {
    const secretResult = TotpSecret.fromString(rfcSecretString);
    if (!Result.isOk(secretResult)) throw new Error("Invalid secret");
    const secret = secretResult.value;

    for (const vector of vectors) {
      // time in the RFC is in seconds, algorithm expects milliseconds
      const code = Rfc6238TotpAlgorithm.generate(secret, vector.time * 1000);
      expect(code).toBe(vector.code);
    }
  });

  describe("TotpAlgorithm port (instance methods)", () => {
    const algorithm = new Rfc6238TotpAlgorithm();

    it("generates a CSPRNG secret and an otpauth provisioning URI", async () => {
      const generated = await algorithm.generateSecret("alice@example.com", "Verixa");
      expect(generated.value).toMatch(/^[A-Z2-7]+$/);
      expect(generated.provisioningUri).toContain("otpauth://totp");
      expect(generated.provisioningUri).toContain(`secret=${generated.value}`);
      expect(generated.provisioningUri).toContain(encodeURIComponent("alice@example.com"));
    });

    it("verifies a code generated for the current time step", async () => {
      const secret = TotpSecret.generate();
      const code = Rfc6238TotpAlgorithm.generate(secret, Date.now());
      await expect(algorithm.verify(secret.value, code)).resolves.toEqual(expect.any(Number));
    });

    it("rejects an invalid code", async () => {
      const secret = TotpSecret.generate();
      const current = Rfc6238TotpAlgorithm.generate(secret, Date.now());
      const wrong = current === "000000" ? "111111" : "000000";
      await expect(algorithm.verify(secret.value, wrong)).resolves.toBeNull();
    });

    it("rejects a secret that is not valid base32", async () => {
      await expect(algorithm.verify("not base32!!", "123456")).resolves.toBeNull();
    });
  });

  describe("isValid", () => {
    it("accepts a valid code", () => {
      const secretResult = TotpSecret.fromString(rfcSecretString);
      if (!Result.isOk(secretResult)) throw new Error("Invalid secret");
      const secret = secretResult.value;

      const isValid = Rfc6238TotpAlgorithm.isValid(secret, "081804", {
        timestamp: 1111111109 * 1000,
      });
      expect(isValid).toBe(true);
    });

    it("rejects an invalid code", () => {
      const secretResult = TotpSecret.fromString(rfcSecretString);
      if (!Result.isOk(secretResult)) throw new Error("Invalid secret");
      const secret = secretResult.value;

      const isValid = Rfc6238TotpAlgorithm.isValid(secret, "999999", {
        timestamp: 1111111109 * 1000,
      });
      expect(isValid).toBe(false);
    });

    it("accepts a code within the time window", () => {
      const secretResult = TotpSecret.fromString(rfcSecretString);
      if (!Result.isOk(secretResult)) throw new Error("Invalid secret");
      const secret = secretResult.value;

      // 1111111109 is in the 1111111080 - 1111111110 window
      // 1111111139 is one window ahead (30s later).
      // If we verify at 1111111139 with window=1, it should accept the previous window's code
      const isValid = Rfc6238TotpAlgorithm.isValid(secret, "081804", {
        timestamp: 1111111139 * 1000,
        window: 1,
      });
      expect(isValid).toBe(true);
    });
  });
});
