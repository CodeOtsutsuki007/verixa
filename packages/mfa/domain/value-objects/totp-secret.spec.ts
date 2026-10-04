import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";
import { TotpSecret } from "../value-objects/totp-secret.js";

describe("TotpSecret", () => {
  it("generates a new secret successfully", () => {
    const secret = TotpSecret.generate();
    expect(secret.value).toMatch(/^[A-Z2-7]+$/);
  });

  it("can be created from a valid base32 string", () => {
    const valid = "GEZDGNBVGY3TQOJQ";
    const result = TotpSecret.fromString(valid);
    expect(Result.isOk(result)).toBe(true);
    if (Result.isOk(result)) {
      expect(result.value.value).toBe(valid);
    }
  });

  it("fails to create from an invalid base32 string", () => {
    const invalid = "1234567890"; // 1, 8, 9, 0 are not in RFC 4648 base32
    const result = TotpSecret.fromString(invalid);
    expect(Result.isErr(result)).toBe(true);
  });

  it("generates a valid provisioning URI", () => {
    const result = TotpSecret.fromString("GEZDGNBVGY3TQOJQ");
    if (!Result.isOk(result)) throw new Error("Failed");
    const secret = result.value;
    const uri = secret.getProvisioningUri("alice@example.com", "Verixa Local");
    expect(uri).toBe(
      "otpauth://totp/Verixa%20Local:alice%40example.com?secret=GEZDGNBVGY3TQOJQ&issuer=Verixa%20Local&algorithm=SHA1&digits=6&period=30",
    );
  });

  it("redacts secret in JSON serialization and toString", () => {
    const secret = TotpSecret.generate();
    expect(secret.toString()).toBe("<redacted>");
    expect(JSON.stringify(secret)).toBe('"<redacted>"');
  });
});
