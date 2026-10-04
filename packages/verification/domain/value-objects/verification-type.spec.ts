import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { isVerificationType, VerificationType } from "./verification-type.js";

describe("VerificationType", () => {
  it("accepts each supported type", () => {
    for (const value of ["identity-document", "address", "liveness"]) {
      const created = VerificationType.create(value);
      expect(Result.isOk(created)).toBe(true);
      if (Result.isOk(created)) {
        expect(created.value.value).toBe(value);
      }
      expect(isVerificationType(value)).toBe(true);
    }
  });

  it("rejects a type it does not define", () => {
    const created = VerificationType.create("biometric-retina");

    expect(Result.isErr(created)).toBe(true);
    if (Result.isErr(created)) {
      expect(created.error.fieldErrors["verificationType"]).toEqual(["unsupported"]);
    }
    expect(isVerificationType("biometric-retina")).toBe(false);
  });

  it("compares and prints by value", () => {
    const address = VerificationType.reconstitute("address");

    expect(address.equals(VerificationType.reconstitute("address"))).toBe(true);
    expect(address.equals(VerificationType.reconstitute("liveness"))).toBe(false);
    expect(VerificationType.reconstitute("liveness").toString()).toBe("liveness");
  });
});
