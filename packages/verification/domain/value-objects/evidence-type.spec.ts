import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { EvidenceType, isEvidenceType, requiredEvidenceTypesFor } from "./evidence-type.js";

describe("EvidenceType", () => {
  it("accepts each supported evidence type", () => {
    for (const value of [
      "government-id-front",
      "government-id-back",
      "selfie",
      "proof-of-address",
    ]) {
      expect(Result.isOk(EvidenceType.create(value))).toBe(true);
      expect(isEvidenceType(value)).toBe(true);
    }
  });

  it("rejects an evidence type it does not define", () => {
    const created = EvidenceType.create("utility-bill-selfie");

    expect(Result.isErr(created)).toBe(true);
    if (Result.isErr(created)) {
      expect(created.error.fieldErrors["evidenceType"]).toEqual(["unsupported"]);
    }
  });

  it("knows which verification types each evidence type satisfies", () => {
    expect(EvidenceType.reconstitute("selfie").isValidFor("liveness")).toBe(true);
    expect(EvidenceType.reconstitute("selfie").isValidFor("address")).toBe(false);
    expect(EvidenceType.reconstitute("proof-of-address").isValidFor("address")).toBe(true);
    expect(EvidenceType.reconstitute("government-id-back").isValidFor("identity-document")).toBe(
      true,
    );
  });

  it("lists the required evidence types in prompt order", () => {
    expect(requiredEvidenceTypesFor("identity-document")).toEqual([
      "government-id-front",
      "government-id-back",
    ]);
    expect(requiredEvidenceTypesFor("address")).toEqual(["proof-of-address"]);
    expect(requiredEvidenceTypesFor("liveness")).toEqual(["selfie"]);
  });

  it("compares and prints by value", () => {
    const selfie = EvidenceType.reconstitute("selfie");

    expect(selfie.equals(EvidenceType.reconstitute("selfie"))).toBe(true);
    expect(selfie.equals(EvidenceType.reconstitute("proof-of-address"))).toBe(false);
    expect(selfie.toString()).toBe("selfie");
  });
});
