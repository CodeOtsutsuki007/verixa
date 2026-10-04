import { createId, Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { VerificationType } from "../value-objects/verification-type.js";

import { Evidence } from "./evidence.js";

const CHECKSUM = "b".repeat(64);

function attach(params: {
  verificationType: string;
  evidenceType: string;
  storageRef?: string;
  checksum?: string;
}) {
  return Evidence.attach({
    requestId: createId<"VerificationRequestId">(),
    verificationType: VerificationType.reconstitute(
      params.verificationType as Parameters<typeof VerificationType.reconstitute>[0],
    ),
    evidenceType: params.evidenceType,
    storageRef: params.storageRef ?? "evidence/abc-123",
    checksum: params.checksum ?? CHECKSUM,
  });
}

describe("Evidence", () => {
  it("attaches a document valid for an identity-document request", () => {
    const attached = attach({
      verificationType: "identity-document",
      evidenceType: "government-id-front",
    });

    expect(Result.isOk(attached)).toBe(true);
    if (Result.isOk(attached)) {
      expect(attached.value.typeValue).toBe("government-id-front");
      expect(attached.value.storageRef).toBe("evidence/abc-123");
      expect(attached.value.checksum).toBe(CHECKSUM);
      expect(attached.value.uploadedAt).toBeInstanceOf(Date);
    }
  });

  it("rejects an evidence type that does not belong to the request's verification type", () => {
    // The pairing invariant: a selfie is a real evidence type and an
    // identity-document is a real verification type, but one cannot satisfy
    // the other. Attaching it here is what keeps the reviewer queue free of
    // cases no reviewer could act on.
    const attached = attach({
      verificationType: "identity-document",
      evidenceType: "selfie",
    });

    expect(Result.isErr(attached)).toBe(true);
    if (Result.isErr(attached)) {
      expect(attached.error.fieldErrors["evidenceType"]).toEqual(["invalid_for_verification_type"]);
    }
  });

  it("accepts a selfie for a liveness request and proof-of-address for an address request", () => {
    expect(Result.isOk(attach({ verificationType: "liveness", evidenceType: "selfie" }))).toBe(
      true,
    );
    expect(
      Result.isOk(attach({ verificationType: "address", evidenceType: "proof-of-address" })),
    ).toBe(true);
  });

  it("rejects an unknown evidence type", () => {
    const attached = attach({ verificationType: "liveness", evidenceType: "birth-certificate" });

    expect(Result.isErr(attached)).toBe(true);
    if (Result.isErr(attached)) {
      expect(attached.error.fieldErrors["evidenceType"]).toEqual(["unsupported"]);
    }
  });

  it("requires an opaque storage reference, never raw bytes", () => {
    const empty = attach({
      verificationType: "liveness",
      evidenceType: "selfie",
      storageRef: "   ",
    });
    const inline = attach({
      verificationType: "liveness",
      evidenceType: "selfie",
      storageRef: "data:image/png;base64,iVBORw0KGgo=",
    });
    const tooLong = attach({
      verificationType: "liveness",
      evidenceType: "selfie",
      storageRef: "x".repeat(1025),
    });

    expect(Result.isErr(empty)).toBe(true);
    expect(Result.isErr(inline)).toBe(true);
    expect(Result.isErr(tooLong)).toBe(true);
    if (Result.isErr(inline)) {
      expect(inline.error.fieldErrors["storageRef"]).toEqual(["not_a_reference"]);
    }
  });

  it("requires a 64-character lowercase hex checksum", () => {
    const short = attach({
      verificationType: "liveness",
      evidenceType: "selfie",
      checksum: "abc",
    });
    const uppercase = attach({
      verificationType: "liveness",
      evidenceType: "selfie",
      checksum: "B".repeat(64),
    });

    expect(Result.isErr(short)).toBe(true);
    expect(Result.isErr(uppercase)).toBe(true);
    if (Result.isErr(short)) {
      expect(short.error.fieldErrors["checksum"]).toEqual(["invalid_sha256"]);
    }
  });

  it("reports which request it belongs to", () => {
    const requestId = createId<"VerificationRequestId">();
    const attached = Evidence.attach({
      requestId,
      verificationType: VerificationType.reconstitute("liveness"),
      evidenceType: "selfie",
      storageRef: "evidence/xyz",
      checksum: CHECKSUM,
    });
    if (Result.isErr(attached)) throw new Error("fixture setup failed");

    expect(attached.value.belongsTo(requestId)).toBe(true);
    expect(attached.value.belongsTo(createId<"VerificationRequestId">())).toBe(false);
  });
});
