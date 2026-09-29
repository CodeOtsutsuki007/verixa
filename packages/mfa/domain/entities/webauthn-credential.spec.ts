import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { createId } from "@verixa/shared-kernel";
import type { MfaMethodId, UserId } from "./mfa-method.js";
import { WebAuthnCredential } from "./webauthn-credential.js";

describe("WebAuthnCredential", () => {
  const userId = createId<"UserId">();
  const mfaMethodId = createId<"MfaMethodId">();

  it("registers a valid WebAuthn credential without private key", () => {
    const result = WebAuthnCredential.register({
      userId,
      mfaMethodId,
      credentialId: "cred-id-123",
      publicKey: "public-key-bytes-or-pem",
      transports: ["internal", "usb"],
      attestationType: "packed",
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isOk(result)) {
      expect(result.value.credentialId).toBe("cred-id-123");
      expect(result.value.publicKey).toBe("public-key-bytes-or-pem");
      expect(result.value.signCounter).toBe(0);
      expect(result.value.transports).toEqual(["internal", "usb"]);
      expect(result.value.attestationType).toBe("packed");
      expect(result.value.lastUsedAt).toBeUndefined();
    }
  });

  it("rejects registration without credentialId or publicKey", () => {
    const noCredId = WebAuthnCredential.register({
      userId,
      mfaMethodId,
      credentialId: "",
      publicKey: "pubkey",
    });
    expect(Result.isErr(noCredId)).toBe(true);

    const noPubKey = WebAuthnCredential.register({
      userId,
      mfaMethodId,
      credentialId: "cred",
      publicKey: "   ",
    });
    expect(Result.isErr(noPubKey)).toBe(true);
  });

  it("updates signCounter successfully when counter increases or stays equal", () => {
    const cred = WebAuthnCredential.register({
      userId,
      mfaMethodId,
      credentialId: "cred",
      publicKey: "pubkey",
      signCounter: 5,
    });
    if (!Result.isOk(cred)) throw new Error("setup failed");

    const updated = cred.value.updateSignCounter(10);
    expect(Result.isOk(updated)).toBe(true);
    if (Result.isOk(updated)) {
      expect(updated.value.signCounter).toBe(10);
      expect(updated.value.lastUsedAt).toBeInstanceOf(Date);
    }
  });

  it("rejects signCounter regression (clone detection for Issue 113)", () => {
    const cred = WebAuthnCredential.register({
      userId,
      mfaMethodId,
      credentialId: "cred",
      publicKey: "pubkey",
      signCounter: 10,
    });
    if (!Result.isOk(cred)) throw new Error("setup failed");

    const regression = cred.value.updateSignCounter(9);
    expect(Result.isErr(regression)).toBe(true);
    if (Result.isErr(regression)) {
      expect(regression.error.fieldErrors["signCounter"]).toContain("clone_detected");
    }
  });
});
