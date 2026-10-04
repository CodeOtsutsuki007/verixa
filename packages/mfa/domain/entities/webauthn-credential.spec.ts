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
import { asId } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { WebAuthnCredential } from "./webauthn-credential.js";

describe("WebAuthnCredential", () => {
  const userId = asId<"UserId">("user-1");
  const mfaMethodId = asId<"MfaMethodId">("method-1");

  it("creates a WebAuthnCredential with defaults", () => {
    const cred = WebAuthnCredential.create({
      credentialId: "cred-abc",
      userId,
      mfaMethodId,
      publicKey: "pub-key-123",
      attestationType: "none",
      aaguid: "00000000-0000-0000-0000-000000000000",
      deviceName: "Security Key",
    });

    expect(cred.id).toBeDefined();
    expect(cred.credentialId).toBe("cred-abc");
    expect(cred.userId).toBe(userId);
    expect(cred.mfaMethodId).toBe(mfaMethodId);
    expect(cred.publicKey).toBe("pub-key-123");
    expect(cred.signCounter).toBe(0);
    expect(cred.transports).toEqual([]);
    expect(cred.attestationType).toBe("none");
    expect(cred.deviceName).toBe("Security Key");
    expect(cred.lastUsedAt).toBeUndefined();
  });

  it("updates sign counter and lastUsedAt", () => {
    const cred = WebAuthnCredential.create({
      credentialId: "cred-abc",
      userId,
      mfaMethodId,
      publicKey: "pub-key-123",
      attestationType: "none",
    });

    const now = new Date("2026-09-25T14:00:00Z");
    const updated = cred.updateSignCounter(5, now);

    expect(updated.signCounter).toBe(5);
    expect(updated.lastUsedAt).toEqual(now);
  });

  it("reconstitutes from persisted data", () => {
    const now = new Date();
    const cred = WebAuthnCredential.reconstitute({
      id: asId("cred-id-1"),
      credentialId: "cred-abc",
      userId,
      mfaMethodId,
      publicKey: "pub-key",
      signCounter: 42,
      transports: ["usb"],
      attestationType: "packed",
      createdAt: now,
    });

    expect(cred.id).toBe("cred-id-1");
    expect(cred.signCounter).toBe(42);
    expect(cred.transports).toEqual(["usb"]);
  });
});
