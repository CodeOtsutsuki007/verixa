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
