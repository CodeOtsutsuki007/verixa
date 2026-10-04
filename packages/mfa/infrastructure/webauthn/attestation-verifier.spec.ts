import crypto from "node:crypto";

import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { WebAuthnAttestationVerifier } from "./attestation-verifier.js";
import { encodeCbor } from "./cbor.js";

function createValidAuthData(options: {
  rpId: string;
  flags?: number;
  signCount?: number;
  aaguid?: Uint8Array;
  credentialId?: Uint8Array;
  publicKey?: Uint8Array;
}): Uint8Array {
  const rpIdHash = crypto.createHash("sha256").update(options.rpId).digest();
  const flags = options.flags ?? 0x01 | 0x40; // UP and AT
  const signCount = options.signCount ?? 0;
  const aaguid = options.aaguid ?? new Uint8Array(16).fill(0xaa);
  const credentialId =
    options.credentialId ?? new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  const publicKey =
    options.publicKey ??
    new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]); // mock COSE key

  const authData = new Uint8Array(37 + 16 + 2 + credentialId.length + publicKey.length);
  authData.set(rpIdHash, 0);
  authData[32] = flags;

  const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
  view.setUint32(33, signCount, false);

  authData.set(aaguid, 37);
  view.setUint16(53, credentialId.length, false);
  authData.set(credentialId, 55);
  authData.set(publicKey, 55 + credentialId.length);

  return authData;
}

function createAttestationObject(
  authData: Uint8Array,
  fmt = "none",
  attStmt: Record<string, unknown> = {},
): Uint8Array {
  return encodeCbor({
    fmt,
    attStmt,
    authData,
  });
}

function createClientDataJSON(options: {
  type?: string;
  challenge: string;
  origin: string;
}): string {
  return JSON.stringify({
    type: options.type ?? "webauthn.create",
    challenge: options.challenge,
    origin: options.origin,
    crossOrigin: false,
  });
}

describe("WebAuthnAttestationVerifier", () => {
  const verifier = new WebAuthnAttestationVerifier();
  const defaultRpId = "verixa.example";
  const defaultOrigin = "https://verixa.example";
  const defaultChallenge = "k3Y9-sample-random-challenge-base64url";

  it("verifies a valid WebAuthn registration attestation with fmt=none", async () => {
    const authData = createValidAuthData({ rpId: defaultRpId });
    const attestationObject = createAttestationObject(authData);
    const clientDataJSON = createClientDataJSON({
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    expect(result.value.attestationType).toBe("none");
    expect(result.value.rpId).toBe(defaultRpId);
    expect(result.value.origin).toBe(defaultOrigin);
    expect(result.value.signCounter).toBe(0);
    expect(result.value.credentialId).toBeDefined();
    expect(result.value.credentialPublicKey).toBeDefined();
    expect(result.value.aaguid).toBe("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
  });

  it("rejects when clientDataJSON has invalid type", async () => {
    const authData = createValidAuthData({ rpId: defaultRpId });
    const attestationObject = createAttestationObject(authData);
    const clientDataJSON = createClientDataJSON({
      type: "webauthn.get",
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain('expected "webauthn.create"');
  });

  it("rejects when challenge in clientDataJSON does not match expected challenge", async () => {
    const authData = createValidAuthData({ rpId: defaultRpId });
    const attestationObject = createAttestationObject(authData);
    const clientDataJSON = createClientDataJSON({
      challenge: "tampered-challenge",
      origin: defaultOrigin,
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("Challenge mismatch");
  });

  it("rejects when origin in clientDataJSON does not match expected origin (phishing prevention)", async () => {
    const authData = createValidAuthData({ rpId: defaultRpId });
    const attestationObject = createAttestationObject(authData);
    const clientDataJSON = createClientDataJSON({
      challenge: defaultChallenge,
      origin: "https://phishing-site.example",
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("Origin mismatch");
  });

  it("rejects when RP ID hash in authData does not match expected RP ID", async () => {
    const authData = createValidAuthData({ rpId: "different-rp.com" });
    const attestationObject = createAttestationObject(authData);
    const clientDataJSON = createClientDataJSON({
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("RP ID hash mismatch");
  });

  it("rejects when User Present (UP) flag is 0", async () => {
    const authData = createValidAuthData({
      rpId: defaultRpId,
      flags: 0x40, // AT set, UP missing
    });
    const attestationObject = createAttestationObject(authData);
    const clientDataJSON = createClientDataJSON({
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("User Present (UP) flag was not set");
  });

  it("rejects when Attested Credential Data (AT) flag is 0 in registration", async () => {
    const authData = createValidAuthData({
      rpId: defaultRpId,
      flags: 0x01, // UP set, AT missing
    });
    const attestationObject = createAttestationObject(authData);
    const clientDataJSON = createClientDataJSON({
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("Attested Credential Data (AT) flag was not set");
  });

  it("rejects malformed clientDataJSON that is not valid JSON", async () => {
    const authData = createValidAuthData({ rpId: defaultRpId });
    const attestationObject = createAttestationObject(authData);

    const result = await verifier.verify({
      clientDataJSON: "invalid json string <<>>",
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("JSON parse error");
  });

  it("rejects malformed attestationObject that cannot be CBOR decoded", async () => {
    const clientDataJSON = createClientDataJSON({
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject: new Uint8Array([0xff, 0xff, 0xff]),
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("CBOR decode failed");
  });

  it("rejects attestationObject with non-empty attStmt when fmt=none", async () => {
    const authData = createValidAuthData({ rpId: defaultRpId });
    const attestationObject = createAttestationObject(authData, "none", { extra: "data" });
    const clientDataJSON = createClientDataJSON({
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain('Attestation statement for "none" format must be empty');
  });

  it("handles base64url encoded strings for clientDataJSON and attestationObject", async () => {
    const authData = createValidAuthData({ rpId: defaultRpId });
    const attestationBytes = createAttestationObject(authData);
    const attestationBase64Url = Buffer.from(attestationBytes).toString("base64url");

    const clientDataString = createClientDataJSON({
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });
    const clientDataBase64Url = Buffer.from(clientDataString).toString("base64url");

    const result = await verifier.verify({
      clientDataJSON: clientDataBase64Url,
      attestationObject: attestationBase64Url,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isOk(result)).toBe(true);
  });

  it("rejects when authData is shorter than minimum 37 bytes", async () => {
    const truncatedAuthData = new Uint8Array(20);
    const attestationObject = createAttestationObject(truncatedAuthData);
    const clientDataJSON = createClientDataJSON({
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("less than minimum 37 bytes");
  });

  it("rejects when authData is shorter than 55 bytes for attested credential data", async () => {
    const authData = new Uint8Array(45);
    const rpIdHash = crypto.createHash("sha256").update(defaultRpId).digest();
    authData.set(rpIdHash, 0);
    authData[32] = 0x41; // UP | AT
    const attestationObject = createAttestationObject(authData);
    const clientDataJSON = createClientDataJSON({
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("insufficient length");
  });

  it("rejects when credentialId extends past authData buffer length", async () => {
    const authData = new Uint8Array(60);
    const rpIdHash = crypto.createHash("sha256").update(defaultRpId).digest();
    authData.set(rpIdHash, 0);
    authData[32] = 0x41; // UP | AT
    const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
    view.setUint16(53, 100, false); // Length 100, but buffer is only 60
    const attestationObject = createAttestationObject(authData);
    const clientDataJSON = createClientDataJSON({
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("credentialId extends past buffer");
  });

  it("rejects when credential public key is missing", async () => {
    const credId = new Uint8Array([1, 2, 3, 4]);
    const authData = new Uint8Array(55 + credId.length); // exactly credId, no public key bytes
    const rpIdHash = crypto.createHash("sha256").update(defaultRpId).digest();
    authData.set(rpIdHash, 0);
    authData[32] = 0x41;
    const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
    view.setUint16(53, credId.length, false);
    authData.set(credId, 55);

    const attestationObject = createAttestationObject(authData);
    const clientDataJSON = createClientDataJSON({
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("missing public key");
  });

  it("rejects when root CBOR is not a map", async () => {
    const attestationObject = encodeCbor(["not", "a", "map"]);
    const clientDataJSON = createClientDataJSON({
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });

    const result = await verifier.verify({
      clientDataJSON,
      attestationObject,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("root CBOR value is not a map");
  });

  it("rejects when fmt or authData are missing or wrong type in attestationObject", async () => {
    const clientDataJSON = createClientDataJSON({
      challenge: defaultChallenge,
      origin: defaultOrigin,
    });

    // Missing fmt
    const noFmt = encodeCbor(new Map([["authData", new Uint8Array(40)]]));
    const res1 = await verifier.verify({
      clientDataJSON,
      attestationObject: noFmt,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });
    expect(Result.isErr(res1)).toBe(true);

    // Missing authData
    const noAuth = encodeCbor(new Map([["fmt", "none"]]));
    const res2 = await verifier.verify({
      clientDataJSON,
      attestationObject: noAuth,
      expectedChallenge: defaultChallenge,
      expectedOrigin: defaultOrigin,
      expectedRpId: defaultRpId,
    });
    expect(Result.isErr(res2)).toBe(true);
  });
});
