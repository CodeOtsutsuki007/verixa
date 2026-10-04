import crypto from "node:crypto";

import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { WebAuthnAssertionVerifier } from "./assertion-verifier.js";
import { encodeCbor } from "./cbor.js";

function generateTestEcKeyPair() {
  return crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

function coseKeyFromEcPublicKey(publicKey: crypto.KeyObject): Uint8Array {
  const jwk = publicKey.export({ format: "jwk" });
  const x = Buffer.from(jwk.x!, "base64url");
  const y = Buffer.from(jwk.y!, "base64url");

  return encodeCbor(
    new Map<number, unknown>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, x],
      [-3, y],
    ]),
  );
}

function createAuthData(options: { rpId: string; flags?: number; signCount?: number }): Uint8Array {
  const rpIdHash = crypto.createHash("sha256").update(options.rpId).digest();
  const flags = options.flags ?? 0x01; // UP
  const signCount = options.signCount ?? 1;

  const authData = new Uint8Array(37);
  authData.set(rpIdHash, 0);
  authData[32] = flags;

  const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
  view.setUint32(33, signCount, false);

  return authData;
}

function createClientDataJSON(options: {
  type?: string;
  challenge: string;
  origin: string;
}): string {
  return JSON.stringify({
    type: options.type ?? "webauthn.get",
    challenge: options.challenge,
    origin: options.origin,
  });
}

function signAssertion(
  authData: Uint8Array,
  clientDataJSON: string,
  privateKey: crypto.KeyObject,
): Uint8Array {
  const clientDataHash = crypto
    .createHash("sha256")
    .update(Buffer.from(clientDataJSON, "utf-8"))
    .digest();
  const verifyData = Buffer.concat([Buffer.from(authData), clientDataHash]);

  return crypto.sign("sha256", verifyData, privateKey);
}

describe("WebAuthnAssertionVerifier", () => {
  const verifier = new WebAuthnAssertionVerifier();
  const rpId = "verixa.example";
  const origin = "https://verixa.example";
  const challenge = "test-auth-challenge-123456";

  it("successfully verifies a valid assertion signed with a COSE public key", async () => {
    const keyPair = generateTestEcKeyPair();
    const coseKeyBytes = coseKeyFromEcPublicKey(keyPair.publicKey);
    const coseKeyBase64Url = Buffer.from(coseKeyBytes).toString("base64url");

    const authData = createAuthData({ rpId, signCount: 42, flags: 0x05 }); // UP | UV
    const clientDataJSON = createClientDataJSON({ challenge, origin });
    const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

    const result = await verifier.verify({
      credentialId: "cred_123",
      clientDataJSON,
      authenticatorData: authData,
      signature,
      credentialPublicKey: coseKeyBase64Url,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isOk(result)) {
      expect(result.value.credentialId).toBe("cred_123");
      expect(result.value.signCounter).toBe(42);
      expect(result.value.userPresent).toBe(true);
      expect(result.value.userVerified).toBe(true);
      expect(result.value.rpId).toBe(rpId);
      expect(result.value.origin).toBe(origin);
    }
  });

  it("successfully verifies a valid assertion signed with a PEM public key", async () => {
    const keyPair = generateTestEcKeyPair();
    const pemKey = keyPair.publicKey.export({ format: "pem", type: "spki" }) as string;

    const authData = createAuthData({ rpId, signCount: 10 });
    const clientDataJSON = createClientDataJSON({ challenge, origin });
    const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

    const result = await verifier.verify({
      credentialId: "cred_pem",
      clientDataJSON,
      authenticatorData: authData,
      signature,
      credentialPublicKey: pemKey,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isOk(result)) {
      expect(result.value.signCounter).toBe(10);
    }
  });

  it("fails when clientDataJSON has invalid type", async () => {
    const keyPair = generateTestEcKeyPair();
    const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");
    const authData = createAuthData({ rpId });
    const clientDataJSON = createClientDataJSON({
      type: "webauthn.create",
      challenge,
      origin,
    });
    const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

    const result = await verifier.verify({
      credentialId: "cred_1",
      clientDataJSON,
      authenticatorData: authData,
      signature,
      credentialPublicKey: coseKey,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.message).toContain('expected "webauthn.get"');
    }
  });

  it("fails when challenge does not match", async () => {
    const keyPair = generateTestEcKeyPair();
    const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");
    const authData = createAuthData({ rpId });
    const clientDataJSON = createClientDataJSON({
      challenge: "mismatched-challenge",
      origin,
    });
    const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

    const result = await verifier.verify({
      credentialId: "cred_1",
      clientDataJSON,
      authenticatorData: authData,
      signature,
      credentialPublicKey: coseKey,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.message).toContain("Challenge mismatch");
    }
  });

  it("fails when origin does not match", async () => {
    const keyPair = generateTestEcKeyPair();
    const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");
    const authData = createAuthData({ rpId });
    const clientDataJSON = createClientDataJSON({
      challenge,
      origin: "https://phishing.site",
    });
    const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

    const result = await verifier.verify({
      credentialId: "cred_1",
      clientDataJSON,
      authenticatorData: authData,
      signature,
      credentialPublicKey: coseKey,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.message).toContain("Origin mismatch");
    }
  });

  it("fails when RP ID hash does not match", async () => {
    const keyPair = generateTestEcKeyPair();
    const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");
    const authData = createAuthData({ rpId: "other.domain.com" });
    const clientDataJSON = createClientDataJSON({ challenge, origin });
    const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

    const result = await verifier.verify({
      credentialId: "cred_1",
      clientDataJSON,
      authenticatorData: authData,
      signature,
      credentialPublicKey: coseKey,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.message).toContain("RP ID hash mismatch");
    }
  });

  it("fails when User Present (UP) flag is missing", async () => {
    const keyPair = generateTestEcKeyPair();
    const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");
    const authData = createAuthData({ rpId, flags: 0x00 }); // UP is bit 0, 0x00 has no UP
    const clientDataJSON = createClientDataJSON({ challenge, origin });
    const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

    const result = await verifier.verify({
      credentialId: "cred_1",
      clientDataJSON,
      authenticatorData: authData,
      signature,
      credentialPublicKey: coseKey,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.message).toContain("User Present (UP) flag is not set");
    }
  });

  it("fails when signature is cryptographically invalid", async () => {
    const keyPair1 = generateTestEcKeyPair();
    const keyPair2 = generateTestEcKeyPair(); // Different key
    const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair1.publicKey)).toString("base64url");

    const authData = createAuthData({ rpId });
    const clientDataJSON = createClientDataJSON({ challenge, origin });
    // Sign with keyPair2 instead of keyPair1
    const invalidSignature = signAssertion(authData, clientDataJSON, keyPair2.privateKey);

    const result = await verifier.verify({
      credentialId: "cred_1",
      clientDataJSON,
      authenticatorData: authData,
      signature: invalidSignature,
      credentialPublicKey: coseKey,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.message).toContain("signature verification failed");
    }
  });

  it("fails on malformed authenticatorData", async () => {
    const keyPair = generateTestEcKeyPair();
    const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");
    const clientDataJSON = createClientDataJSON({ challenge, origin });

    const result = await verifier.verify({
      credentialId: "cred_1",
      clientDataJSON,
      authenticatorData: new Uint8Array([1, 2, 3]), // too short
      signature: new Uint8Array(64),
      credentialPublicKey: coseKey,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.message).toContain("less than required 37 bytes");
    }
  });

  it("fails when clientDataJSON is malformed JSON", async () => {
    const keyPair = generateTestEcKeyPair();
    const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");
    const authData = createAuthData({ rpId });

    const result = await verifier.verify({
      credentialId: "cred_1",
      clientDataJSON: "invalid json string {",
      authenticatorData: authData,
      signature: new Uint8Array(64),
      credentialPublicKey: coseKey,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.message).toContain("JSON parse error");
    }
  });

  it("fails when credential public key is invalid", async () => {
    const authData = createAuthData({ rpId });
    const clientDataJSON = createClientDataJSON({ challenge, origin });

    const result = await verifier.verify({
      credentialId: "cred_1",
      clientDataJSON,
      authenticatorData: authData,
      signature: new Uint8Array(64),
      credentialPublicKey: "not_a_valid_key",
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.message).toContain("Invalid credential public key");
    }
  });

  it("successfully verifies when credential public key is SPKI DER format", async () => {
    const keyPair = generateTestEcKeyPair();
    const derKey = keyPair.publicKey.export({ format: "der", type: "spki" });
    const derKeyBase64Url = Buffer.from(derKey).toString("base64url");

    const authData = createAuthData({ rpId, signCount: 5 });
    const clientDataJSON = createClientDataJSON({ challenge, origin });
    const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

    const result = await verifier.verify({
      credentialId: "cred_der",
      clientDataJSON,
      authenticatorData: authData,
      signature,
      credentialPublicKey: derKeyBase64Url,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRpId: rpId,
    });

    expect(Result.isOk(result)).toBe(true);
  });
});
