import crypto from "node:crypto";

import { Result, asId } from "@verixa/shared-kernel";
import { describe, beforeEach, expect, it } from "vitest";

import { InMemoryMfaMethodRepository } from "../../infrastructure/fakes/in-memory-mfa-method-repository.js";
import { InMemoryWebAuthnChallengeRepository } from "../../infrastructure/fakes/in-memory-webauthn-challenge-repository.js";
import { InMemoryWebAuthnCredentialRepository } from "../../infrastructure/fakes/in-memory-webauthn-credential-repository.js";
import { WebAuthnAttestationVerifier } from "../../infrastructure/webauthn/attestation-verifier.js";
import { encodeCbor } from "../../infrastructure/webauthn/cbor.js";

import { RegisterWebAuthnCredential } from "./register-webauthn-credential.js";

function createValidAuthData(options: {
  rpId: string;
  flags?: number;
  signCount?: number;
  credentialId?: Uint8Array;
  publicKey?: Uint8Array;
}): Uint8Array {
  const rpIdHash = crypto.createHash("sha256").update(options.rpId).digest();
  const flags = options.flags ?? 0x01 | 0x40; // UP | AT
  const signCount = options.signCount ?? 0;
  const aaguid = new Uint8Array(16).fill(0x55);
  const credentialId = options.credentialId ?? new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);
  const publicKey = options.publicKey ?? new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01]);

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

function createAttestationObject(authData: Uint8Array): string {
  const cbor = encodeCbor({
    fmt: "none",
    attStmt: {},
    authData,
  });
  return Buffer.from(cbor).toString("base64url");
}

function createClientDataJSON(challenge: string, origin: string): string {
  return Buffer.from(
    JSON.stringify({
      type: "webauthn.create",
      challenge,
      origin,
      crossOrigin: false,
    }),
  ).toString("base64url");
}

describe("RegisterWebAuthnCredential", () => {
  const expectedOrigin = "https://verixa.example";
  const expectedRpId = "verixa.example";

  let mfaMethodRepo: InMemoryMfaMethodRepository;
  let credentialRepo: InMemoryWebAuthnCredentialRepository;
  let challengeRepo: InMemoryWebAuthnChallengeRepository;
  let attestationVerifier: WebAuthnAttestationVerifier;
  let useCase: RegisterWebAuthnCredential;

  beforeEach(() => {
    mfaMethodRepo = new InMemoryMfaMethodRepository();
    credentialRepo = new InMemoryWebAuthnCredentialRepository();
    challengeRepo = new InMemoryWebAuthnChallengeRepository();
    attestationVerifier = new WebAuthnAttestationVerifier();

    useCase = new RegisterWebAuthnCredential(
      mfaMethodRepo,
      credentialRepo,
      challengeRepo,
      attestationVerifier,
      {
        expectedOrigin,
        expectedRpId,
        challengeTtlMs: 5 * 60 * 1000,
      },
    );
  });

  describe("issueChallenge", () => {
    it("issues a cryptographically random challenge with TTL", async () => {
      const now = new Date("2026-09-25T12:00:00Z");
      const result = await useCase.issueChallenge({ userId: "user-123" }, now);

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;

      expect(result.value.challenge).toBeDefined();
      expect(result.value.challenge.length).toBeGreaterThan(20);
      expect(result.value.expiresAt.getTime()).toBe(now.getTime() + 5 * 60 * 1000);

      const stored = await challengeRepo.findByChallenge(result.value.challenge);
      expect(stored).toBeDefined();
      expect(stored?.userId).toBe("user-123");
      expect(stored?.used).toBe(false);
    });

    it("rejects when userId is empty", async () => {
      const result = await useCase.issueChallenge({ userId: "" });
      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.message).toContain("User ID is required");
    });
  });

  describe("execute (registration ceremony)", () => {
    const userId = "user-alice";

    it("successfully registers a WebAuthn credential and creates active MfaMethod", async () => {
      const startTime = new Date("2026-09-25T12:00:00Z");
      const challengeResult = await useCase.issueChallenge({ userId }, startTime);
      expect(Result.isOk(challengeResult)).toBe(true);
      if (!Result.isOk(challengeResult)) return;

      const challenge = challengeResult.value.challenge;
      const authData = createValidAuthData({ rpId: expectedRpId });
      const attestationObject = createAttestationObject(authData);
      const clientDataJSON = createClientDataJSON(challenge, expectedOrigin);

      const executeTime = new Date("2026-09-25T12:01:00Z");
      const result = await useCase.execute(
        {
          userId,
          challenge,
          clientDataJSON,
          attestationObject,
          transports: ["internal", "hybrid"],
          deviceName: "MacBook Touch ID",
        },
        executeTime,
      );

      expect(Result.isOk(result)).toBe(true);
      if (!Result.isOk(result)) return;

      // 1. Verifies MfaMethod created as 'active'
      expect(result.value.mfaMethod.type).toBe("webauthn");
      expect(result.value.mfaMethod.status).toBe("active");
      expect(result.value.mfaMethod.userId).toBe(asId(userId));

      // 2. Verifies WebAuthnCredential persisted
      expect(result.value.credential.userId).toBe(asId(userId));
      expect(result.value.credential.mfaMethodId).toBe(result.value.mfaMethod.id);
      expect(result.value.credential.deviceName).toBe("MacBook Touch ID");
      expect(result.value.credential.transports).toEqual(["internal", "hybrid"]);

      // 3. Verifies repository state
      const savedMethod = await mfaMethodRepo.findById(result.value.mfaMethod.id);
      expect(savedMethod).toBeDefined();
      expect(savedMethod?.status).toBe("active");

      const savedCred = await credentialRepo.findByCredentialId(
        result.value.credential.credentialId,
      );
      expect(savedCred).toBeDefined();

      // 4. Verifies challenge is marked as used
      const storedChallenge = await challengeRepo.findByChallenge(challenge);
      expect(storedChallenge?.used).toBe(true);
    });

    it("enforces single-use challenge: rejects reuse of already-consumed challenge", async () => {
      const startTime = new Date("2026-09-25T12:00:00Z");
      const challengeResult = await useCase.issueChallenge({ userId }, startTime);
      if (!Result.isOk(challengeResult)) return;

      const challenge = challengeResult.value.challenge;
      const authData = createValidAuthData({ rpId: expectedRpId });
      const attestationObject = createAttestationObject(authData);
      const clientDataJSON = createClientDataJSON(challenge, expectedOrigin);

      // First run succeeds
      const firstRun = await useCase.execute(
        {
          userId,
          challenge,
          clientDataJSON,
          attestationObject,
        },
        startTime,
      );
      expect(Result.isOk(firstRun)).toBe(true);

      // Second run with same challenge must fail
      const secondRun = await useCase.execute(
        {
          userId,
          challenge,
          clientDataJSON,
          attestationObject,
        },
        startTime,
      );
      expect(Result.isErr(secondRun)).toBe(true);
      if (!Result.isErr(secondRun)) return;
      expect(secondRun.error.message).toContain("already been used");
    });

    it("rejects registration when challenge has expired", async () => {
      const startTime = new Date("2026-09-25T12:00:00Z");
      const challengeResult = await useCase.issueChallenge({ userId }, startTime);
      if (!Result.isOk(challengeResult)) return;

      const challenge = challengeResult.value.challenge;
      const authData = createValidAuthData({ rpId: expectedRpId });
      const attestationObject = createAttestationObject(authData);
      const clientDataJSON = createClientDataJSON(challenge, expectedOrigin);

      // Current time is 10 minutes later (TTL was 5 minutes)
      const expiredTime = new Date("2026-09-25T12:10:00Z");
      const result = await useCase.execute(
        {
          userId,
          challenge,
          clientDataJSON,
          attestationObject,
        },
        expiredTime,
      );

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.message).toContain("expired");
    });

    it("rejects registration with unknown or invalid challenge", async () => {
      const authData = createValidAuthData({ rpId: expectedRpId });
      const attestationObject = createAttestationObject(authData);
      const clientDataJSON = createClientDataJSON("non-existent-challenge", expectedOrigin);

      const result = await useCase.execute({
        userId,
        challenge: "non-existent-challenge",
        clientDataJSON,
        attestationObject,
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.message).toContain("invalid or does not belong");
    });

    it("rejects challenge issued for a different user", async () => {
      const challengeResult = await useCase.issueChallenge({ userId: "bob" });
      if (!Result.isOk(challengeResult)) return;

      const challenge = challengeResult.value.challenge;
      const authData = createValidAuthData({ rpId: expectedRpId });
      const attestationObject = createAttestationObject(authData);
      const clientDataJSON = createClientDataJSON(challenge, expectedOrigin);

      // Alice tries to claim Bob's challenge
      const result = await useCase.execute({
        userId: "alice",
        challenge,
        clientDataJSON,
        attestationObject,
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.message).toContain("invalid or does not belong");
    });

    it("rejects registration when origin does not match expected RP origin", async () => {
      const challengeResult = await useCase.issueChallenge({ userId });
      if (!Result.isOk(challengeResult)) return;

      const challenge = challengeResult.value.challenge;
      const authData = createValidAuthData({ rpId: expectedRpId });
      const attestationObject = createAttestationObject(authData);
      // Origin forged or phishing attempt
      const clientDataJSON = createClientDataJSON(challenge, "https://attacker.site");

      const result = await useCase.execute({
        userId,
        challenge,
        clientDataJSON,
        attestationObject,
      });

      expect(Result.isErr(result)).toBe(true);
      if (!Result.isErr(result)) return;
      expect(result.error.message).toContain("Origin mismatch");
    });

    it("rejects duplicate credential ID registration", async () => {
      const credId = new Uint8Array([99, 99, 99, 99]);

      // Enroll first credential
      const challenge1 = await useCase.issueChallenge({ userId: "user-1" });
      if (!Result.isOk(challenge1)) return;

      const authData1 = createValidAuthData({ rpId: expectedRpId, credentialId: credId });
      const attestation1 = createAttestationObject(authData1);
      const clientData1 = createClientDataJSON(challenge1.value.challenge, expectedOrigin);

      const res1 = await useCase.execute({
        userId: "user-1",
        challenge: challenge1.value.challenge,
        clientDataJSON: clientData1,
        attestationObject: attestation1,
      });
      expect(Result.isOk(res1)).toBe(true);

      // Try enrolling same credential ID for user-2
      const challenge2 = await useCase.issueChallenge({ userId: "user-2" });
      if (!Result.isOk(challenge2)) return;

      const authData2 = createValidAuthData({ rpId: expectedRpId, credentialId: credId });
      const attestation2 = createAttestationObject(authData2);
      const clientData2 = createClientDataJSON(challenge2.value.challenge, expectedOrigin);

      const res2 = await useCase.execute({
        userId: "user-2",
        challenge: challenge2.value.challenge,
        clientDataJSON: clientData2,
        attestationObject: attestation2,
      });

      expect(Result.isErr(res2)).toBe(true);
      if (!Result.isErr(res2)) return;
      expect(res2.error.name).toBe("ConflictError");
      expect(res2.error.message).toContain("already registered");
    });

    it("validates mandatory fields", async () => {
      const res1 = await useCase.execute({
        userId: "",
        challenge: "ch",
        clientDataJSON: "c",
        attestationObject: "a",
      });
      expect(Result.isErr(res1)).toBe(true);

      const res2 = await useCase.execute({
        userId: "u",
        challenge: "",
        clientDataJSON: "c",
        attestationObject: "a",
      });
      expect(Result.isErr(res2)).toBe(true);

      const res3 = await useCase.execute({
        userId: "u",
        challenge: "c",
        clientDataJSON: "",
        attestationObject: "a",
      });
      expect(Result.isErr(res3)).toBe(true);

      const res4 = await useCase.execute({
        userId: "u",
        challenge: "c",
        clientDataJSON: "c",
        attestationObject: "",
      });
      expect(Result.isErr(res4)).toBe(true);
    });
  });
});
