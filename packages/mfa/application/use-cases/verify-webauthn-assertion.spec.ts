import crypto from "node:crypto";

import { Result, asId } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { MfaMethod } from "../../domain/entities/mfa-method.js";
import { WebAuthnChallenge } from "../../domain/entities/webauthn-challenge.js";
import { WebAuthnCredential } from "../../domain/entities/webauthn-credential.js";
import { WebAuthnCloneSuspected } from "../../domain/events/webauthn-clone-suspected.js";
import { InMemoryDomainEventPublisher } from "../../infrastructure/fakes/in-memory-domain-event-publisher.js";
import { InMemoryMfaMethodRepository } from "../../infrastructure/fakes/in-memory-mfa-method-repository.js";
import { InMemoryWebAuthnChallengeRepository } from "../../infrastructure/fakes/in-memory-webauthn-challenge-repository.js";
import { InMemoryWebAuthnCredentialRepository } from "../../infrastructure/fakes/in-memory-webauthn-credential-repository.js";
import { WebAuthnAssertionVerifier } from "../../infrastructure/webauthn/assertion-verifier.js";
import { encodeCbor } from "../../infrastructure/webauthn/cbor.js";

import { VerifyWebAuthnAssertion } from "./verify-webauthn-assertion.js";

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

function createClientDataJSON(challenge: string, origin: string): string {
  return JSON.stringify({
    type: "webauthn.get",
    challenge,
    origin,
    crossOrigin: false,
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

describe("VerifyWebAuthnAssertion use case", () => {
  const expectedOrigin = "https://verixa.example";
  const expectedRpId = "verixa.example";

  let mfaMethodRepo: InMemoryMfaMethodRepository;
  let credentialRepo: InMemoryWebAuthnCredentialRepository;
  let challengeRepo: InMemoryWebAuthnChallengeRepository;
  let assertionVerifier: WebAuthnAssertionVerifier;
  let eventPublisher: InMemoryDomainEventPublisher;
  let useCase: VerifyWebAuthnAssertion;

  const userId = "user_test_456";
  const rawUserId = asId<"UserId">(userId);

  beforeEach(() => {
    mfaMethodRepo = new InMemoryMfaMethodRepository();
    credentialRepo = new InMemoryWebAuthnCredentialRepository();
    challengeRepo = new InMemoryWebAuthnChallengeRepository();
    assertionVerifier = new WebAuthnAssertionVerifier();
    eventPublisher = new InMemoryDomainEventPublisher();

    useCase = new VerifyWebAuthnAssertion(
      mfaMethodRepo,
      credentialRepo,
      challengeRepo,
      assertionVerifier,
      eventPublisher,
      {
        expectedOrigin,
        expectedRpId,
        challengeTtlMs: 5 * 60 * 1000,
      },
    );
  });

  describe("issueChallenge", () => {
    it("generates and persists an authentication challenge", async () => {
      const result = await useCase.issueChallenge({ userId });

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.challenge).toBeDefined();
        expect(result.value.expiresAt.getTime()).toBeGreaterThan(Date.now());

        const saved = await challengeRepo.findByChallenge(result.value.challenge);
        expect(saved).not.toBeNull();
        expect(saved?.userId).toBe(rawUserId);
        expect(saved?.ceremonyType).toBe("authentication");
      }
    });

    it("rejects when userId is empty", async () => {
      const result = await useCase.issueChallenge({ userId: "" });
      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.message).toContain("User ID is required");
      }
    });
  });

  describe("execute", () => {
    it("successfully verifies an assertion with increased counter and updates credential", async () => {
      const keyPair = generateTestEcKeyPair();
      const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");

      const mfaMethod = MfaMethod.createActive(rawUserId, "webauthn");
      await mfaMethodRepo.save(mfaMethod);

      const credential = WebAuthnCredential.create({
        credentialId: "cred_auth_1",
        userId: rawUserId,
        mfaMethodId: mfaMethod.id,
        publicKey: coseKey,
        signCounter: 10,
        attestationType: "none",
      });
      await credentialRepo.save(credential);

      const challengeRes = await useCase.issueChallenge({ userId });
      expect(Result.isOk(challengeRes)).toBe(true);
      const challengeStr = (challengeRes as { value: { challenge: string } }).value.challenge;

      const authData = createAuthData({ rpId: expectedRpId, signCount: 15 }); // increased counter: 15 > 10
      const clientDataJSON = createClientDataJSON(challengeStr, expectedOrigin);
      const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

      const executeResult = await useCase.execute({
        userId,
        credentialId: "cred_auth_1",
        challenge: challengeStr,
        clientDataJSON,
        authenticatorData: authData,
        signature,
      });

      expect(Result.isOk(executeResult)).toBe(true);
      if (Result.isOk(executeResult)) {
        expect(executeResult.value.credential.signCounter).toBe(15);
        expect(executeResult.value.credential.lastUsedAt).toBeDefined();
        expect(executeResult.value.mfaMethod.failedAttempts).toBe(0);

        // Verify challenge was consumed
        const storedChallenge = await challengeRepo.findByChallenge(challengeStr);
        expect(storedChallenge?.used).toBe(true);
      }
    });

    it("detects clone when counter is non-increasing (stale counter) and emits security event", async () => {
      const keyPair = generateTestEcKeyPair();
      const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");

      const mfaMethod = MfaMethod.createActive(rawUserId, "webauthn");
      await mfaMethodRepo.save(mfaMethod);

      const credential = WebAuthnCredential.create({
        credentialId: "cred_clone_test",
        userId: rawUserId,
        mfaMethodId: mfaMethod.id,
        publicKey: coseKey,
        signCounter: 20, // stored counter is 20
        attestationType: "none",
      });
      await credentialRepo.save(credential);

      const challengeRes = await useCase.issueChallenge({ userId });
      const challengeStr = (challengeRes as { value: { challenge: string } }).value.challenge;

      // Authenticator presents counter 20 (not increased)
      const authData = createAuthData({ rpId: expectedRpId, signCount: 20 });
      const clientDataJSON = createClientDataJSON(challengeStr, expectedOrigin);
      const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

      const executeResult = await useCase.execute({
        userId,
        credentialId: "cred_clone_test",
        challenge: challengeStr,
        clientDataJSON,
        authenticatorData: authData,
        signature,
      });

      expect(Result.isErr(executeResult)).toBe(true);
      if (Result.isErr(executeResult)) {
        expect(executeResult.error.message).toContain("Suspected credential cloning");
      }

      // Check domain event was published
      expect(eventPublisher.publishedEvents.length).toBe(1);
      const event = eventPublisher.publishedEvents[0];
      expect(event).toBeInstanceOf(WebAuthnCloneSuspected);
      if (event instanceof WebAuthnCloneSuspected) {
        expect(event.credentialId).toBe("cred_clone_test");
        expect(event.userId).toBe(userId);
        expect(event.previousCounter).toBe(20);
        expect(event.presentedCounter).toBe(20);
      }

      // MFA method failedAttempts should have been incremented
      const updatedMethod = await mfaMethodRepo.findById(mfaMethod.id);
      expect(updatedMethod?.failedAttempts).toBe(1);
    });

    it("rejects expired authentication challenge", async () => {
      const keyPair = generateTestEcKeyPair();
      const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");

      const mfaMethod = MfaMethod.createActive(rawUserId, "webauthn");
      await mfaMethodRepo.save(mfaMethod);

      const credential = WebAuthnCredential.create({
        credentialId: "cred_exp",
        userId: rawUserId,
        mfaMethodId: mfaMethod.id,
        publicKey: coseKey,
        attestationType: "none",
      });
      await credentialRepo.save(credential);

      const now = new Date("2026-09-25T12:00:00Z");
      const expiredChallenge = WebAuthnChallenge.create({
        userId: rawUserId,
        challenge: "expired-auth-chal",
        ceremonyType: "authentication",
        ttlMs: 60 * 1000,
        now,
      });
      await challengeRepo.save(expiredChallenge);

      const authData = createAuthData({ rpId: expectedRpId, signCount: 1 });
      const clientDataJSON = createClientDataJSON("expired-auth-chal", expectedOrigin);
      const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

      const executeResult = await useCase.execute(
        {
          userId,
          credentialId: "cred_exp",
          challenge: "expired-auth-chal",
          clientDataJSON,
          authenticatorData: authData,
          signature,
        },
        new Date("2026-09-25T12:05:00Z"), // 5 minutes later
      );

      expect(Result.isErr(executeResult)).toBe(true);
      if (Result.isErr(executeResult)) {
        expect(executeResult.error.message).toContain("challenge has expired");
      }
    });

    it("rejects challenge that has already been consumed (single-use)", async () => {
      const keyPair = generateTestEcKeyPair();
      const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");

      const mfaMethod = MfaMethod.createActive(rawUserId, "webauthn");
      await mfaMethodRepo.save(mfaMethod);

      const credential = WebAuthnCredential.create({
        credentialId: "cred_reuse",
        userId: rawUserId,
        mfaMethodId: mfaMethod.id,
        publicKey: coseKey,
        signCounter: 1,
        attestationType: "none",
      });
      await credentialRepo.save(credential);

      const challengeRes = await useCase.issueChallenge({ userId });
      const challengeStr = (challengeRes as { value: { challenge: string } }).value.challenge;

      // Consume the challenge manually
      await challengeRepo.consume(challengeStr);

      const authData = createAuthData({ rpId: expectedRpId, signCount: 2 });
      const clientDataJSON = createClientDataJSON(challengeStr, expectedOrigin);
      const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

      const executeResult = await useCase.execute({
        userId,
        credentialId: "cred_reuse",
        challenge: challengeStr,
        clientDataJSON,
        authenticatorData: authData,
        signature,
      });

      expect(Result.isErr(executeResult)).toBe(true);
      if (Result.isErr(executeResult)) {
        expect(executeResult.error.message).toContain("already been used");
      }
    });

    it("rejects when credential does not belong to the user", async () => {
      const keyPair = generateTestEcKeyPair();
      const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");

      const otherUserId = asId<"UserId">("other_user");
      const mfaMethod = MfaMethod.createActive(otherUserId, "webauthn");
      await mfaMethodRepo.save(mfaMethod);

      const credential = WebAuthnCredential.create({
        credentialId: "cred_other_user",
        userId: otherUserId,
        mfaMethodId: mfaMethod.id,
        publicKey: coseKey,
        attestationType: "none",
      });
      await credentialRepo.save(credential);

      const challengeRes = await useCase.issueChallenge({ userId });
      const challengeStr = (challengeRes as { value: { challenge: string } }).value.challenge;

      const authData = createAuthData({ rpId: expectedRpId, signCount: 2 });
      const clientDataJSON = createClientDataJSON(challengeStr, expectedOrigin);
      const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

      const executeResult = await useCase.execute({
        userId, // user_test_456, but credential belongs to other_user
        credentialId: "cred_other_user",
        challenge: challengeStr,
        clientDataJSON,
        authenticatorData: authData,
        signature,
      });

      expect(Result.isErr(executeResult)).toBe(true);
      if (Result.isErr(executeResult)) {
        expect(executeResult.error.message).toContain("WebAuthn credential not found");
      }
    });

    it("rejects when MFA method is locked", async () => {
      const keyPair = generateTestEcKeyPair();
      const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");

      let mfaMethod = MfaMethod.createActive(rawUserId, "webauthn");
      // Simulate 5 failed attempts to trigger lock
      const now = new Date();
      for (let i = 0; i < 5; i++) {
        mfaMethod = mfaMethod.recordFailedAttempt(now);
      }
      await mfaMethodRepo.save(mfaMethod);

      const credential = WebAuthnCredential.create({
        credentialId: "cred_locked",
        userId: rawUserId,
        mfaMethodId: mfaMethod.id,
        publicKey: coseKey,
        attestationType: "none",
      });
      await credentialRepo.save(credential);

      const challengeRes = await useCase.issueChallenge({ userId });
      const challengeStr = (challengeRes as { value: { challenge: string } }).value.challenge;

      const authData = createAuthData({ rpId: expectedRpId, signCount: 2 });
      const clientDataJSON = createClientDataJSON(challengeStr, expectedOrigin);
      const signature = signAssertion(authData, clientDataJSON, keyPair.privateKey);

      const executeResult = await useCase.execute({
        userId,
        credentialId: "cred_locked",
        challenge: challengeStr,
        clientDataJSON,
        authenticatorData: authData,
        signature,
      });

      expect(Result.isErr(executeResult)).toBe(true);
      if (Result.isErr(executeResult)) {
        expect(executeResult.error.message).toContain("MFA method is temporarily locked");
      }
    });

    it("rejects when required command fields are missing", async () => {
      const baseCmd = {
        userId: "u1",
        credentialId: "c1",
        challenge: "ch1",
        clientDataJSON: "{}",
        authenticatorData: new Uint8Array(37),
        signature: new Uint8Array(64),
      };

      const res1 = await useCase.execute({ ...baseCmd, userId: "" });
      expect(Result.isErr(res1)).toBe(true);

      const res2 = await useCase.execute({ ...baseCmd, credentialId: "" });
      expect(Result.isErr(res2)).toBe(true);

      const res3 = await useCase.execute({ ...baseCmd, challenge: "" });
      expect(Result.isErr(res3)).toBe(true);

      const res4 = await useCase.execute({ ...baseCmd, clientDataJSON: "" });
      expect(Result.isErr(res4)).toBe(true);

      const res5 = await useCase.execute({ ...baseCmd, authenticatorData: "" });
      expect(Result.isErr(res5)).toBe(true);

      const res6 = await useCase.execute({ ...baseCmd, signature: "" });
      expect(Result.isErr(res6)).toBe(true);
    });

    it("rejects when challenge has registration ceremonyType", async () => {
      const regChallenge = WebAuthnChallenge.create({
        userId: rawUserId,
        challenge: "reg-challenge-not-auth",
        ceremonyType: "registration",
        ttlMs: 5 * 60 * 1000,
      });
      await challengeRepo.save(regChallenge);

      const res = await useCase.execute({
        userId,
        credentialId: "cred_1",
        challenge: "reg-challenge-not-auth",
        clientDataJSON: "{}",
        authenticatorData: new Uint8Array(37),
        signature: new Uint8Array(64),
      });

      expect(Result.isErr(res)).toBe(true);
      if (Result.isErr(res)) {
        expect(res.error.message).toContain("Authentication challenge is invalid");
      }
    });

    it("rejects when associated MFA method is not active", async () => {
      const keyPair = generateTestEcKeyPair();
      const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");

      const pendingMethod = MfaMethod.createPending(rawUserId, "webauthn");
      await mfaMethodRepo.save(pendingMethod);

      const credential = WebAuthnCredential.create({
        credentialId: "cred_pending",
        userId: rawUserId,
        mfaMethodId: pendingMethod.id,
        publicKey: coseKey,
        attestationType: "none",
      });
      await credentialRepo.save(credential);

      const challengeRes = await useCase.issueChallenge({ userId });
      const challengeStr = (challengeRes as { value: { challenge: string } }).value.challenge;

      const res = await useCase.execute({
        userId,
        credentialId: "cred_pending",
        challenge: challengeStr,
        clientDataJSON: "{}",
        authenticatorData: new Uint8Array(37),
        signature: new Uint8Array(64),
      });

      expect(Result.isErr(res)).toBe(true);
      if (Result.isErr(res)) {
        expect(res.error.message).toContain("WebAuthn MFA method is not active");
      }
    });

    it("records failure when assertion verification fails", async () => {
      const keyPair = generateTestEcKeyPair();
      const coseKey = Buffer.from(coseKeyFromEcPublicKey(keyPair.publicKey)).toString("base64url");

      const mfaMethod = MfaMethod.createActive(rawUserId, "webauthn");
      await mfaMethodRepo.save(mfaMethod);

      const credential = WebAuthnCredential.create({
        credentialId: "cred_bad_sig",
        userId: rawUserId,
        mfaMethodId: mfaMethod.id,
        publicKey: coseKey,
        attestationType: "none",
      });
      await credentialRepo.save(credential);

      const challengeRes = await useCase.issueChallenge({ userId });
      const challengeStr = (challengeRes as { value: { challenge: string } }).value.challenge;

      const authData = createAuthData({ rpId: expectedRpId, signCount: 1 });
      const clientDataJSON = createClientDataJSON(challengeStr, expectedOrigin);

      const res = await useCase.execute({
        userId,
        credentialId: "cred_bad_sig",
        challenge: challengeStr,
        clientDataJSON,
        authenticatorData: authData,
        signature: new Uint8Array(64).fill(0xff), // bad signature
      });

      expect(Result.isErr(res)).toBe(true);
      const updatedMethod = await mfaMethodRepo.findById(mfaMethod.id);
      expect(updatedMethod?.failedAttempts).toBe(1);
    });
  });
});
