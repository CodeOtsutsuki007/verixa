import crypto from "node:crypto";

import { ConflictError, Result, ValidationError, asId } from "@verixa/shared-kernel";

import { MfaMethod } from "../../domain/entities/mfa-method.js";
import { WebAuthnChallenge } from "../../domain/entities/webauthn-challenge.js";
import { WebAuthnCredential } from "../../domain/entities/webauthn-credential.js";
import type { AttestationVerifier } from "../ports/attestation-verifier.js";
import type { MfaMethodRepository } from "../ports/mfa-method-repository.js";
import type { WebAuthnChallengeRepository } from "../ports/webauthn-challenge-repository.js";
import type { WebAuthnCredentialRepository } from "../ports/webauthn-credential-repository.js";

export interface RegisterWebAuthnCredentialConfig {
  readonly expectedOrigin: string;
  readonly expectedRpId: string;
  readonly challengeTtlMs?: number | undefined;
}

export interface IssueRegistrationChallengeCommand {
  readonly userId: string;
}

export interface IssueRegistrationChallengeResult {
  readonly challenge: string;
  readonly expiresAt: Date;
}

export interface RegisterWebAuthnCredentialCommand {
  readonly userId: string;
  readonly challenge: string;
  readonly clientDataJSON: string | Uint8Array;
  readonly attestationObject: string | Uint8Array;
  readonly transports?: readonly string[] | undefined;
  readonly deviceName?: string | undefined;
}

export interface RegisterWebAuthnCredentialResult {
  readonly mfaMethod: MfaMethod;
  readonly credential: WebAuthnCredential;
}

export type RegisterWebAuthnCredentialError = ValidationError | ConflictError | Error;

/**
 * Orchestrates the WebAuthn registration ceremony:
 * 1. Issues cryptographically random registration challenges bound to the user.
 * 2. Verifies the returned attestation object's signature and origin/RP ID binding.
 * 3. Persists the resulting WebAuthnCredential as an active MfaMethod.
 */
export class RegisterWebAuthnCredential {
  private readonly expectedOrigin: string;
  private readonly expectedRpId: string;
  private readonly challengeTtlMs: number;

  constructor(
    private readonly mfaMethodRepository: MfaMethodRepository,
    private readonly credentialRepository: WebAuthnCredentialRepository,
    private readonly challengeRepository: WebAuthnChallengeRepository,
    private readonly attestationVerifier: AttestationVerifier,
    config: RegisterWebAuthnCredentialConfig,
  ) {
    this.expectedOrigin = config.expectedOrigin;
    this.expectedRpId = config.expectedRpId;
    this.challengeTtlMs = config.challengeTtlMs ?? 5 * 60 * 1000;
  }

  /**
   * Generates and stores a new single-use registration challenge for a user.
   */
  async issueChallenge(
    command: IssueRegistrationChallengeCommand,
    now: Date = new Date(),
  ): Promise<Result<IssueRegistrationChallengeResult, ValidationError>> {
    if (!command.userId || command.userId.trim().length === 0) {
      return Result.err(new ValidationError("User ID is required to issue a challenge."));
    }

    const userId = asId<"UserId">(command.userId);
    const challengeBytes = crypto.randomBytes(32);
    const challengeString = challengeBytes.toString("base64url");

    const challenge = WebAuthnChallenge.create({
      userId,
      challenge: challengeString,
      ceremonyType: "registration",
      ttlMs: this.challengeTtlMs,
      now,
    });

    await this.challengeRepository.save(challenge);

    return Result.ok({
      challenge: challenge.challenge,
      expiresAt: challenge.expiresAt,
    });
  }

  /**
   * Completes the registration ceremony by verifying the attestation and
   * persisting the active MFA method and WebAuthn credential.
   */
  async execute(
    command: RegisterWebAuthnCredentialCommand,
    now: Date = new Date(),
  ): Promise<Result<RegisterWebAuthnCredentialResult, RegisterWebAuthnCredentialError>> {
    // 1. Basic input validation
    if (!command.userId || command.userId.trim().length === 0) {
      return Result.err(new ValidationError("User ID is required."));
    }
    if (!command.challenge || command.challenge.trim().length === 0) {
      return Result.err(new ValidationError("Challenge is required."));
    }
    if (!command.clientDataJSON) {
      return Result.err(new ValidationError("clientDataJSON is required."));
    }
    if (!command.attestationObject) {
      return Result.err(new ValidationError("attestationObject is required."));
    }

    const userId = asId<"UserId">(command.userId);

    // 2. Fetch challenge and verify user binding
    const challenge = await this.challengeRepository.findByChallenge(command.challenge);
    if (!challenge || challenge.userId !== userId || challenge.ceremonyType !== "registration") {
      return Result.err(
        new ValidationError("Registration challenge is invalid or does not belong to this user."),
      );
    }

    // 3. Verify challenge expiry
    if (challenge.isExpired(now)) {
      return Result.err(new ValidationError("Registration challenge has expired."));
    }

    // 4. Verify single-use invariant and consume the challenge
    if (challenge.used) {
      return Result.err(new ValidationError("Registration challenge has already been used."));
    }

    const consumed = await this.challengeRepository.consume(command.challenge);
    if (!consumed) {
      return Result.err(new ValidationError("Registration challenge has already been used."));
    }

    // 5. Verify attestation
    const verificationResult = await this.attestationVerifier.verify({
      clientDataJSON: command.clientDataJSON,
      attestationObject: command.attestationObject,
      expectedChallenge: command.challenge,
      expectedOrigin: this.expectedOrigin,
      expectedRpId: this.expectedRpId,
    });

    if (Result.isErr(verificationResult)) {
      return verificationResult;
    }

    const verified = verificationResult.value;

    // 6. Check for duplicate credential
    const existingCredential = await this.credentialRepository.findByCredentialId(
      verified.credentialId,
    );
    if (existingCredential) {
      return Result.err(
        new ConflictError(
          `WebAuthn credential with ID "${verified.credentialId}" is already registered.`,
        ),
      );
    }

    // 7. Persist active MfaMethod and WebAuthnCredential
    const mfaMethod = MfaMethod.createActive(userId, "webauthn", now);
    await this.mfaMethodRepository.save(mfaMethod);

    const credential = WebAuthnCredential.create({
      credentialId: verified.credentialId,
      userId,
      mfaMethodId: mfaMethod.id,
      publicKey: verified.credentialPublicKey,
      signCounter: verified.signCounter,
      transports: command.transports,
      attestationType: verified.attestationType,
      aaguid: verified.aaguid,
      deviceName: command.deviceName,
      createdAt: now,
    });
    await this.credentialRepository.save(credential);

    return Result.ok({
      mfaMethod,
      credential,
    });
  }
}
