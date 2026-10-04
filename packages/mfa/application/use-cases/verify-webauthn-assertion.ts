import crypto from "node:crypto";

import {
  AccountLockedError,
  Result,
  ValidationError,
  asId,
  type DomainEventPublisher,
} from "@verixa/shared-kernel";

import type { MfaMethod } from "../../domain/entities/mfa-method.js";
import { WebAuthnChallenge } from "../../domain/entities/webauthn-challenge.js";
import type { WebAuthnCredential } from "../../domain/entities/webauthn-credential.js";
import { WebAuthnCloneSuspected } from "../../domain/events/webauthn-clone-suspected.js";
import type { AssertionVerifier } from "../ports/assertion-verifier.js";
import type { MfaMethodRepository } from "../ports/mfa-method-repository.js";
import type { WebAuthnChallengeRepository } from "../ports/webauthn-challenge-repository.js";
import type { WebAuthnCredentialRepository } from "../ports/webauthn-credential-repository.js";

export interface VerifyWebAuthnAssertionConfig {
  readonly expectedOrigin: string;
  readonly expectedRpId: string;
  readonly challengeTtlMs?: number | undefined;
}

export interface IssueAuthenticationChallengeCommand {
  readonly userId: string;
}

export interface IssueAuthenticationChallengeResult {
  readonly challenge: string;
  readonly expiresAt: Date;
}

export interface VerifyWebAuthnAssertionCommand {
  readonly userId: string;
  readonly credentialId: string;
  readonly challenge: string;
  readonly clientDataJSON: string | Uint8Array;
  readonly authenticatorData: string | Uint8Array;
  readonly signature: string | Uint8Array;
  readonly userHandle?: string | Uint8Array | undefined;
}

export interface VerifyWebAuthnAssertionResult {
  readonly credential: WebAuthnCredential;
  readonly mfaMethod: MfaMethod;
}

export type VerifyWebAuthnAssertionError = ValidationError | AccountLockedError | Error;

/**
 * Orchestrates the WebAuthn authentication ceremony:
 * 1. Issues single-use authentication challenges bound to a user.
 * 2. Validates assertion response (clientDataJSON, authenticatorData, signature).
 * 3. Enforces clone detection by verifying that the signature counter increased.
 * 4. Emits `WebAuthnCloneSuspected` domain event on counter rollback.
 * 5. Updates credential lastUsedAt and signCounter.
 */
export class VerifyWebAuthnAssertion {
  private readonly expectedOrigin: string;
  private readonly expectedRpId: string;
  private readonly challengeTtlMs: number;

  constructor(
    private readonly mfaMethodRepository: MfaMethodRepository,
    private readonly credentialRepository: WebAuthnCredentialRepository,
    private readonly challengeRepository: WebAuthnChallengeRepository,
    private readonly assertionVerifier: AssertionVerifier,
    private readonly eventPublisher: DomainEventPublisher,
    config: VerifyWebAuthnAssertionConfig,
  ) {
    this.expectedOrigin = config.expectedOrigin;
    this.expectedRpId = config.expectedRpId;
    this.challengeTtlMs = config.challengeTtlMs ?? 5 * 60 * 1000;
  }

  /**
   * Generates and stores a new single-use authentication challenge for a user.
   */
  async issueChallenge(
    command: IssueAuthenticationChallengeCommand,
    now: Date = new Date(),
  ): Promise<Result<IssueAuthenticationChallengeResult, ValidationError>> {
    if (!command.userId || command.userId.trim().length === 0) {
      return Result.err(new ValidationError("User ID is required to issue a challenge."));
    }

    const userId = asId<"UserId">(command.userId);
    const challengeBytes = crypto.randomBytes(32);
    const challengeString = challengeBytes.toString("base64url");

    const challenge = WebAuthnChallenge.create({
      userId,
      challenge: challengeString,
      ceremonyType: "authentication",
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
   * Verifies the presented WebAuthn assertion, detects clone anomalies,
   * updates the signature counter, and resets failure attempts.
   */
  async execute(
    command: VerifyWebAuthnAssertionCommand,
    now: Date = new Date(),
  ): Promise<Result<VerifyWebAuthnAssertionResult, VerifyWebAuthnAssertionError>> {
    // 1. Basic input validation
    if (!command.userId || command.userId.trim().length === 0) {
      return Result.err(new ValidationError("User ID is required."));
    }
    if (!command.credentialId || command.credentialId.trim().length === 0) {
      return Result.err(new ValidationError("Credential ID is required."));
    }
    if (!command.challenge || command.challenge.trim().length === 0) {
      return Result.err(new ValidationError("Challenge is required."));
    }
    if (!command.clientDataJSON) {
      return Result.err(new ValidationError("clientDataJSON is required."));
    }
    if (!command.authenticatorData) {
      return Result.err(new ValidationError("authenticatorData is required."));
    }
    if (!command.signature) {
      return Result.err(new ValidationError("signature is required."));
    }

    const userId = asId<"UserId">(command.userId);

    // 2. Fetch challenge and verify user binding
    const challenge = await this.challengeRepository.findByChallenge(command.challenge);
    if (!challenge || challenge.userId !== userId || challenge.ceremonyType !== "authentication") {
      return Result.err(
        new ValidationError("Authentication challenge is invalid or does not belong to this user."),
      );
    }

    // 3. Verify challenge expiry
    if (challenge.isExpired(now)) {
      return Result.err(new ValidationError("Authentication challenge has expired."));
    }

    // 4. Verify single-use invariant and consume challenge
    if (challenge.used) {
      return Result.err(new ValidationError("Authentication challenge has already been used."));
    }

    const consumed = await this.challengeRepository.consume(command.challenge);
    if (!consumed) {
      return Result.err(
        new ValidationError("Authentication challenge could not be consumed (concurrent use)."),
      );
    }

    // 5. Fetch credential
    const credential = await this.credentialRepository.findByCredentialId(command.credentialId);
    if (!credential || credential.userId !== userId) {
      return Result.err(new ValidationError("WebAuthn credential not found."));
    }

    // 6. Fetch associated MFA method
    const mfaMethod = await this.mfaMethodRepository.findById(credential.mfaMethodId);
    if (!mfaMethod || mfaMethod.status !== "active") {
      return Result.err(new ValidationError("WebAuthn MFA method is not active."));
    }

    if (mfaMethod.isLockedAt(now)) {
      return Result.err(new AccountLockedError("MFA method is temporarily locked."));
    }

    // 7. Verify assertion signature and binding via verifier
    const verifyResult = await this.assertionVerifier.verify({
      credentialId: command.credentialId,
      clientDataJSON: command.clientDataJSON,
      authenticatorData: command.authenticatorData,
      signature: command.signature,
      credentialPublicKey: credential.publicKey,
      expectedChallenge: command.challenge,
      expectedOrigin: this.expectedOrigin,
      expectedRpId: this.expectedRpId,
      userHandle: command.userHandle,
    });

    if (Result.isErr(verifyResult)) {
      const failedMethod = mfaMethod.recordFailedAttempt(now);
      await this.mfaMethodRepository.save(failedMethod);
      return Result.err(verifyResult.error);
    }

    const verifiedAssertion = verifyResult.value;

    // 8. Clone detection: counter must increase if counter tracking is active
    if (credential.signCounter > 0 && verifiedAssertion.signCounter <= credential.signCounter) {
      const cloneEvent = new WebAuthnCloneSuspected({
        credentialId: credential.credentialId,
        userId: command.userId,
        previousCounter: credential.signCounter,
        presentedCounter: verifiedAssertion.signCounter,
      });

      await this.eventPublisher.publish(cloneEvent);

      const failedMethod = mfaMethod.recordFailedAttempt(now);
      await this.mfaMethodRepository.save(failedMethod);

      return Result.err(
        new ValidationError("Suspected credential cloning: signature counter did not increase."),
      );
    }

    // 9. Success: advance signCounter, set lastUsedAt, reset failure attempts via recordUse
    const updatedCredential = credential.updateSignCounter(verifiedAssertion.signCounter, now);
    await this.credentialRepository.save(updatedCredential);

    const activeMethod = mfaMethod.recordUse(now);
    await this.mfaMethodRepository.save(activeMethod);

    return Result.ok({
      credential: updatedCredential,
      mfaMethod: activeMethod,
    });
  }
}
