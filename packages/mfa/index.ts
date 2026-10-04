// Curated public surface of @verixa/mfa. Nothing outside this package
// should import from a deep path (`@verixa/mfa/domain/...`,
// `@verixa/mfa/application/...`) — see docs/guides/domain-modeling.md
// ("Package encapsulation") for why, and eslint.config.mjs's
// `no-restricted-imports` rule, which enforces it.

// Domain: entities & value objects
export type { MfaMethodId, MfaMethodStatus, MfaMethodProps } from "./domain/entities/mfa-method.js";
export { MfaMethod } from "./domain/entities/mfa-method.js";

export type {
  WebAuthnCredentialId,
  WebAuthnCredentialProps,
} from "./domain/entities/webauthn-credential.js";
export { WebAuthnCredential } from "./domain/entities/webauthn-credential.js";

export type {
  WebAuthnChallengeId,
  WebAuthnCeremonyType,
  WebAuthnChallengeProps,
} from "./domain/entities/webauthn-challenge.js";
export { WebAuthnChallenge } from "./domain/entities/webauthn-challenge.js";

export type { MfaMethodType } from "./domain/value-objects/mfa-method-type.js";

// Domain: events
export type { WebAuthnCloneSuspectedProps } from "./domain/events/webauthn-clone-suspected.js";
export { WebAuthnCloneSuspected } from "./domain/events/webauthn-clone-suspected.js";

// Application: ports
export type { MfaMethodRepository } from "./application/ports/mfa-method-repository.js";
export type { WebAuthnCredentialRepository } from "./application/ports/webauthn-credential-repository.js";
export type { WebAuthnChallengeRepository } from "./application/ports/webauthn-challenge-repository.js";
export type {
  AttestationVerifier,
  VerifiedAttestation,
  VerifyAttestationOptions,
} from "./application/ports/attestation-verifier.js";
export type {
  AssertionVerifier,
  VerifiedAssertion,
  VerifyAssertionOptions,
} from "./application/ports/assertion-verifier.js";

// Application: use cases
export type {
  RegisterWebAuthnCredentialConfig,
  IssueRegistrationChallengeCommand,
  IssueRegistrationChallengeResult,
  RegisterWebAuthnCredentialCommand,
  RegisterWebAuthnCredentialResult,
  RegisterWebAuthnCredentialError,
} from "./application/use-cases/register-webauthn-credential.js";
export { RegisterWebAuthnCredential } from "./application/use-cases/register-webauthn-credential.js";

export type {
  VerifyWebAuthnAssertionConfig,
  IssueAuthenticationChallengeCommand,
  IssueAuthenticationChallengeResult,
  VerifyWebAuthnAssertionCommand,
  VerifyWebAuthnAssertionResult,
  VerifyWebAuthnAssertionError,
} from "./application/use-cases/verify-webauthn-assertion.js";
export { VerifyWebAuthnAssertion } from "./application/use-cases/verify-webauthn-assertion.js";

// Infrastructure: adapters & fakes
export { WebAuthnAttestationVerifier } from "./infrastructure/webauthn/attestation-verifier.js";
export { WebAuthnAssertionVerifier } from "./infrastructure/webauthn/assertion-verifier.js";
export { InMemoryMfaMethodRepository } from "./infrastructure/fakes/in-memory-mfa-method-repository.js";
export { InMemoryWebAuthnCredentialRepository } from "./infrastructure/fakes/in-memory-webauthn-credential-repository.js";
export { InMemoryWebAuthnChallengeRepository } from "./infrastructure/fakes/in-memory-webauthn-challenge-repository.js";
export { InMemoryDomainEventPublisher } from "./infrastructure/fakes/in-memory-domain-event-publisher.js";
export * from "./domain/value-objects/mfa-method-type.js";
export * from "./domain/entities/mfa-method.js";
export * from "./domain/entities/webauthn-credential.js";
export * from "./domain/entities/webauthn-challenge.js";
export * from "./domain/events/webauthn-clone-suspected.js";
export * from "./application/ports/mfa-method-repository.js";
export * from "./application/ports/webauthn-credential-repository.js";
export * from "./application/ports/webauthn-challenge-repository.js";
export * from "./application/ports/attestation-verifier.js";
export * from "./application/use-cases/register-webauthn-credential.js";
export * from "./infrastructure/webauthn/attestation-verifier.js";
export * from "./infrastructure/fakes/in-memory-mfa-method-repository.js";
export * from "./infrastructure/fakes/in-memory-webauthn-credential-repository.js";
export * from "./infrastructure/fakes/in-memory-webauthn-challenge-repository.js";
export * from "./application/ports/assertion-verifier.js";
export * from "./application/use-cases/register-webauthn-credential.js";
export * from "./application/use-cases/verify-webauthn-assertion.js";
export * from "./infrastructure/webauthn/attestation-verifier.js";
export * from "./infrastructure/webauthn/assertion-verifier.js";
export * from "./infrastructure/fakes/in-memory-mfa-method-repository.js";
export * from "./infrastructure/fakes/in-memory-webauthn-credential-repository.js";
export * from "./infrastructure/fakes/in-memory-webauthn-challenge-repository.js";
export * from "./infrastructure/fakes/in-memory-domain-event-publisher.js";
export { MfaMethod, type MfaMethodId, type MfaMethodStatus } from "./domain/entities/mfa-method.js";
export { MfaMethodType, type MfaMethodTypeValue } from "./domain/value-objects/mfa-method-type.js";
// Curated public surface of @verixa/mfa. Only this entrypoint may be imported
// from outside the package (see docs/guides/domain-modeling.md).
//
// Reconstructed after a merge left two versions of this file concatenated:
// one using `export *` wildcards, one curated. The curated form is kept,
// because a wildcard re-export makes the public surface whatever the files
// happen to contain — which is how a package's internals become someone
// else's dependency by accident.

// Domain: entities
export {
  MfaMethod,
  type MfaMethodId,
  type MfaMethodProps,
  type MfaMethodStatus,
  type MfaMethodType,
  type UserId,
} from "./domain/entities/mfa-method.js";

// Domain: value objects
export { TotpSecret } from "./domain/value-objects/totp-secret.js";
export { StepUpAssertion } from "./domain/value-objects/step-up-assertion.js";

// Domain: services
export type { TotpAlgorithm, TotpSecretLike } from "./domain/services/totp-algorithm.js";
export { Rfc6238TotpAlgorithm } from "./domain/services/rfc-totp-algorithm.js";
export {
  BackupCodeSet,
  type BackupCodeGenerationResult,
} from "./domain/services/backup-code-set.js";
export {
  MfaEnforcementPolicy,
  type MfaEnforcementDecision,
  type MfaEnforcementLevel,
  type MfaEnforcementOverride,
  type MfaEnforcementPolicyInput,
} from "./domain/services/mfa-enforcement-policy.js";

// Application: ports
export type { MfaMethodRepository } from "./application/ports/mfa-method-repository.js";
export type { AuditLogger } from "./application/ports/audit-logger.js";
export type { StepUpAssertionStore } from "./application/ports/step-up-assertion-store.js";
export type { SessionRevoker } from "./application/ports/session-revoker.js";
export type { MfaRecoveryAuthorizer } from "./application/ports/mfa-recovery-authorizer.js";

// Application: use cases
export {
  EnrollTotp,
  type EnrollTotpCommand,
  type EnrollTotpResult,
} from "./application/use-cases/enroll-totp.js";
export {
  ConfirmTotpEnrollment,
  type ConfirmTotpEnrollmentCommand,
  type ConfirmTotpEnrollmentError,
} from "./application/use-cases/confirm-totp-enrollment.js";
export {
  VerifyTotpChallenge,
  type VerifyTotpChallengeCommand,
  type VerifyTotpChallengeError,
} from "./application/use-cases/verify-totp-challenge.js";
export {
  GenerateBackupCodes,
  type GenerateBackupCodesCommand,
  type GenerateBackupCodesResult,
} from "./application/use-cases/generate-backup-codes.js";
export {
  ConsumeBackupCode,
  type ConsumeBackupCodeCommand,
  type ConsumeBackupCodeOutcome,
  type ConsumeBackupCodeResult,
} from "./application/use-cases/consume-backup-code.js";
export {
  StepUpAuthentication,
  type StepUpAuthenticationCommand,
  type StepUpAuthenticationResult,
  type StepUpVerificationMethod,
} from "./application/use-cases/step-up-authentication.js";
export {
  RecoverMfaAccess,
  type RecoverMfaAccessCommand,
} from "./application/use-cases/recover-mfa-access.js";

// Infrastructure: persistence adapter
export { PrismaMfaMethodRepository } from "./infrastructure/persistence/prisma-mfa-method-repository.js";

// Infrastructure: testing fakes
export { InMemoryMfaMethodRepository } from "./infrastructure/testing/in-memory-mfa-method-repository.js";
