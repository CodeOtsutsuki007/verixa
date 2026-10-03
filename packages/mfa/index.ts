// Curated public surface of @verixa/mfa. Only this entrypoint may be imported
// from outside the package (see docs/guides/domain-modeling.md).

// Domain: entities and types
export {
  MfaMethod,
  type MfaMethodId,
  type MfaMethodProps,
  type MfaMethodStatus,
  type MfaMethodType,
  type UserId,
} from "./domain/entities/mfa-method.js";

// Domain: value objects and services
export { TotpSecret } from "./domain/value-objects/totp-secret.js";
export { TotpAlgorithm } from "./domain/services/totp-algorithm.js";
export * from "./domain/entities/mfa-method.js";
export * from "./application/ports/mfa-method-repository.js";
export * from "./infrastructure/persistence/prisma-mfa-method-repository.js";
export * from "./domain/services/backup-code-set.js";
export * from "./application/use-cases/generate-backup-codes.js";
export * from "./application/ports/audit-logger.js";
export * from "./application/use-cases/consume-backup-code.js";
export { RecoverMfaAccess, type RecoverMfaAccessCommand, type RecoverMfaAccessResult, type RecoverMfaAccessError } from "./application/use-cases/recover-mfa-access.js";
export type { SessionRevoker } from "./application/ports/session-revoker.js";
export {
  MfaEnforcementPolicy,
  type MfaEnforcementLevel,
  type MfaEnforcementConfig,
  type MfaEnforcementContext,
  type ResolvedMfaPolicy,
} from "./domain/services/mfa-enforcement-policy.js";
export { StepUpAssertion } from "./domain/value-objects/step-up-assertion.js";
export type { TotpAlgorithm, TotpSecretLike } from "./domain/services/totp-algorithm.js";
export { Rfc6238TotpAlgorithm } from "./domain/services/rfc-totp-algorithm.js";
export { BackupCodeSet, type BackupCodeGenerationResult } from "./domain/services/backup-code-set.js";
export {
  MfaEnforcementPolicy,
  type MfaEnforcementDecision,
  type MfaEnforcementLevel,
  type MfaEnforcementPolicyInput,
} from "./domain/services/mfa-enforcement-policy.js";

// Application: ports
export type { MfaMethodRepository } from "./application/ports/mfa-method-repository.js";
export type { AuditLogger } from "./application/ports/audit-logger.js";
export type { StepUpAssertionStore } from "./application/ports/step-up-assertion-store.js";
export type { SessionRevoker } from "./application/ports/session-revoker.js";
export type { MfaRecoveryAuthorizer } from "./application/ports/mfa-recovery-authorizer.js";

// Application: use cases
export { EnrollTotp, type EnrollTotpCommand, type EnrollTotpResult } from "./application/use-cases/enroll-totp.js";
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
