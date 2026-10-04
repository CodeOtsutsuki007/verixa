// Curated public surface of @verixa/credentials. Deep imports are blocked by
// the boundary rule in eslint.config.mjs — see docs/guides/domain-modeling.md.

// Domain
export {
  EmailVerificationToken,
  type EmailVerificationTokenId,
  type EmailVerificationUserId,
  type IssuedEmailVerificationToken,
} from "./domain/entities/email-verification-token.js";
export {
  type IssuedPasswordResetToken,
  PasswordResetToken,
  type PasswordResetTokenId,
  type PasswordResetUserId,
} from "./domain/entities/password-reset-token.js";
export {
  generateToken,
  hashToken,
  tokenMatchesDigest,
} from "./domain/value-objects/token-digest.js";
export {
  Credential,
  type CredentialId,
  type CredentialUserId,
} from "./domain/entities/credential.js";
export {
  DEFAULT_LOCKOUT_POLICY,
  lockDurationMs,
  type LockoutPolicy,
} from "./domain/value-objects/lockout-policy.js";
export {
  type BreachedPasswordChecker,
  DEFAULT_PASSWORD_POLICY,
  type PasswordPolicy,
  RawPassword,
} from "./domain/value-objects/raw-password.js";
export { PasswordChanged } from "./domain/events/password-changed.js";

// Application: ports
export {
  type CredentialNotifier,
  NullCredentialNotifier,
} from "./application/ports/credential-notifier.js";
export type { CredentialRepository } from "./application/ports/credential-repository.js";
export { NoSessionsRevoker, type SessionRevoker } from "./application/ports/session-revoker.js";
export type {
  EmailVerificationTokenRepository,
  PasswordResetTokenRepository,
} from "./application/ports/verification-token-repository.js";
export type {
  CredentialsRepositories,
  CredentialsUnitOfWork,
} from "./application/ports/credentials-unit-of-work.js";
export type { PasswordHasher } from "./application/ports/password-hasher.js";

// Application: use cases
export {
  ChangePassword,
  type ChangePasswordCommand,
  type ChangePasswordResult,
} from "./application/use-cases/change-password.js";
export {
  ConfirmEmailVerification,
  type ConfirmEmailVerificationCommand,
  type ConfirmEmailVerificationResult,
} from "./application/use-cases/confirm-email-verification.js";
export {
  ConfirmPasswordReset,
  type ConfirmPasswordResetCommand,
  type ConfirmPasswordResetResult,
} from "./application/use-cases/confirm-password-reset.js";
export {
  RequestEmailVerification,
  type RequestEmailVerificationCommand,
  type RequestEmailVerificationResult,
} from "./application/use-cases/request-email-verification.js";
export {
  RequestPasswordReset,
  type RequestPasswordResetCommand,
  type RequestPasswordResetResult,
} from "./application/use-cases/request-password-reset.js";
export {
  AuthenticateWithPassword,
  type AuthenticateWithPasswordCommand,
  type AuthenticateWithPasswordError,
  type AuthenticateWithPasswordResult,
} from "./application/use-cases/authenticate-with-password.js";
export {
  RegisterUserWithPassword,
  type RegisterUserWithPasswordCommand,
  type RegisterUserWithPasswordError,
  type RegisterUserWithPasswordResult,
} from "./application/use-cases/register-user-with-password.js";
export { HandleUserDeleted } from "./application/use-cases/handle-user-deleted.js";

// Infrastructure
export {
  Argon2PasswordHasher,
  type Argon2Parameters,
  DEFAULT_ARGON2_PARAMETERS,
} from "./infrastructure/argon2-password-hasher.js";
export {
  CredentialMapper,
  PrismaCredentialRepository,
} from "./infrastructure/persistence/prisma-credential-repository.js";
export { PrismaCredentialsUnitOfWork } from "./infrastructure/persistence/prisma-credentials-unit-of-work.js";
export {
  EmailVerificationTokenMapper,
  PasswordResetTokenMapper,
  PrismaEmailVerificationTokenRepository,
  PrismaPasswordResetTokenRepository,
} from "./infrastructure/persistence/prisma-verification-token-repositories.js";

// Testing fakes. Exported so contexts built on top of credentials can test
// their own use cases against fake credential repositories, rather than each
// re-implementing one that drifts.
export { InMemoryCredentialRepository } from "./infrastructure/testing/in-memory-credential-repository.js";
export { InMemoryCredentialsUnitOfWork } from "./infrastructure/testing/in-memory-credentials-unit-of-work.js";
export {
  InMemoryEmailVerificationTokenRepository,
  InMemoryPasswordResetTokenRepository,
} from "./infrastructure/testing/in-memory-verification-token-repositories.js";
