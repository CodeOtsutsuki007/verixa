// Domain entities and value objects
export { Session, type SessionId, type UserId } from "./domain/entities/session.js";
export { SessionExpiryPolicy, type ExpiryMode } from "./domain/value-objects/session-expiry-policy.js";

// Application ports
export type { SessionRepository } from "./application/ports/session-repository.js";
/**
 * @verixa/sessions – Session lifecycle, JWT token issuance, revocation, and
 * session-based authentication primitives for Phase 05 and later.
 *
 * This package encapsulates sessions as a bounded context: domain entities
 * (`Session`, `RefreshToken`, `SessionExpiryPolicy`), application ports
 * (`SessionRepository`), and infrastructure implementations (Prisma persistence,
 * in-memory testing).
 *
 * ### Public API Surface
 *
 * Only the items listed below are meant to be consumed outside this package.
 * Internal implementation (mappers, error handlers, testing harnesses) is not
 * exported; deep imports via `@verixa/sessions/infrastructure/...` are
 * prevented by the eslint `no-restricted-imports` rule.
 *
 * **Domain layer:**
 * - `Session` aggregate with `create`, `reconstitute`, `touch`, `revoke` methods
 * - `RefreshToken` entity with opaque, hashed bearer token design (Issue 086)
 * - `SessionExpiryPolicy` value object with `sliding` and `absolute` modes
 * - `SessionStatus` type for lifecycle states
 *
 * **Application layer:**
 * - `SessionRepository` port defining behavioral contract for persistence
 *
 * **Infrastructure (for use-case wiring):**
 * - `PrismaSessionRepository` for Postgres-backed persistence
 * - `InMemorySessionRepository` for testing and component composition
 *
 * See `docs/guides/domain-modeling.md` for the domain modeling rationale and
 * architectural decisions specific to sessions.
 */

// Domain
export { Session, type SessionId, type SessionStatus, type UserId } from "./domain/entities/session.js";
export { RefreshToken, type RefreshTokenId, type IssuedRefreshToken } from "./domain/entities/refresh-token.js";
export {
  SessionExpiryPolicy,
  type SessionExpiryMode,
} from "./domain/value-objects/session-expiry-policy.js";

// Application
export type { SessionRepository } from "./application/ports/session-repository.js";

// Infrastructure — adapters only
export { PrismaSessionRepository } from "./infrastructure/persistence/prisma-session-repository.js";
export { InMemorySessionRepository } from "./infrastructure/testing/in-memory-session-repository.js";
// The public API of @verixa/sessions. Consumers import from the package root
// (`@verixa/sessions`), never a deep path — a context's domain/application
// internals are not part of its public surface. See
// docs/guides/domain-modeling.md ("Package encapsulation").
//
// This package is being built incrementally across Phase 05. What is exported
// here today is the slice landed so far: session identity, the access-token
// signer with key rotation (Issue 085), and the Redis revocation deny-list
// (Issue 088). The session aggregate, refresh tokens, and the issue/refresh/
// logout use cases arrive with their own issues.

// Domain: value objects
export { asSessionId, createSessionId } from "./domain/value-objects/session-id.js";
export type { SessionId } from "./domain/value-objects/session-id.js";

// Domain: errors
export { TokenVerificationError } from "./domain/errors/token-verification-error.js";
export type { TokenVerificationFailure } from "./domain/errors/token-verification-error.js";

// Application: ports (implemented by the infrastructure adapters below, and
// depended on by the use cases that will follow)
export type { RevocationList } from "./application/ports/revocation-list.js";
export type {
  AccessTokenInput,
  TokenSigner,
  VerifiedAccessToken,
} from "./application/ports/token-signer.js";

// Infrastructure: token signing & key rotation (Issue 084/085)
export { JwtTokenSigner } from "./infrastructure/jwt-token-signer.js";
export type { JwtTokenSignerOptions } from "./infrastructure/jwt-token-signer.js";
export { createConfigSigningKeyProvider } from "./infrastructure/signing-key-provider.js";
export type {
  ActiveSigningKey,
  SigningKeyProvider,
  VerificationKey,
} from "./infrastructure/signing-key-provider.js";

// Infrastructure: revocation deny-list (Issue 088)
export { RedisRevocationList } from "./infrastructure/redis-revocation-list.js";
export type { RedisRevocationListOptions } from "./infrastructure/redis-revocation-list.js";

// Testing: in-memory fake for consumers unit-testing against the revocation port
export { InMemoryRevocationList } from "./infrastructure/testing/in-memory-revocation-list.js";
// Curated public surface of @verixa/sessions. Nothing outside this package
// should import from a deep path (`@verixa/sessions/domain/...`,
// `@verixa/sessions/application/...`) — see docs/guides/domain-modeling.md
// ("Package encapsulation") for why, and eslint.config.mjs's
// `no-restricted-imports` rule, which enforces it.

// Domain: entities
export type {
  AccessTokenReference,
  IssuedSession,
  SessionId,
  SessionMetadata,
  SessionMetadataObservation,
  SessionUserId,
} from "./domain/entities/session.js";
export { Session } from "./domain/entities/session.js";
export { RefreshToken } from "./domain/entities/refresh-token.js";

// Domain: value objects
export { SessionExpiryPolicy } from "./domain/value-objects/session-expiry-policy.js";
export {
  generateToken,
  hashToken,
  tokenMatchesDigest,
} from "./domain/value-objects/token-digest.js";

// Domain: events
export { RefreshTokenReuseDetected } from "./domain/events/refresh-token-reuse-detected.js";

// Application: ports (for infrastructure adapters to implement)
export type { SessionRepository } from "./application/ports/session-repository.js";
export type { IssuedAccessToken, TokenSigner } from "./application/ports/token-signer.js";
export type { RevocationList } from "./application/ports/revocation-list.js";
export type { SessionAuditLogger } from "./application/ports/session-audit-logger.js";

// Application: use cases
export {
  IssueSession,
  type IssueSessionCommand,
  type IssueSessionResult,
} from "./application/use-cases/issue-session.js";
export {
  RefreshAccessToken,
  type RefreshAccessTokenCommand,
  type RefreshAccessTokenResult,
} from "./application/use-cases/refresh-access-token.js";
export { Logout, type LogoutCommand } from "./application/use-cases/logout.js";
export {
  LogoutEverywhere,
  type LogoutEverywhereCommand,
  type LogoutEverywhereResult,
} from "./application/use-cases/logout-everywhere.js";
export { ListActiveSessions } from "./application/use-cases/list-active-sessions.js";

// Infrastructure: adapters (Exported so the composition root can construct them)
export { PrismaSessionRepository } from "./infrastructure/persistence/prisma-session-repository.js";
export { JwtTokenSigner } from "./infrastructure/jwt-token-signer.js";
export { RedisRevocationList } from "./infrastructure/redis-revocation-list.js";
export { SigningKeyProvider } from "./infrastructure/signing-key-provider.js";

// Testing fakes
export { InMemorySessionRepository } from "./infrastructure/testing/in-memory-session-repository.js";
export { InMemoryRevocationList } from "./infrastructure/testing/in-memory-revocation-list.js";
export { InMemoryTokenSigner } from "./infrastructure/testing/in-memory-token-signer.js";
export {
  InMemorySessionAuditLogger,
  type RecordedSessionAuditEntry,
} from "./infrastructure/testing/in-memory-session-audit-logger.js";
