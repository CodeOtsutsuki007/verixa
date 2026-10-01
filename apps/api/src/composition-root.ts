import { randomUUID } from "node:crypto";

import {
  AnchorAuditLog,
  PermissionGrantedAuditSubscriber,
  PrismaAnchorRecordRepository,
  PrismaAuditLogRepository,
  QueryAuditEvents,
  RecordAuditEvent,
  RoleAssignedAuditSubscriber,
  SessionCreatedAuditSubscriber,
  SessionRevokedAuditSubscriber,
} from "@verixa/audit";
import { loadConfig } from "@verixa/config";
import {
  Argon2PasswordHasher,
  AuthenticateWithPassword,
  ConfirmEmailVerification,
  ConfirmPasswordReset,
  NoSessionsRevoker,
  NullCredentialNotifier,
  PrismaCredentialsUnitOfWork,
  RegisterUserWithPassword,
  RequestEmailVerification,
  RequestPasswordReset,
} from "@verixa/credentials";
import { PrismaClient } from "@verixa/database";
import {
  CreateOrganization,
  InviteUserToOrganization,
  PrismaInvitationRepository,
  PrismaUnitOfWork,
  PrismaUserRepository,
  ReactivateUser,
  RegisterUser,
  SuspendUser,
  UpdateUserProfile,
} from "@verixa/identity";
import { NoopRateLimiter } from "@verixa/shared-kernel";
import { StellarHashAnchor } from "@verixa/stellar-anchor";

/**
 * The composition root: the one place in the system allowed to know which
 * concrete implementations exist.
 *
 * Everything else depends on interfaces. `RegisterUser` knows it needs *a*
 * `UserRepository`; it has no idea one is backed by Prisma. That's what makes
 * the whole application layer testable without a database — and it only holds
 * because the knowledge of "which implementation" is concentrated here rather
 * than scattered across the modules that use them.
 *
 * The rule to preserve: **nothing outside this file imports a `Prisma*`
 * class.** The moment a route handler constructs its own repository, the
 * dependency inversion is gone and that handler can no longer be tested
 * without a database. Wiring is deliberately boring and explicit for the same
 * reason — a DI container would hide these edges behind runtime resolution,
 * where a missing dependency becomes a runtime failure instead of a compile
 * error. At this size, explicit construction costs a few lines and buys
 * complete type safety.
 */

/**
 * Applies pool settings to the connection string (Issue 053).
 *
 * Prisma has no constructor option for pool size — it reads
 * `connection_limit` and `pool_timeout` from the URL query string. Building
 * that here keeps the tuning knobs as ordinary validated config
 * (`DATABASE_POOL_SIZE`, `DATABASE_POOL_TIMEOUT_SECONDS`) instead of
 * requiring operators to hand-append query parameters to a URL and get the
 * spelling right.
 *
 * Existing query parameters are preserved; explicit ones in `DATABASE_URL`
 * win, so a deployment can still override per-environment without changing
 * code.
 */
function pooledDatabaseUrl(): string {
  const config = loadConfig();
  const url = new URL(config.DATABASE_URL);

  if (!url.searchParams.has("connection_limit")) {
    url.searchParams.set("connection_limit", String(config.DATABASE_POOL_SIZE));
  }
  if (!url.searchParams.has("pool_timeout")) {
    url.searchParams.set("pool_timeout", String(config.DATABASE_POOL_TIMEOUT_SECONDS));
  }

  return url.toString();
}

/** Every use case the application exposes, fully wired. */
export interface IdentityUseCases {
  readonly registerUser: RegisterUser;
  readonly updateUserProfile: UpdateUserProfile;
  readonly suspendUser: SuspendUser;
  readonly reactivateUser: ReactivateUser;
  readonly createOrganization: CreateOrganization;
  readonly inviteUserToOrganization: InviteUserToOrganization;
}

/** Use cases spanning identity and credentials. */
export interface CredentialUseCases {
  readonly registerUserWithPassword: RegisterUserWithPassword;
  readonly authenticateWithPassword: AuthenticateWithPassword;
  readonly requestEmailVerification: RequestEmailVerification;
  readonly confirmEmailVerification: ConfirmEmailVerification;
  readonly requestPasswordReset: RequestPasswordReset;
  readonly confirmPasswordReset: ConfirmPasswordReset;
}

/** Audit recording and its external anchoring. */
export interface AuditUseCases {
  readonly recordEvent: RecordAuditEvent;
  readonly queryEvents: QueryAuditEvents;
  /**
   * Present only when an anchoring ledger is configured.
   *
   * Absent rather than a no-op, so a deployment that has not set up anchoring
   * cannot believe it has. A silent stub here would be the worst outcome
   * available: an operator who thinks their audit log is externally verifiable
   * when nothing has ever been committed anywhere.
   */
  readonly anchor: AnchorAuditLog | undefined;
}

export interface Container {
  readonly prisma: PrismaClient;
  readonly eventPublisher: DomainEventPublisher;
  readonly identity: IdentityUseCases;
  readonly credentials: CredentialUseCases;
  readonly audit: AuditUseCases;
  /** Releases the database connection. Call on shutdown. */
  readonly dispose: () => Promise<void>;
}

/**
 * Builds the object graph.
 *
 * Takes an optional `PrismaClient` so tests can inject one pointed at a
 * throwaway database. Production passes nothing and gets a client configured
 * from `DATABASE_URL`.
 */
export function buildContainer(prismaClient?: PrismaClient): Container {
  const prisma =
    prismaClient ?? new PrismaClient({ datasources: { db: { url: pooledDatabaseUrl() } } });

  const users = new PrismaUserRepository(prisma);
  const invitations = new PrismaInvitationRepository(prisma);
  const unitOfWork = new PrismaUnitOfWork(prisma);

  // One hasher for the process, not one per request. Its cost parameters are
  // fixed configuration; constructing it per call would allocate for nothing.
  const passwordHasher = new Argon2PasswordHasher();
  const credentialsUnitOfWork = new PrismaCredentialsUnitOfWork(prisma);

  // Both of these are placeholders for later phases, and both are wired to
  // real call sites rather than left as TODOs.
  //
  // `NullCredentialNotifier` delivers nothing — mail is Phase 14. It is
  // deliberately silent rather than a stub that logs "would have sent:
  // <token>", which is the version that survives in production for a
  // fortnight while every reset token in the system lands in a log
  // aggregator.
  //
  // `NoSessionsRevoker` is *correct* today, not a stub: sessions are Phase
  // 05, so revoking all of them is genuinely a no-op. Having the call site
  // exist now is what stops "invalidate sessions on password reset" becoming
  // a step someone has to remember to add later — the most commonly missed
  // part of a reset flow.
  //
  // `NoopRateLimiter` always allows requests — rate limiting is Phase 15.
  // It is wired as the default adapter so use cases work before the real
  // limiter exists. No changes to use cases required when the real one
  // arrives — only a new adapter and a new wire in composition root.
  const credentialNotifier = new NullCredentialNotifier();
  const sessionRevoker = new NoSessionsRevoker();
  const rateLimiter = new NoopRateLimiter();

  // Audit recording. Failures are logged and never propagated -- see
  // RecordAuditEvent on why a failed audit write must not fail the operation
  // it was recording.
  const auditLog = new PrismaAuditLogRepository(prisma.auditLogEntry);
  const anchorRecords = new PrismaAnchorRecordRepository(prisma.anchorRecord, () => randomUUID());

  const recordAuditEvent = new RecordAuditEvent(auditLog, (error: unknown) => {
    // Written to stderr rather than swallowed entirely: a gap in the audit
    // log is itself a security-relevant event, and the sequence gap it
    // leaves is deliberately visible to `verifyChain`.
    process.stderr.write(
      `audit write failed: ${error instanceof Error ? error.message : String(error)}
`,
    );
  });

  // Domain event publisher with audit subscribers (Phase 10, Issue 186).
  // Subscribe to session lifecycle events (SessionCreated, SessionRevoked from Phase 05)
  // and RBAC events (RoleAssigned, PermissionGranted from Phase 07).
  const eventPublisher = new InMemoryEventPublisher();

  // Session audit subscribers
  const sessionCreatedSubscriber = new SessionCreatedAuditSubscriber(recordAuditEvent);
  const sessionRevokedSubscriber = new SessionRevokedAuditSubscriber(recordAuditEvent);
  eventPublisher.subscribe("sessions.session.created", (event) => sessionCreatedSubscriber.handle(event));
  eventPublisher.subscribe("sessions.session.revoked", (event) => sessionRevokedSubscriber.handle(event));

  // RBAC audit subscribers
  const roleAssignedSubscriber = new RoleAssignedAuditSubscriber(recordAuditEvent);
  const permissionGrantedSubscriber = new PermissionGrantedAuditSubscriber(recordAuditEvent);
  eventPublisher.subscribe("rbac.role.assigned", (event) => roleAssignedSubscriber.handle(event));
  eventPublisher.subscribe("rbac.permission.granted", (event) => permissionGrantedSubscriber.handle(event));

  // Anchoring is wired only when a signing key is configured. See AuditUseCases
  // on why this is `undefined` rather than a no-op.
  const anchorSecretKey = process.env["STELLAR_ANCHOR_SECRET_KEY"];
  const stellarNetwork = process.env["STELLAR_NETWORK"] === "public" ? "public" : "testnet";
  const hashAnchor =
    anchorSecretKey === undefined || anchorSecretKey === ""
      ? undefined
      : new StellarHashAnchor({ secretKey: anchorSecretKey, network: stellarNetwork });

  // PrismaOrganizationRepository and PrismaOrganizationMembershipRepository
  // aren't constructed here: the only use case that touches them
  // (CreateOrganization) reaches them through the unit of work, since its two
  // writes must commit together. Phase 12's read-only routes will need them
  // directly, and that's when they get wired — building them now would mean
  // an unused object graph pretending to be used.

  return {
    prisma,
    eventPublisher,
    identity: {
      registerUser: new RegisterUser(users),
      updateUserProfile: new UpdateUserProfile(users),
      suspendUser: new SuspendUser(users),
      reactivateUser: new ReactivateUser(users),
      // Takes the unit of work rather than the two repositories: it writes an
      // organization and a membership, and those must commit together.
      createOrganization: new CreateOrganization(unitOfWork),
      inviteUserToOrganization: new InviteUserToOrganization(invitations),
    },
    credentials: {
      registerUserWithPassword: new RegisterUserWithPassword(
        credentialsUnitOfWork,
        passwordHasher,
        rateLimiter,
      ),
      // Shares the hasher instance with registration deliberately. Beyond
      // avoiding a second allocation, the timing decoy that hides whether an
      // account exists is cached per hasher, so a second instance would build
      // its own on the first failed login.
      authenticateWithPassword: new AuthenticateWithPassword(
        credentialsUnitOfWork,
        passwordHasher,
        rateLimiter,
      ),
      requestEmailVerification: new RequestEmailVerification(
        credentialsUnitOfWork,
        credentialNotifier,
      ),
      confirmEmailVerification: new ConfirmEmailVerification(credentialsUnitOfWork),
      requestPasswordReset: new RequestPasswordReset(
        credentialsUnitOfWork,
        credentialNotifier,
        rateLimiter,
      ),
      confirmPasswordReset: new ConfirmPasswordReset(
        credentialsUnitOfWork,
        passwordHasher,
        sessionRevoker,
        rateLimiter,
      ),
    },
    audit: {
      recordEvent: recordAuditEvent,
      queryEvents: new QueryAuditEvents(auditLog),
      anchor:
        hashAnchor === undefined
          ? undefined
          : new AnchorAuditLog(auditLog, anchorRecords, hashAnchor),
    },
    dispose: async () => {
      await prisma.$disconnect();
    },
  };
}
