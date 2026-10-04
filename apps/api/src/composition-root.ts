import { randomUUID } from "node:crypto";

import {
  AnchorAuditLog,
  PrismaAnchorRecordRepository,
  PrismaAuditLogRepository,
  QueryAuditEvents,
  RecordAuditEvent,
  VerifyAuditChain,
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
import {
  LocalTransactionSigner,
  StellarHashAnchor,
  type StellarNetwork,
  type TransactionSigner,
} from "@verixa/stellar-anchor";
import {
  InMemoryDomainEventPublisher,
  InMemoryMfaMethodRepository,
  InMemoryWebAuthnChallengeRepository,
  InMemoryWebAuthnCredentialRepository,
  RegisterWebAuthnCredential,
  VerifyWebAuthnAssertion,
  WebAuthnAssertionVerifier,
  WebAuthnAttestationVerifier,
} from "@verixa/mfa";
  InMemoryEventPublisher,
  NoopRateLimiter,
  type DomainEventPublisher,
} from "@verixa/shared-kernel";
import { StellarHashAnchor } from "@verixa/stellar-anchor";

import { registerAuditSubscribers } from "./composition/register-audit-subscribers.js";

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

/**
 * Binds the audit append's compare-and-set to a real database transaction
 * (Issue #128).
 *
 * `PrismaAuditLogRepository` takes the transaction as an injected function
 * rather than a client it can call `$transaction` on, so that this package
 * never has to name Prisma. This closure is the one place where that
 * translation happens, and it is deliberately a *transaction runner* rather
 * than a transaction object: the repository decides where the boundary goes,
 * and a composition root that handed it an open transaction would move that
 * decision to the wiring layer, where nobody is testing it.
 */
function auditTransaction(prisma: PrismaClient): AuditTransaction {
  return <T>(work: (entries: AuditDelegate) => Promise<T>): Promise<T> =>
    prisma.$transaction(async (tx) => work(tx.auditLogEntry));
}

/**
 * Reads a positive integer setting, falling back when absent or malformed.
 *
 * Not validated by `@verixa/config` because these are tuning knobs for one
 * adapter rather than part of the app's configuration contract, and a typo in
 * `AUDIT_FLUSH_INTERVAL_MS` should degrade to the documented default rather
 * than prevent the API from starting.
 */
function positiveIntFromEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") {
    return fallback;
  }

  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * Resolves the anchoring signing backend (Issue #129).
 *
 * `STELLAR_SIGNING_BACKEND` chooses between the two `TransactionSigner`
 * implementations:
 *
 * - `local` — the key is in this process's environment. Testnet and development
 *   only; on the public network it is refused unless
 *   `STELLAR_ALLOW_LOCAL_SIGNING=1` states the risk explicitly.
 * - `kms` — the key never enters this process. Cannot be built here: the cloud
 *   SDK that talks to the key service belongs to the deployment, so the
 *   signer is supplied through `ContainerOverrides.signer`. Setting `kms`
 *   without supplying one is a startup failure rather than a silent downgrade
 *   to no anchoring, because "I configured hardware-backed signing and got
 *   nothing" is the worst possible outcome to discover during an audit.
 *
 * Unset means: `local` if `STELLAR_ANCHOR_SECRET_KEY` is present (the
 * pre-#129 arrangement, kept working), otherwise no signer at all.
 */
function resolveSigner(
  overrides: ContainerOverrides,
  network: StellarNetwork,
): TransactionSigner | undefined {
  const backend = process.env["STELLAR_SIGNING_BACKEND"];

  if (backend === "kms") {
    if (overrides.signer === undefined) {
      throw new Error(
        'STELLAR_SIGNING_BACKEND is "kms" but no signer was supplied. Build a KmsTransactionSigner with your key service client at composition time and pass it as buildContainer(undefined, { signer }). See docs/security/stellar-key-management.md.',
      );
    }
    return overrides.signer;
  }

  if (overrides.signer !== undefined) {
    return overrides.signer;
  }

  const secretKey = process.env["STELLAR_ANCHOR_SECRET_KEY"];
  if (secretKey === undefined || secretKey === "") {
    return undefined;
  }

  if (network === "public" && process.env["STELLAR_ALLOW_LOCAL_SIGNING"] !== "1") {
    throw new Error(
      "Refusing to anchor on the public network with a key read from the environment. Use STELLAR_SIGNING_BACKEND=kms, or set STELLAR_ALLOW_LOCAL_SIGNING=1 only if you accept the risk described in docs/security/stellar-key-management.md.",
    );
  }

  return new LocalTransactionSigner(secretKey);
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

/** Audit recording, query, integrity verification and its external anchoring. */
export interface AuditUseCases {
  readonly recordEvent: RecordAuditEvent;
  readonly queryEvents: QueryAuditEvents;
  /**
   * Re-derives the hash chain and reports the first divergence.
   *
   * Wired here rather than left to the CLI alone, because the check is only a
   * control if something can run it on a schedule; a tool a human has to
   * remember to invoke is a tool that gets invoked after the incident.
   */
  readonly verifyChain: VerifyAuditChain;
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

/** Multi-factor authentication use cases. */
export interface MfaUseCases {
  readonly registerWebAuthnCredential: RegisterWebAuthnCredential;
  readonly verifyWebAuthnAssertion: VerifyWebAuthnAssertion;
}

export interface Container {
  readonly prisma: PrismaClient;
  readonly eventPublisher: DomainEventPublisher;
  readonly identity: IdentityUseCases;
  readonly credentials: CredentialUseCases;
  readonly audit: AuditUseCases;
  /**
   * Drains any queued audit writes, then releases the database connection.
   * Call on shutdown.
   */
  readonly mfa: MfaUseCases;
  /** Releases the database connection. Call on shutdown. */
  readonly dispose: () => Promise<void>;
}

/**
 * Pieces a deployment must supply because they cannot be derived from
 * environment variables alone.
 */
export interface ContainerOverrides {
  /**
   * A signer built by the deployment, for `STELLAR_SIGNING_BACKEND=kms`.
   *
   * It lives here rather than behind another environment variable because the
   * point of the key service is that *this process never holds the key* — the
   * SDK client that talks to it is configured by its own credential chain, and
   * reconstructing that from strings here would put the credential management
   * problem back where it started.
   */
  readonly signer?: TransactionSigner | undefined;
}

/**
 * Builds the object graph.
 *
 * Takes an optional `PrismaClient` so tests can inject one pointed at a
 * throwaway database. Production passes nothing and gets a client configured
 * from `DATABASE_URL`.
 */
export function buildContainer(
  prismaClient?: PrismaClient,
  overrides: ContainerOverrides = {},
): Container {
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
  const auditLog = new PrismaAuditLogRepository(prisma.auditLogEntry, auditTransaction(prisma));
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

  // Domain event publisher, with every audit subscriber already on it.
  //
  // Registration is part of building the container rather than something a
  // caller does afterwards, because the ordering is a correctness property, not
  // a setup step: an event published with no subscriber attached is dropped
  // permanently, and the first request a process serves is also the first
  // event it publishes. See `composition/register-audit-subscribers.ts`.
  const eventPublisher = new InMemoryEventPublisher();
  registerAuditSubscribers(eventPublisher, recordAuditEvent);

  // Anchoring is wired only when a signing key is configured. See AuditUseCases
  // on why this is `undefined` rather than a no-op.
  const stellarNetwork: StellarNetwork =
    process.env["STELLAR_NETWORK"] === "public" ? "public" : "testnet";
  const signer = resolveSigner(overrides, stellarNetwork);
  const hashAnchor =
    signer === undefined ? undefined : new StellarHashAnchor({ signer, network: stellarNetwork });

  // Multi-factor authentication (MFA) use cases and WebAuthn verifier adapters.
  const webauthnRpId = process.env["WEBAUTHN_RP_ID"] ?? "localhost";
  const webauthnOrigin = process.env["WEBAUTHN_ORIGIN"] ?? "http://localhost:3000";

  const mfaMethodRepo = new InMemoryMfaMethodRepository();
  const webAuthnCredentialRepo = new InMemoryWebAuthnCredentialRepository();
  const webAuthnChallengeRepo = new InMemoryWebAuthnChallengeRepository();
  const mfaEventPublisher = new InMemoryDomainEventPublisher();
  const attestationVerifier = new WebAuthnAttestationVerifier();
  const assertionVerifier = new WebAuthnAssertionVerifier();

  const registerWebAuthnCredential = new RegisterWebAuthnCredential(
    mfaMethodRepo,
    webAuthnCredentialRepo,
    webAuthnChallengeRepo,
    attestationVerifier,
    {
      expectedOrigin: webauthnOrigin,
      expectedRpId: webauthnRpId,
    },
  );

  const verifyWebAuthnAssertion = new VerifyWebAuthnAssertion(
    mfaMethodRepo,
    webAuthnCredentialRepo,
    webAuthnChallengeRepo,
    assertionVerifier,
    mfaEventPublisher,
    {
      expectedOrigin: webauthnOrigin,
      expectedRpId: webauthnRpId,
    },
  );

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
      // Verification is given the same ledger the anchor use case uses, so a
      // deployment that anchors gets the independent ledger check for free and
      // one that does not still gets the local re-derivation. `undefined` is
      // honest here in the other direction: `VerifyAuditChain` reports
      // `anchorsSkipped` rather than quietly returning an empty receipt list.
      verifyChain: new VerifyAuditChain(auditLog, anchorRecords, hashAnchor),
      anchor:
        hashAnchor === undefined
          ? undefined
          : new AnchorAuditLog(auditLog, anchorRecords, hashAnchor),
    },
    mfa: {
      registerWebAuthnCredential,
      verifyWebAuthnAssertion,
    },
    dispose: async () => {
      // Drained *before* disconnecting, and only because the batched writer
      // may hold entries that are not in the database yet. Skipping this is
      // the one way the queue's bounded delay becomes permanent data loss.
      await batchedWriter?.stop();
      await prisma.$disconnect();
    },
  };
}
