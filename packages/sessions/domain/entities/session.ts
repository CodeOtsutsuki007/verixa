import { createId, type DomainEvent, type Id } from "@verixa/shared-kernel";

import type { SessionExpiryPolicy } from "../value-objects/session-expiry-policy.js";
import { type Id, Result } from "@verixa/shared-kernel";

import { SessionExpiryPolicy } from "../value-objects/session-expiry-policy.js";

export type SessionId = Id<"SessionId">;
export type UserId = Id<"UserId">;

interface SessionProps {
  readonly id: SessionId;
  readonly userId: UserId;
  readonly createdAt: Date;
  readonly lastSeenAt: Date;
  readonly expiresAt: Date;
  readonly revokedAt?: Date | undefined;
  readonly expiryPolicy: SessionExpiryPolicy;
  readonly domainEvents?: readonly DomainEvent[];
}

/**
 * A user session, tracking lifecycle and expiry independently of any token
 * format or storage mechanism.
 *
 * ## Responsibility scope
 *
 * This entity owns the session *identity* and lifecycle only: the fields
 * (timestamps, expiry) and the state machine (`isExpired`, `isRevoked`,
 * `touch`). It does NOT own:
 *
 * - Token format (JWT, opaque string, etc.) — that's a Phase 05 (Issues 084,
 *   086) detail to be decided later.
 * - Token storage (Redis, cookies, database rows) — Phase 05 (Issues 083,
 *   088) will layer on adapters.
 * - Token rotation or refresh — Issue 089 adds use-case logic for that.
 *
 * The entity encapsulates the policy driving expiry behavior via
 * {@link expiryPolicy}, which makes `touch()` genuinely pluggable without
 * hardcoding sliding or absolute expiry.
 *
 * ## Invariants
 *
 * - A session must have a positive lifetime: `expiresAt > createdAt`.
 * - `lastSeenAt` tracks activity but never exceeds `expiresAt`.
 * - Once `revokedAt` is set, it cannot be unset (revocation is terminal).
 * - `touch()` updates `lastSeenAt` and may extend `expiresAt` depending on
 *   the policy.
 */
export class Session {
  readonly id: SessionId;
  readonly userId: UserId;
  readonly createdAt: Date;
  readonly lastSeenAt: Date;
  readonly expiresAt: Date;
  readonly revokedAt: Date | undefined;
  readonly expiryPolicy: SessionExpiryPolicy;
  private readonly domainEvents: readonly DomainEvent[];
/**
 * Lifecycle state of a session.
 * - **active:** The session is valid and can be used.
 * - **revoked:** The session has been explicitly revoked and is no longer valid.
 */
export type SessionStatus = "active" | "revoked";

/**
 * The Session aggregate root. Represents an authenticated user's session,
 * tracking its lifecycle from creation through expiry or explicit revocation.
 *
 * Sessions are immutable: methods return either a new instance (via Result, if
 * a transition can fail) or the same instance unchanged (for idempotent
 * operations like revoke). This mirrors the pattern used by User and
 * Organization aggregates.
 *
 * A session can end in two ways:
 * 1. **Expiry:** `expiresAt` passes; `isExpired()` returns true
 * 2. **Revocation:** `revoke()` is called; `revokedAt` is set and `status` becomes "revoked"
 */
export class Session {
  private constructor(
    readonly id: SessionId,
    readonly userId: UserId,
    readonly createdAt: Date,
    readonly lastSeenAt: Date,
    readonly expiresAt: Date,
    readonly revokedAt: Date | undefined,
    readonly status: SessionStatus,
    readonly expiryPolicy: SessionExpiryPolicy,
  ) {}

  /**
   * Create a new Session aggregate.
   *
   * Called by domain logic or use cases when a session is first created
   * (e.g., after a successful login). The returned Session carries the
   * initial expiryPolicy but has not yet been persisted.
   */
  static create(input: {
    id: SessionId;
    userId: UserId;
    expiryPolicy: SessionExpiryPolicy;
    createdAt?: Date;
  }): Session {
    const now = input.createdAt ?? new Date();
    return new Session(
      input.id,
      input.userId,
      now,
      now, // lastSeenAt starts at creation
      input.expiryPolicy.expiresAt(now),
      undefined, // not revoked
      "active",
      input.expiryPolicy,
    );
  }

  /**
   * Rebuild a Session from persisted data (e.g., a database row).
   *
   * Used by the persistence layer to reconstitute an aggregate after loading
   * it. Does not re-run creation validation: the data is assumed to be
   * already-valid (it was valid when saved, so re-running checks would be
   * redundant).
   */
  static reconstitute(input: {
    id: SessionId;
    userId: UserId;
    createdAt: Date;
    lastSeenAt: Date;
    expiresAt: Date;
    revokedAt: Date | undefined;
    status: SessionStatus;
    expiryPolicy: SessionExpiryPolicy;
  }): Session {
    return new Session(
      input.id,
      input.userId,
      input.createdAt,
      input.lastSeenAt,
      input.expiresAt,
      input.revokedAt,
      input.status,
      input.expiryPolicy,
    );
  }

  /**
   * Is this session no longer valid?
   *
   * True if either expired or revoked. Once either is true, the session
   * cannot be "un-expired" or "un-revoked" — a new session must be issued.
   */
  isInvalid(asOf: Date = new Date()): boolean {
    return this.isExpired(asOf) || this.isRevoked();
  }

  /**
   * Is the session's `expiresAt` timestamp in the past?
   *
   * Note: a revoked session may or may not be expired yet. This method only
   * checks the expiry clock, not the revocation status.
   */
  isExpired(asOf: Date = new Date()): boolean {
    return this.expiryPolicy.isExpired(this.expiresAt, asOf);
  }

  /**
   * Has this session been explicitly revoked?
   */
  isRevoked(): boolean {
    return this.status === "revoked";
  }

  /**
   * Record activity on this session, optionally extending the expiry.
   *
   * Under a sliding-expiry policy, this extends `expiresAt` to now + interval.
   * Under absolute expiry, this returns the same session unchanged.
   * In either case, `lastSeenAt` is updated to the current time.
   *
   * Returns a new Session with updated timestamps (or the same instance if
   * no change was needed, though callers should not rely on reference equality).
   */
  touch(touchedAt: Date = new Date()): Session {
    const newExpiresAt = this.expiryPolicy.maybeExtendExpiry(this.expiresAt, touchedAt);

    // If expiry changed, return a new instance; otherwise return this unchanged
    if (newExpiresAt.getTime() === this.expiresAt.getTime() && touchedAt === this.lastSeenAt) {
      return this;
    }

    return new Session(
      this.id,
      this.userId,
      this.createdAt,
      touchedAt,
      newExpiresAt,
      this.revokedAt,
      this.status,
      this.expiryPolicy,
    );
  }

  /**
   * Revoke this session, making it invalid immediately.
   *
   * Returns a new Session with status="revoked" and revokedAt set to the
   * current time.
   */
  revoke(revokedAt: Date = new Date()): Session {
    return new Session(
      this.id,
      this.userId,
      this.createdAt,
      this.lastSeenAt,
      this.expiresAt,
      revokedAt,
      "revoked",
      this.expiryPolicy,
    );
  }
}
import { createId, type Id } from "@verixa/shared-kernel";

import { generateToken, hashToken, tokenMatchesDigest } from "../value-objects/token-digest.js";

export type SessionId = Id<"SessionId">;

/** A `UserId` from the identity context, referenced by value — see `Credential` in `@verixa/credentials` for why sessions never hold a `User` instance. */
export type SessionUserId = Id<"UserId">;

/**
 * Default session lifetime: 30 days.
 *
 * Bounds how long a refresh token that is never explicitly revoked stays
 * usable — a "remember me" style window rather than the much shorter-lived
 * access token it repeatedly reissues. Long enough that a user who signs in
 * weekly never notices it; short enough that a device lost and never signed
 * out of stops working within a month rather than indefinitely.
 */
const DEFAULT_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * What the client presented at issuance and, potentially, again at every
 * later refresh. All fields are optional: none of them are supplied by a
 * trusted source (a mobile app can send any user-agent it likes), so this is
 * context for anomaly review, never an authorization input.
 */
export interface SessionMetadata {
  readonly ipAddress?: string | undefined;
  readonly userAgent?: string | undefined;
  /** A short human-readable label ("Chrome on macOS"), typically derived from `userAgent` by the caller. */
  readonly deviceLabel?: string | undefined;
}

/** One recorded observation of a session's metadata, and when it was seen. */
export interface SessionMetadataObservation {
  readonly metadata: SessionMetadata;
  readonly recordedAt: Date;
}

/** The access token currently associated with a session, as issued by a `TokenSigner`. */
export interface AccessTokenReference {
  /** The signer-assigned identifier (JWT `jti`) — what a `RevocationList` denylists. */
  readonly tokenId: string;
  readonly expiresAt: Date;
}

interface SessionProps {
  readonly id: SessionId;
  readonly userId: SessionUserId;
  readonly refreshTokenHash: string;
  /**
   * Every metadata observation made for this session, oldest first. The
   * first entry is what issuance captured; each later one is a refresh that
   * saw something different. Never trimmed — this is exactly the record
   * Issue 093 asks for, and it is small (one session refreshes at most a
   * handful of times an hour).
   */
  readonly metadataHistory: readonly SessionMetadataObservation[];
  readonly currentAccessToken: AccessTokenReference | undefined;
  readonly createdAt: Date;
  readonly lastActiveAt: Date;
  readonly expiresAt: Date;
  readonly revokedAt: Date | undefined;
  readonly stepUpVerifiedAt: Date | undefined;
}

/** A session plus the one-time raw refresh token issued with it. */
export interface IssuedSession {
  readonly session: Session;
  /** The raw refresh token, returned exactly once and never stored. */
  readonly rawRefreshToken: string;
}

/**
 * One authenticated device's ongoing relationship with the system: a
 * refresh token, the access token currently derived from it, and the
 * metadata observed along the way.
 *
 * ## Why metadata is a history, not a single snapshot
 *
 * A session that overwrote its metadata on every refresh could tell you
 * where it currently claims to be, and nothing about whether that changed.
 * "Logged in from Lagos, refreshed an hour later from a different country"
 * is the entire signal a future impossible-travel check (Phase 06+) would
 * need, and it only exists if the earlier observation was kept rather than
 * replaced. See Issue 093 and `docs/security/authentication-flows.md`.
 *
 * ## No setters
 *
 * Same discipline as `AuditLogEntry` and `User`: every state change returns
 * a new `Session`, and there is no way to mutate `metadataHistory`,
 * `revokedAt`, or the refresh token hash from outside this class.
 */
export class Session {
  readonly id: SessionId;
  readonly userId: SessionUserId;
  readonly refreshTokenHash: string;
  readonly metadataHistory: readonly SessionMetadataObservation[];
  readonly currentAccessToken: AccessTokenReference | undefined;
  readonly createdAt: Date;
  readonly lastActiveAt: Date;
  readonly expiresAt: Date;
  readonly revokedAt: Date | undefined;
  readonly stepUpVerifiedAt: Date | undefined;

  private constructor(props: SessionProps) {
    this.id = props.id;
    this.userId = props.userId;
    this.createdAt = props.createdAt;
    this.lastSeenAt = props.lastSeenAt;
    this.expiresAt = props.expiresAt;
    this.revokedAt = props.revokedAt;
    this.expiryPolicy = props.expiryPolicy;
    this.domainEvents = props.domainEvents ?? [];
  }

  /**
   * Creates a brand-new session for a user with the given expiry policy.
   *
   * Sets both `createdAt` and `lastSeenAt` to now; `expiresAt` is computed
   * from the policy's duration. The new session is not revoked.
   *
   * @param params.userId - The user this session belongs to.
   * @param params.expiryPolicy - The policy controlling how expiry behaves.
   * @returns The newly created session.
   */
  static create(params: { userId: UserId; expiryPolicy: SessionExpiryPolicy }): Session {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + params.expiryPolicy.durationMs);

    return new Session({
      id: createId<"SessionId">(),
      userId: params.userId,
      createdAt: now,
      lastSeenAt: now,
      expiresAt,
      expiryPolicy: params.expiryPolicy,
    });
  }

  /**
   * Rebuilds a session from already-trusted data (e.g. a database row).
   *
   * Unlike {@link create}, this does not validate invariants — the data is
   * assumed to already represent a previously-valid state.
   *
   * @param props - The session data to reconstitute.
   * @returns The reconstituted session.
   */
  static reconstitute(props: SessionProps): Session {
    return new Session({ ...props, domainEvents: [] });
  }

  /**
   * Whether this session has expired.
   *
   * A session is expired if `expiresAt` has passed, regardless of whether
   * it has been explicitly revoked. An expired session is unusable.
   *
   * @param asOf - The moment to check expiry against; defaults to now.
   * @returns `true` if the session has expired, `false` otherwise.
   */
  isExpired(asOf: Date = new Date()): boolean {
    return asOf >= this.expiresAt;
  }

  /**
   * Whether this session has been explicitly revoked.
   *
   * Revocation is terminal and independent of expiry — a revoked session is
   * always unusable, even if not yet expired by the clock. This is used to
   * implement logout and deny-list revocation (Issue 088).
   *
   * @returns `true` if the session is revoked, `false` otherwise.
   */
  isRevoked(): boolean {
    return this.revokedAt !== undefined;
  }

  /**
   * Marks the session as revoked at the given time.
   *
   * Once revoked, a session cannot be un-revoked. This method returns a new
   * session instance with `revokedAt` set (following the immutable entity
   * pattern from {@link User}).
   *
   * Calling `revoke()` on an already-revoked session is idempotent and
   * returns the same instance unchanged.
   *
   * @param revokedAt - When the session was revoked; defaults to now.
   * @returns A new session with revocation marked, or the same instance if
   *   already revoked.
   */
  revoke(revokedAt: Date = new Date()): Session {
    if (this.isRevoked()) {
      return this;
    }

    return new Session({
      ...this,
      revokedAt,
      domainEvents: [],
    });
  }

  /**
   * Updates the session's activity timestamp and (under a sliding policy)
   * extends the expiry time.
   *
   * Returns a new session instance with `lastSeenAt` updated to the current
   * time and, if using a sliding expiry policy, `expiresAt` pushed forward
   * by the policy's duration. If using an absolute policy, `expiresAt`
   * remains unchanged.
   *
   * This is a no-op on a revoked session — `touch()` returns the same
   * instance unchanged if the session is already revoked, since a revoked
   * session should not become active again.
   *
   * @param touchedAt - When the session was touched; defaults to now.
   * @returns A new session with activity recorded (and possibly expiry
   *   extended), or the same instance if revoked.
   */
  touch(touchedAt: Date = new Date()): Session {
    // Revoked sessions are immutable and not re-activated by touch.
    if (this.isRevoked()) {
      return this;
    }

    const newExpiresAt = this.expiryPolicy.computeNewExpiresAt(this.expiresAt, touchedAt);

    return new Session({
      ...this,
      lastSeenAt: touchedAt,
      expiresAt: newExpiresAt,
      domainEvents: [],
    });
  }

  /**
   * Returns domain events produced by the action that created this session
   * instance.
   *
   * For now, this returns an empty array (Phase 05, Issue 081 does not
   * define domain events yet), but the method is present to follow the
   * established entity pattern and to accommodate future event emission.
   */
  pullDomainEvents(): readonly DomainEvent[] {
    return this.domainEvents;
  }
}
    this.refreshTokenHash = props.refreshTokenHash;
    this.metadataHistory = props.metadataHistory;
    this.currentAccessToken = props.currentAccessToken;
    this.createdAt = props.createdAt;
    this.lastActiveAt = props.lastActiveAt;
    this.expiresAt = props.expiresAt;
    this.revokedAt = props.revokedAt;
    this.stepUpVerifiedAt = props.stepUpVerifiedAt;
  }

  /** SHA-256 of a raw refresh token, hex-encoded. The only form ever persisted. */
  static hashRefreshToken(token: string): string {
    return hashToken(token);
  }

  /**
   * Issues a brand-new session for `userId`, capturing the metadata seen at
   * login as the first entry in its history.
   *
   * `accessToken` is required, not optional: a session with no access token
   * would be a refresh token with nothing to show for it yet, which is not a
   * state any caller of this codebase's `IssueSession` use case should be
   * able to produce.
   */
  static issue(params: {
    userId: SessionUserId;
    metadata: SessionMetadata;
    accessToken: AccessTokenReference;
    ttlMs?: number;
    now?: Date;
  }): IssuedSession {
    const now = params.now ?? new Date();
    const rawRefreshToken = generateToken();

    return {
      rawRefreshToken,
      session: new Session({
        id: createId<"SessionId">(),
        userId: params.userId,
        refreshTokenHash: hashToken(rawRefreshToken),
        metadataHistory: [{ metadata: params.metadata, recordedAt: now }],
        currentAccessToken: params.accessToken,
        createdAt: now,
        lastActiveAt: now,
        expiresAt: new Date(now.getTime() + (params.ttlMs ?? DEFAULT_SESSION_TTL_MS)),
        revokedAt: undefined,
        stepUpVerifiedAt: undefined,
      }),
    };
  }

  /** Rebuilds from already-trusted data (a database row). */
  static reconstitute(props: SessionProps): Session {
    return new Session(props);
  }

  /** Whether `candidate` is the raw refresh token this session was issued (or last rotated) with. */
  matchesRefreshToken(candidate: string): boolean {
    return tokenMatchesDigest(candidate, this.refreshTokenHash);
  }

  /** The most recently observed metadata — what a "your active sessions" list should show. */
  get currentMetadata(): SessionMetadata {
    return this.metadataHistory[this.metadataHistory.length - 1]!.metadata;
  }

  get isRevoked(): boolean {
    return this.revokedAt !== undefined;
  }

  isExpiredAt(now: Date): boolean {
    return now.getTime() >= this.expiresAt.getTime();
  }

  /** Whether this session may still be used to authenticate or refresh. */
  isActiveAt(now: Date): boolean {
    return !this.isRevoked && !this.isExpiredAt(now);
  }

  /**
   * Records a refresh: bumps `lastActiveAt`, attaches the newly issued
   * access token, and — this is the part Issue 093 is for — appends a new
   * metadata observation *only when it differs* from the current one.
   *
   * Comparing rather than always appending keeps the history meaningful: a
   * user who refreshes forty times a day from the same laptop should not
   * bury the one entry that matters (a genuinely new IP) under forty
   * identical copies of "same as before."
   */
  recordActivity(params: {
    metadata: SessionMetadata;
    accessToken: AccessTokenReference;
    now?: Date;
  }): Session {
    const now = params.now ?? new Date();
    const changed = !metadataEquals(this.currentMetadata, params.metadata);

    return new Session({
      ...this,
      metadataHistory: changed
        ? [...this.metadataHistory, { metadata: params.metadata, recordedAt: now }]
        : this.metadataHistory,
      currentAccessToken: params.accessToken,
      lastActiveAt: now,
    });
  }

  /**
   * Revokes the session: no further refresh will succeed, and the caller is
   * responsible for denylisting {@link currentAccessToken} via a
   * `RevocationList` so the still-live access token stops working too (see
   * `Logout`/`LogoutEverywhere`) — a `Session` alone has no way to reach one.
   *
   * Idempotent: revoking an already-revoked session returns it unchanged, so
   * the original revocation time survives.
   */
  revoke(now: Date = new Date()): Session {
    if (this.isRevoked) {
      return this;
    }
    return new Session({ ...this, revokedAt: now });
  }

  /**
   * Records a successful step-up authentication verification, stamping the current time
   * to satisfy sensitive action checks within the configured max age.
   */
  recordStepUp(now: Date = new Date()): Session {
    return new Session({ ...this, stepUpVerifiedAt: now });
  }

  /** Whether the session has a fresh step-up verification within `maxAgeMs` relative to `now`. */
  isStepUpFresh(maxAgeMs: number, now: Date = new Date()): boolean {
    if (!this.stepUpVerifiedAt) {
      return false;
    }
    return now.getTime() - this.stepUpVerifiedAt.getTime() <= maxAgeMs;
  }

  /** The refresh token hash is a secret in the same sense a password hash is; it has no business in a log line. */
  toJSON(): Record<string, unknown> {
    return {
      id: this.id,
      userId: this.userId,
      refreshTokenHash: "[REDACTED]",
      metadataHistory: this.metadataHistory,
      currentAccessToken: this.currentAccessToken,
      createdAt: this.createdAt,
      lastActiveAt: this.lastActiveAt,
      expiresAt: this.expiresAt,
      revokedAt: this.revokedAt,
      stepUpVerifiedAt: this.stepUpVerifiedAt,
    };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): Record<string, unknown> {
    return this.toJSON();
  }
}

function metadataEquals(a: SessionMetadata, b: SessionMetadata): boolean {
  return (
    a.ipAddress === b.ipAddress && a.userAgent === b.userAgent && a.deviceLabel === b.deviceLabel
  );
}
