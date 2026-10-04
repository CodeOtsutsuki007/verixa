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

  private constructor(props: SessionProps) {
    this.id = props.id;
    this.userId = props.userId;
    this.refreshTokenHash = props.refreshTokenHash;
    this.metadataHistory = props.metadataHistory;
    this.currentAccessToken = props.currentAccessToken;
    this.createdAt = props.createdAt;
    this.lastActiveAt = props.lastActiveAt;
    this.expiresAt = props.expiresAt;
    this.revokedAt = props.revokedAt;
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
