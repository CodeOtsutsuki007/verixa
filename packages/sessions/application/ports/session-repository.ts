import type { Session, SessionId, UserId } from "../../domain/entities/session.js";

/**
 * The persistence contract the application layer needs for `Session` — the
 * **port** half of ports & adapters (hexagonal architecture). No Prisma, SQL,
 * Redis, or any other implementation detail appears here; the concrete adapter
 * (Phase 05, Postgres or Redis-backed) implements this interface without this
 * package ever depending on it. See `docs/guides/domain-modeling.md`.
 *
 * ## Method contracts
 *
 * ### save(session: Session): Promise<void>
 *
 * Persists a session, whether newly created or previously stored. This is an
 * idempotent upsert operation:
 *
 * - If no session with this id exists, a new row is created.
 * - If a session with this id already exists, it is updated with the new state.
 * - The caller does not distinguish "create" from "update" — the session
 *   instance's complete state (including expiry time, revocation status,
 *   last-seen timestamp) is the only contract. The adapter observes the state
 *   and persists it correctly regardless of whether the session is new or an
 *   update.
 *
 * Implementations should persist all session fields: id, userId, createdAt,
 * lastSeenAt, expiresAt, revokedAt (if set), and the expiryPolicy. The
 * expiryPolicy should be stored in a way that allows it to be reconstituted
 * (e.g., as a JSON object with { mode: "sliding" | "absolute", durationMs }).
 *
 * ### findById(sessionId: SessionId): Promise<Session | undefined>
 *
 * Retrieves a single session by its id, or returns `undefined` if no matching
 * session exists. A missing session is an expected, common outcome (e.g.,
 * checking whether a session id is valid), not an error condition.
 *
 * Returns `undefined` for:
 * - A session id that has never been saved.
 * - A session that existed but was deleted (if soft-delete is implemented).
 *
 * Note: Does NOT filter by expiry or revocation status. The repository returns
 * whatever row it finds; the caller is responsible for checking `isExpired()`
 * and `isRevoked()` to decide whether to accept it. This separation of concerns
 * lets callers apply time-dependent logic at the time of use (using their own
 * `now` reference, which matters for testing and time-zone independence).
 *
 * ### findActiveByUserId(userId: UserId): Promise<Session[]>
 *
 * Retrieves all sessions for a given user that are currently active. Returns
 * an array, which may be empty.
 *
 * "Active" means:
 * - The session has NOT been explicitly revoked (`isRevoked()` returns false).
 * - The session has NOT expired (`isExpired()` returns false when checked at
 *   the time of retrieval).
 *
 * Callers rely on this to list a user's valid login sessions (e.g., for a
 * session-management UI). The repository MUST apply these filters at retrieval
 * time, not leave it to the caller, because:
 * 1. Filtering in the storage layer is vastly cheaper (a WHERE clause) than
 *    fetching and filtering in the application layer.
 * 2. Implementations are free to optimize: a Redis-backed adapter might use
 *    TTL expiry to auto-delete, while a Postgres adapter uses a time check.
 *
 * The array is ordered by `lastSeenAt` descending (most-recently-active first)
 * to be useful for UIs listing a user's sessions. (This ordering is a
 * convenience; callers should not depend on it for correctness, only for UX.)
 *
 * ### revoke(sessionId: SessionId): Promise<void>
 *
 * Marks a single session as revoked, making it permanently unusable. A revoked
 * session will never become active again (even if not yet expired).
 *
 * This operation is idempotent: calling `revoke()` on an already-revoked
 * session is a no-op and does not fail. Revoking an expired session is also
 * idempotent and succeeds silently.
 *
 * If no session with the given id exists, this is also a silent no-op (the
 * session is "revoked" in the sense that there is no valid session with that
 * id, so the outcome is the same). This idempotency is important for
 * implementing reliable logout: a caller might retry a revoke request if unsure
 * whether the first one succeeded, and the second attempt must not cause an
 * error.
 *
 * ### revokeAllForUser(userId: UserId): Promise<void>
 *
 * Marks all of a given user's sessions as revoked, making them all permanently
 * unusable. This is the bulk operation used for "log out everywhere" / "revoke
 * all sessions" features.
 *
 * Behavior on edge cases:
 * - If a user has no sessions, this is a silent no-op.
 * - If a user's sessions are already revoked, this is a silent no-op (the
 *   operation is idempotent).
 * - If a user's sessions have already expired, this still revokes them
 *   (marking `revokedAt` so the record reflects an explicit revocation, not
 *   just natural expiry).
 *
 * Implementations must ensure atomicity: either all of a user's sessions are
 * revoked together, or none are. If the operation fails partway through, the
 * caller should receive an error and may retry the entire operation.
 *
 * The array returned by `findActiveByUserId()` for that user must be empty
 * after this call (because no session will be both non-revoked and non-expired,
 * unless new sessions are created between the revoke and the find).
 */
export interface SessionRepository {
  save(session: Session): Promise<void>;
  findById(sessionId: SessionId): Promise<Session | undefined>;
  findActiveByUserId(userId: UserId): Promise<Session[]>;
  revoke(sessionId: SessionId): Promise<void>;
 * Port for session persistence — the interface every implementation (in-memory,
 * Prisma, Redis-backed, etc.) must satisfy.
 *
 * The contract is behavioral: two implementations must be observationally
 * identical from a caller's perspective. Contract testing (see
 * session-repository.contract.ts) verifies this by running the same test suite
 * against both the in-memory fake and, once it exists, the Prisma adapter.
 *
 * Implementations of this port are the only place where Prisma types or other
 * persistence-specific vocabulary appears. Domain and application layers
 * reference only this interface and the Session entity it trades in.
 */
export interface SessionRepository {
  /**
   * Persist a Session, creating it if it doesn't exist or updating it if it does.
   *
   * Idempotent: calling `save(session)` twice with the same session state
   * produces the same result as calling it once. This is what lets a use case
   * safely retry on transient failure without worrying about duplicates.
   *
   * @throws ConflictError if a unique constraint is violated (not expected for
   *   sessions, but possible if a future schema change adds constraints).
   */
  save(session: Session): Promise<void>;

  /**
   * Load a Session by ID, if one exists with that ID.
   *
   * Returns the session if found, regardless of its status (active or revoked).
   * Use-case-level logic decides whether to act on a revoked or expired session.
   *
   * Returns undefined if no session with that ID exists.
   */
  findById(sessionId: SessionId): Promise<Session | undefined>;

  /**
   * Load every active (non-revoked, non-expired) session for a given user.
   *
   * "Active" means:
   * - `status = 'active'` (not revoked)
   * - `expiresAt > now()` (not expired)
   *
   * Returns an empty array if the user has no active sessions.
   *
   * This is the query needed by:
   * - "List my devices" features (Issue 095)
   * - Concurrent-session-limit enforcement (Issue 094)
   * - "Log out everywhere" flows (Issue 092) as a precursor to revoke-all
   *
   * **Performance note:** Indexed on (userId, expiresAt) to support this query
   * without a table scan.
   */
  findActiveByUserId(userId: UserId): Promise<Session[]>;

  /**
   * Mark a single session as revoked (set status='revoked', record revokedAt).
   *
   * After this call, the session is no longer valid. A user presenting a token
   * from this session should be rejected.
   *
   * Idempotent: calling revoke multiple times on the same session is a no-op
   * after the first call.
   *
   * Does nothing (does not error) if no session with that ID exists — treating
   * "revoke a non-existent session" as a successful no-op is standard practice
   * for delete/revoke operations.
   */
  revoke(sessionId: SessionId): Promise<void>;

  /**
   * Revoke every session for a given user at once.
   *
   * Used by:
   * - "Log out on all devices" (Issue 092)
   * - Password-change flows (Phase 04, Issue 070)
   * - Admin account lockdown
   * - Suspected compromise responses
   *
   * After this call, every session for the user is invalid, and any tokens
   * issued from those sessions should be denied (via the deny-list in Issue 088,
   * once it exists).
   *
   * Idempotent and safe if called with a user who has no sessions.
   */
  revokeAllForUser(userId: UserId): Promise<void>;
import type { Session, SessionId, SessionUserId } from "../../domain/entities/session.js";

/**
 * The persistence contract the application layer needs for `Session`. No
 * Prisma or SQL appears here; the concrete adapter (Phase 05's
 * infrastructure work) implements this without this package ever depending
 * on it. See `docs/guides/domain-modeling.md`.
 *
 * Method contracts:
 * - `findById` returns `undefined` when no matching session exists — a
 *   missing session is an expected outcome (a stale id, an already-revoked
 *   session that was pruned), not an error.
 * - `findActiveByUserId` returns only sessions that are neither revoked nor
 *   expired as of `now`, ordered oldest-`lastActiveAt`-first. That ordering
 *   is load-bearing: `IssueSession`'s concurrent-session-limit enforcement
 *   (Issue 094) evicts from the front of this list, and a repository that
 *   returned an unspecified order would make eviction pick an arbitrary
 *   session instead of the least-recently-active one.
 * - `save` is an idempotent upsert, exactly like `UserRepository.save`.
 */
export interface SessionRepository {
  findById(id: SessionId): Promise<Session | undefined>;
  findActiveByUserId(userId: SessionUserId, now: Date): Promise<readonly Session[]>;
  save(session: Session): Promise<void>;
}
