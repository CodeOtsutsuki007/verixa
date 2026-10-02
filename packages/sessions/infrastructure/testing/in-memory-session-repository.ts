import type { Session, SessionId, UserId } from "../../domain/entities/session.js";
import type { SessionRepository } from "../../application/ports/session-repository.js";

/**
 * In-memory implementation of SessionRepository, backed by a Map.
 *
 * Suitable for unit and integration tests of session use cases before real
 * persistence exists. Correctly implements the "active" semantics, revoke
 * idempotency, and all other contract details documented in the port — the
 * behavior must match the port's prose exactly, since the whole point is that
 * this fake and a future real adapter must behave identically from the
 * caller's perspective.
 *
 * Not thread-safe; this is a test fake, not production code.
 */
export class InMemorySessionRepository implements SessionRepository {
  private readonly sessions = new Map<string, Session>();

  async save(session: Session): Promise<void> {
    // Idempotent upsert: store the session state as-is, overwriting any
    // previous version.
 * In-memory implementation of `SessionRepository`, suitable for unit tests.
 *
 * Stores sessions in a Map keyed by session ID. Used alongside the contract
 * test suite (session-repository.contract.ts) to verify that the port's
 * behavioral contract is unambiguous — if both the in-memory fake and a
 * real database adapter pass the same tests, they both behave the same way.
 */
export class InMemorySessionRepository implements SessionRepository {
  private sessions = new Map<SessionId, Session>();

  async save(session: Session): Promise<void> {
    this.sessions.set(session.id, session);
  }

  async findById(sessionId: SessionId): Promise<Session | undefined> {
    return this.sessions.get(sessionId);
  }

  async findActiveByUserId(userId: UserId): Promise<Session[]> {
    const now = new Date();
    const active = Array.from(this.sessions.values())
      .filter(
        (session) =>
          session.userId === userId &&
          !session.isRevoked() &&
          !session.isExpired(now),
      )
      // Sort by lastSeenAt descending (most recently active first)
      .sort((a, b) => b.lastSeenAt.getTime() - a.lastSeenAt.getTime());

    return active;
    return Array.from(this.sessions.values()).filter((session) => {
      // Active means: status is "active" AND not expired
      return session.status === "active" && !session.isExpired(now);
    });
  }

  async revoke(sessionId: SessionId): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) {
      // Revoke is idempotent: calling revoke() on an already-revoked session
      // returns the same instance unchanged (per Session.revoke() semantics).
      const revoked = session.revoke();
      this.sessions.set(sessionId, revoked);
    }
    // If the session doesn't exist, this is a silent no-op (idempotent).
  }

  async revokeAllForUser(userId: UserId): Promise<void> {
    // Iterate over all sessions for this user and revoke each one.
    const sessionsToRevoke = Array.from(this.sessions.entries()).filter(
      ([, session]) => session.userId === userId,
    );

    for (const [sessionId, session] of sessionsToRevoke) {
      // Revoke is idempotent, so re-revoking an already-revoked session is safe.
      const revoked = session.revoke();
      this.sessions.set(sessionId, revoked);
    if (session && !session.isRevoked()) {
      // Create a new revoked session and replace the old one
      this.sessions.set(sessionId, session.revoke());
    }
  }

  async revokeAllForUser(userId: UserId): Promise<void> {
    // Find all sessions for this user and revoke each one
    const sessionsToRevoke: SessionId[] = [];
    for (const [id, session] of this.sessions) {
      if (session.userId === userId && !session.isRevoked()) {
        sessionsToRevoke.push(id);
      }
    }

    for (const id of sessionsToRevoke) {
      await this.revoke(id);
    }
import type { SessionRepository } from "../../application/ports/session-repository.js";
import type { Session, SessionId, SessionUserId } from "../../domain/entities/session.js";

/**
 * A `SessionRepository` backed by an in-memory `Map`, satisfying the exact
 * same port a real (Prisma-backed) adapter will. Exists so use cases and
 * their tests never need a database — see `InMemoryUserRepository` in
 * `@verixa/identity` for the identical pattern.
 */
export class InMemorySessionRepository implements SessionRepository {
  private readonly sessionsById = new Map<SessionId, Session>();

  findById(id: SessionId): Promise<Session | undefined> {
    return Promise.resolve(this.sessionsById.get(id));
  }

  /**
   * Active means neither revoked nor expired as of `now`, sorted
   * oldest-`lastActiveAt`-first — the ordering `IssueSession`'s
   * concurrent-session-limit eviction depends on. See the port doc.
   */
  findActiveByUserId(userId: SessionUserId, now: Date): Promise<readonly Session[]> {
    const active = [...this.sessionsById.values()]
      .filter((session) => session.userId === userId && session.isActiveAt(now))
      .sort((a, b) => a.lastActiveAt.getTime() - b.lastActiveAt.getTime());
    return Promise.resolve(active);
  }

  save(session: Session): Promise<void> {
    this.sessionsById.set(session.id, session);
    return Promise.resolve();
  }
}
