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
