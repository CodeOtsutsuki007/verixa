import { Result, type Id } from "@verixa/shared-kernel";

export type VerificationRequestId = Id<"VerificationRequestId">;
export type ReviewerId = Id<"ReviewerId">;

export interface ReviewAssignmentProps {
import { type Id, Result, ValidationError } from "@verixa/shared-kernel";

import type { VerificationRequestId } from "./verification-request.js";

export type ReviewerId = Id<"ReviewerId">;

/**
 * How long a reviewer's claim on a case lasts before it is automatically
 * released back to the queue.
 *
 * Fifteen minutes is a deliberately unglamorous number: long enough to read a
 * document and a selfie, short enough that a reviewer whose browser tab dies
 * mid-review does not hold a case hostage for the rest of the day. A lease
 * rather than a permanent lock — see the class comment.
 */
export const DEFAULT_CLAIM_TTL_MS = 15 * 60 * 1000;

interface ReviewAssignmentProps {
  readonly requestId: VerificationRequestId;
  readonly reviewerId: ReviewerId;
  readonly assignedAt: Date;
  readonly claimExpiresAt: Date;
}

/**
 * Represents a reviewer's temporary optimistic lease (claim) on a verification
 * request in the review queue. Prevents multiple reviewers from working the
 * same case simultaneously and auto-releases stale claims when sessions expire.
 */

 * A reviewer's temporary claim on one request in the queue.
 *
 * Modelled explicitly, and as an *expiring lease* rather than a boolean
 * `isClaimed` flag, because both halves of that choice prevent a real failure:
 *
 * - Explicit: "who owns this case right now" is a first-class value the queue
 *   can query, not an implicit consequence of some other field. Two reviewers
 *   working the same case is a race the domain should be able to detect and
 *   refuse (see `VerificationRequest.claimBy`), not a mystery to debug.
 * - Expiring: a permanent lock means a reviewer who closes their laptop
 *   leaves the case unworkable forever, with nothing in the system able to
 *   notice. An expiry releases itself, the same way a credential lockout
 *   uses an expiry rather than a flag (see `docs/security/authentication-flows.md`).
 *
 * This is a value object: once claimed, a claim is replaced, never mutated.
 */
export class ReviewAssignment {
  readonly requestId: VerificationRequestId;
  readonly reviewerId: ReviewerId;
  readonly assignedAt: Date;
  readonly claimExpiresAt: Date;

  private constructor(props: ReviewAssignmentProps) {
    this.requestId = props.requestId;
    this.reviewerId = props.reviewerId;
    this.assignedAt = props.assignedAt;
    this.claimExpiresAt = props.claimExpiresAt;
  }

  static create(props: ReviewAssignmentProps): Result<ReviewAssignment, Error> {
    if (props.claimExpiresAt <= props.assignedAt) {
      return Result.err(new Error("Claim expiration must be later than assignment time"));
    }
    return Result.ok(new ReviewAssignment(props));
  }

  isExpired(now: Date = new Date()): boolean {
    return now >= this.claimExpiresAt;
  }

  isActive(now: Date = new Date()): boolean {
    return !this.isExpired(now);
  }

  extend(newExpiry: Date): Result<ReviewAssignment, Error> {
    if (newExpiry <= this.assignedAt) {
      return Result.err(new Error("New claim expiration must be later than assignment time"));
    }
    return Result.ok(
      new ReviewAssignment({
        requestId: this.requestId,
        reviewerId: this.reviewerId,
        assignedAt: this.assignedAt,
        claimExpiresAt: newExpiry,
      }),
    );
  /**
   * Creates a claim of `requestId` by `reviewerId`, expiring `ttlMs` after
   * `assignedAt`.
   *
   * `assignedAt` is passed in rather than read from the clock so the claim and
   * the expiry derive from the same instant — computing them separately is
   * how a claim ends up a few milliseconds shorter or longer than intended in
   * a way no test can pin down.
   */
  static claim(params: {
    requestId: VerificationRequestId;
    reviewerId: ReviewerId;
    assignedAt: Date;
    ttlMs?: number | undefined;
  }): Result<ReviewAssignment, ValidationError> {
    const ttlMs = params.ttlMs ?? DEFAULT_CLAIM_TTL_MS;

    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      return Result.err(
        new ValidationError("Claim duration must be a positive number of milliseconds.", {
          claimTtlMs: ["invalid"],
        }),
      );
    }

    return Result.ok(
      new ReviewAssignment({
        requestId: params.requestId,
        reviewerId: params.reviewerId,
        assignedAt: params.assignedAt,
        claimExpiresAt: new Date(params.assignedAt.getTime() + ttlMs),
      }),
    );
  }

  /** Rebuilds from already-trusted data (e.g. a database row). */
  static reconstitute(props: ReviewAssignmentProps): ReviewAssignment {
    return new ReviewAssignment(props);
  }

  /** Whether the claim is still held at `now` — i.e. it has not expired. */
  isActiveAt(now: Date): boolean {
    return now.getTime() < this.claimExpiresAt.getTime();
  }

  /** Whether the claim has lapsed at `now` and the case is back in the queue. */
  isExpiredAt(now: Date): boolean {
    return !this.isActiveAt(now);
  }

  /** Whether `reviewerId` is the reviewer holding this claim. */
  isHeldBy(reviewerId: ReviewerId): boolean {
    return this.reviewerId === reviewerId;
  }
}
