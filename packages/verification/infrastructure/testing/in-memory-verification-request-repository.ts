import { Result } from "@verixa/shared-kernel";

import type {
  ClaimNextInReviewParams,
  ClaimNextOutcome,
  QueueAssignmentFilter,
  QueueCandidateOptions,
  VerificationRequestRepository,
} from "../../application/ports/verification-request-repository.js";
import type { ReviewerId } from "../../domain/entities/review-assignment.js";
import type {
  VerificationRequest,
  VerificationRequestId,
  VerificationSubjectId,
} from "../../domain/entities/verification-request.js";

/**
 * A `VerificationRequestRepository` backed by a `Map`, satisfying the same
 * port a real Postgres adapter does. Exists so the claim and decision use
 * cases can be tested without a database.
 *
 * ## Why the fake can honour an atomicity guarantee
 *
 * JavaScript runs one turn of the event loop at a time, and every method here
 * is synchronous inside its `async` wrapper. `claimNextInReview` therefore
 * reads the candidate, transitions it, and writes it back with no `await` in
 * between — no other call can interleave, so two concurrent attempts from two
 * reviewers cannot observe the same candidate. That is a *simulation* of the
 * guarantee, not a proof of it: it says nothing about whether the SQL adapter
 * actually locks. The real race is exercised against Postgres in
 * `prisma-verification-request-repository.spec.ts`, which is where the
 * guarantee genuinely lives. See `docs/guides/testing.md`.
 */
export class InMemoryVerificationRequestRepository implements VerificationRequestRepository {
  private readonly requests = new Map<VerificationRequestId, VerificationRequest>();

  save(request: VerificationRequest): Promise<void> {
    this.requests.set(request.id, request);
    return Promise.resolve();
  }

  findById(id: VerificationRequestId): Promise<VerificationRequest | undefined> {
    return Promise.resolve(this.requests.get(id));
  }

  findBySubject(subjectUserId: VerificationSubjectId): Promise<VerificationRequest[]> {
    return Promise.resolve(
      [...this.requests.values()]
        .filter((request) => request.subjectUserId === subjectUserId)
        .sort(byCreatedAt),
    );
  }

  findQueueCandidates(options: QueueCandidateOptions = {}): Promise<VerificationRequest[]> {
    const offset = options.offset ?? 0;
    const now = options.now ?? new Date();

    let rows = [...this.requests.values()]
      .filter(
        (request) =>
          (options.statuses === undefined || options.statuses.includes(request.status.value)) &&
          (options.verificationType === undefined ||
            request.type.value === options.verificationType) &&
          matchesAssignment(request, options.assignment ?? "any", now),
      )
      .sort(byCreatedAt);

    if (offset > 0) {
      rows = rows.slice(offset);
    }
    if (options.limit !== undefined) {
      rows = rows.slice(0, options.limit);
    }

    return Promise.resolve(rows);
  }

  findActiveClaimByReviewer(
    reviewerId: ReviewerId,
    now: Date,
  ): Promise<VerificationRequest | undefined> {
    return Promise.resolve(this.activeClaimOf(reviewerId, now));
  }

  claimNextInReview(params: ClaimNextInReviewParams): Promise<ClaimNextOutcome> {
    // No `await` anywhere below: see the class comment on why that is what
    // makes this atomic in a single-threaded runtime.
    if (params.oneAtATime && this.activeClaimOf(params.reviewerId, params.now) !== undefined) {
      return Promise.resolve({ kind: "already_claiming" });
    }

    const candidate = [...this.requests.values()]
      .filter((request) => request.isClaimableAt(params.now))
      .sort(byCreatedAt)[0];

    if (candidate === undefined) {
      return Promise.resolve({ kind: "none" });
    }

    const claimed = candidate.claimBy({
      reviewerId: params.reviewerId,
      now: params.now,
      ttlMs: params.claimTtlMs,
    });

    if (Result.isErr(claimed)) {
      // Unreachable in this fake — nothing can claim the candidate between
      // the filter above and here — but returning `none` rather than throwing
      // keeps the fake's behaviour identical to the adapter's on a lost race.
      return Promise.resolve({ kind: "none" });
    }

    this.requests.set(claimed.value.id, claimed.value);
    return Promise.resolve({ kind: "claimed", request: claimed.value });
  }

  private activeClaimOf(reviewerId: ReviewerId, now: Date): VerificationRequest | undefined {
    return [...this.requests.values()].find(
      (request) =>
        request.assignment !== undefined &&
        request.assignment.isActiveAt(now) &&
        request.assignment.isHeldBy(reviewerId),
    );
  }
}

/**
 * Whether `request` belongs on the requested side of the queue's claim state.
 *
 * A claim counts as an assignment only while its lease is live — the same rule
 * `VerificationRequest.isClaimableAt` applies, restated here because the fake
 * answers a filter over a whole collection rather than one row at a time.
 */
function matchesAssignment(
  request: VerificationRequest,
  filter: QueueAssignmentFilter,
  now: Date,
): boolean {
  if (filter === "any") {
    return true;
  }

  const claim = request.assignment;
  const assigned = claim !== undefined && claim.isActiveAt(now);
  return filter === "assigned" ? assigned : !assigned;
}

function byCreatedAt(a: VerificationRequest, b: VerificationRequest): number {
  return a.createdAt.getTime() - b.createdAt.getTime();
}
