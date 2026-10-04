import type { ReviewerId } from "../../domain/entities/review-assignment.js";
import type {
  VerificationRequest,
  VerificationRequestId,
  VerificationSubjectId,
} from "../../domain/entities/verification-request.js";
import type { VerificationStatusValue } from "../../domain/value-objects/verification-status.js";
import type { VerificationTypeValue } from "../../domain/value-objects/verification-type.js";

/**
 * Which side of the queue's claim state a listing wants.
 *
 * Three values rather than a boolean, so "the UI has no filter selected" is
 * stated (`"any"`) rather than inferred from an absent field — inferred
 * absence is exactly how a filter ends up silently applied by one adapter and
 * silently ignored by another.
 */
export type QueueAssignmentFilter = "any" | "assigned" | "unassigned";

/**
 * Filters for the reviewer queue listing (Issues 163 and 177). Applied by the
 * store, not by the caller — see `findQueueCandidates`.
 *
 * ## Why `statuses` is a set and not a single status
 *
 * The queue's default view spans two statuses: a `submitted` request is
 * waiting for its automated check (Issue 172) and an `in_review` one is
 * waiting for a reviewer. Asking the store twice — once per status — and
 * merging the two pages in the caller cannot produce a stable global order:
 * each page is ordered `createdAt ASC` independently, so the caller ends up
 * re-sorting a partial view and `offset` stops meaning "rows 26–50 of the
 * queue". One query over one `(status, created_at)` index is both correct and
 * cheaper.
 *
 * ## Why `assignment` needs `now`
 *
 * A claim is a lease, not a lock (see `ReviewAssignment`), so a request whose
 * `claim_expires_at` has passed is back in the unassigned queue even though
 * its `assigned_reviewer_id` column is still populated. Evaluating that needs
 * the current instant, which the caller supplies rather than each adapter
 * reading its own clock — the same convention `findActiveClaimByReviewer`
 * already uses.
 */
export interface QueueCandidateOptions {
  /** Statuses to include. Omitted means every status; a queue listing should pass only the statuses it considers reviewable. */
  readonly statuses?: readonly VerificationStatusValue[] | undefined;
  readonly verificationType?: VerificationTypeValue | undefined;
  /** Defaults to `"any"` — both claimed and unclaimed requests. */
  readonly assignment?: QueueAssignmentFilter | undefined;
  /** The instant `assignment` is evaluated at. Omitted means the adapter reads the clock itself, once. */
  readonly now?: Date | undefined;
  readonly limit?: number | undefined;
  readonly offset?: number | undefined;
}

/**
 * What an atomic "claim the next case" attempt concluded.
 *
 * A discriminated union rather than `VerificationRequest | undefined` because
 * "there is nothing to claim" and "you already hold a case" need different
 * responses from the caller's side (idle, versus finish your current case
 * first), and collapsing them would force the use case to re-query to tell
 * them apart.
 */
export type ClaimNextOutcome =
  | { readonly kind: "claimed"; readonly request: VerificationRequest }
  | { readonly kind: "none" }
  | { readonly kind: "already_claiming" };

export interface ClaimNextInReviewParams {
  readonly reviewerId: ReviewerId;
  readonly now: Date;
  /** Lease length for the claim taken. See `ReviewAssignment`. */
  readonly claimTtlMs: number;
  /** When `true`, a reviewer holding any active claim is refused rather than given a second one. */
  readonly oneAtATime: boolean;
}

/**
 * The persistence contract for `VerificationRequest` — the port half of
 * ports & adapters. No Prisma, SQL, or locking primitive appears in this
 * interface; the adapter is free to use `SELECT ... FOR UPDATE SKIP LOCKED`
 * (and the Prisma adapter does) without any of it leaking upward. See
 * `docs/guides/domain-modeling.md`.
 *
 * Method contracts:
 * - `findById`/`findBySubject`/`findQueueCandidates` return an empty result
 *   for "nothing matched" — an absent request is an expected outcome, not a
 *   `Result` error.
 * - `save` is an idempotent upsert on the request id, exactly like every
 *   other repository in this codebase.
 * - `claimNextInReview` **must be atomic**. Two concurrent calls with
 *   different reviewers must never return the same request, and a reviewer
 *   must never end up holding two cases when `oneAtATime` is set. The port
 *   states the guarantee, not the mechanism; an in-memory fake can satisfy it
 *   by running to completion synchronously, and a SQL adapter by locking the
 *   candidate row(s) it selects. See `docs/guides/use-cases.md`.
 * - `findActiveClaimByReviewer` reports a request only when the claim is
 *   still live at the supplied `now`; an expired claim is not a claim.
 */
export interface VerificationRequestRepository {
  save(request: VerificationRequest): Promise<void>;

  findById(id: VerificationRequestId): Promise<VerificationRequest | undefined>;

  findBySubject(subjectUserId: VerificationSubjectId): Promise<VerificationRequest[]>;

  /**
   * Queue listing, oldest first. Detail beyond summary fields is fetched per
   * request.
   *
   * Filtering and pagination both belong here rather than to the calling use
   * case: a caller that fetched a page and then filtered it would return short
   * pages and skip rows that a later page should have contained.
   */
  findQueueCandidates(options?: QueueCandidateOptions): Promise<VerificationRequest[]>;

  /** The request `reviewerId` currently holds an unexpired claim on, if any. */
  findActiveClaimByReviewer(
    reviewerId: ReviewerId,
    now: Date,
  ): Promise<VerificationRequest | undefined>;

  /**
   * Atomically assigns the oldest claimable `in_review` request to
   * `reviewerId`, returning what happened. Never throws for a contested or
   * empty queue — those are the `already_claiming` and `none` outcomes.
   */
  claimNextInReview(params: ClaimNextInReviewParams): Promise<ClaimNextOutcome>;
}
