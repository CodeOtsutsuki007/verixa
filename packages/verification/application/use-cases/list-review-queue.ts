import { Result, ValidationError, ValidationErrorAggregator } from "@verixa/shared-kernel";

import type { ReviewerId } from "../../domain/entities/review-assignment.js";
import type {
  VerificationOrganizationId,
  VerificationRequest,
  VerificationRequestId,
  VerificationSubjectId,
} from "../../domain/entities/verification-request.js";
import type { VerificationStatusValue } from "../../domain/value-objects/verification-status.js";
import type { VerificationTypeValue } from "../../domain/value-objects/verification-type.js";
import type {
  QueueAssignmentFilter,
  VerificationRequestRepository,
} from "../ports/verification-request-repository.js";

/** Rows per page when the caller does not ask for a size. */
export const DEFAULT_QUEUE_PAGE_SIZE = 25;

/**
 * The largest page a caller may ask for.
 *
 * A ceiling rather than an unbounded `limit` because the page size is the
 * caller's to choose only within what the store can serve in one query; a
 * `limit: 100000` is not a page, it is a full table read wearing a page's
 * clothes, and it would arrive as one large response the UI cannot render.
 */
export const MAX_QUEUE_PAGE_SIZE = 100;

/**
 * The statuses a queue page may contain.
 *
 * `submitted` (waiting on the automated check, Issue 172) and `in_review`
 * (waiting on a reviewer) are the only two states that represent work someone
 * can pick up. `pending_evidence` is the subject's turn, `needs_more_info` has
 * been handed back to them, and `approved`/`rejected` are history — listing any
 * of those would fill a reviewer's queue with rows no reviewer action exists
 * for.
 */
const REVIEWABLE_STATUSES: readonly VerificationStatusValue[] = ["submitted", "in_review"];

export interface ListReviewQueueQuery {
  /**
   * Narrows the page to one reviewable status. Omitted means both of
   * `REVIEWABLE_STATUSES`.
   *
   * A non-reviewable status is rejected rather than answered with an empty
   * page: "the queue is empty" and "you asked the queue for decided requests"
   * are different answers to different questions, and only one of them is
   * something the caller can act on.
   */
  readonly status?: VerificationStatusValue | undefined;
  readonly verificationType?: VerificationTypeValue | undefined;
  /** Defaults to `"any"` — claimed and unclaimed requests together. */
  readonly assignment?: QueueAssignmentFilter | undefined;
  readonly limit?: number | undefined;
  readonly offset?: number | undefined;
  /** Injected clock for tests; defaults to `new Date()`. Used to tell a live claim from a lapsed one. */
  readonly now?: Date | undefined;
}

/**
 * The live claim on a queue row, if there is one.
 *
 * Absent — not `null` — when the request is unclaimed *or* its lease has
 * lapsed, because a reviewer looking for the next case cannot act differently
 * on those two situations.
 */
export interface ReviewQueueClaim {
  readonly reviewerId: ReviewerId;
  readonly claimedAt: Date;
  readonly expiresAt: Date;
}

/**
 * One row of the reviewer queue: enough to render the list and to decide which
 * case to open, and deliberately nothing more.
 *
 * ## What is not here, and why
 *
 * No evidence. Not the storage reference, not the checksum, and not a signed
 * URL. A queue row is a summary — the reviewer opening a case is a separate
 * fetch (Issue 178's per-request detail route), and that is where a document
 * is actually looked at.
 *
 * The alternative rejected was a `includeEvidenceUrls` flag on this query, on
 * the grounds that the issue calls for signed URLs "only on demand". A flag
 * cannot deliver that here: the port that mints a signed URL is
 * `EvidenceStorage` (Issue 166), which does not exist yet, so the flag would
 * either be a parameter that silently does nothing or a dependency of the
 * queue read on a storage adapter it otherwise never touches. Signing belongs
 * on the detail path, where the URL is rendered, rather than in a list where
 * every row would be signed for a view that never shows one.
 */
export interface ReviewQueueItem {
  readonly requestId: VerificationRequestId;
  readonly subjectUserId: VerificationSubjectId;
  readonly organizationId: VerificationOrganizationId;
  readonly verificationType: VerificationTypeValue;
  readonly status: VerificationStatusValue;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly claim: ReviewQueueClaim | undefined;
}

/** One page of the queue, plus what the caller needs to ask for the next one. */
export interface ReviewQueuePage {
  readonly items: readonly ReviewQueueItem[];
  readonly limit: number;
  readonly offset: number;
  /**
   * Whether at least one more row exists after this page.
   *
   * Derived by asking the store for one row more than the page size, not by a
   * second `COUNT(*)` query. A count is a second round-trip over the same
   * predicate, and on a queue that changes while it is being read it is also
   * the wrong number — the count and the page would be read at different
   * instants, so `hasMore` could disagree with the rows actually returned. The
   * extra row costs one row of read and cannot disagree with itself.
   */
  readonly hasMore: boolean;
}

/**
 * Lists the reviewer queue: reviewable work, oldest first, filtered and
 * paginated.
 *
 * ## Why this returns a page object and not an array of requests
 *
 * Everything the reviewer queue UI (Issue 178) needs to render a row has to
 * come out of one query, and everything it must *not* have — evidence bytes,
 * storage references, decision notes — has to be structurally absent rather
 * than merely unused. Returning the aggregates and letting the caller pick
 * fields would make "the API response carries no evidence pointer" a property
 * of whichever serializer happens to be written later, which is the wrong
 * place for it. The projection happens here, once, where it can be tested. See
 * Issue 095 for the same read-model-shaped-for-its-consumer principle applied
 * to a different list.
 *
 * ## Why the filtering is not done here
 *
 * `status`, `verificationType`, `assignment`, `limit` and `offset` are all
 * passed to the repository, not applied to results after they come back. A
 * use case that fetched a page and then filtered it would return short pages —
 * "25 rows were asked for, three came back" — and would silently skip rows that
 * a later page should have contained, because the rows dropped by the filter
 * were already counted against `limit`. The store has the index for this; the
 * use case does not have the data set.
 *
 * What is *not* delegated is the ordering the pagination depends on: the port
 * promises oldest-first, and `offset` is only a stable cursor because it does.
 */
export class ListReviewQueue {
  constructor(private readonly requests: VerificationRequestRepository) {}

  async execute(
    query: ListReviewQueueQuery = {},
  ): Promise<Result<ReviewQueuePage, ValidationError>> {
    const now = query.now ?? new Date();
    const errors = new ValidationErrorAggregator();

    const statuses = resolveStatuses(query.status, errors);

    const limit = query.limit ?? DEFAULT_QUEUE_PAGE_SIZE;
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_QUEUE_PAGE_SIZE) {
      errors.merge({
        limit: [`must be an integer between 1 and ${MAX_QUEUE_PAGE_SIZE}`],
      });
    }

    const offset = query.offset ?? 0;
    if (!Number.isInteger(offset) || offset < 0) {
      errors.merge({ offset: ["must be a non-negative integer"] });
    }

    if (errors.hasErrors()) {
      return Result.err(errors.toError("The review queue query is invalid."));
    }

    // One row beyond the page, so `hasMore` costs a row rather than a count.
    const rows = await this.requests.findQueueCandidates({
      statuses,
      verificationType: query.verificationType,
      assignment: query.assignment,
      now,
      limit: limit + 1,
      offset,
    });

    const hasMore = rows.length > limit;
    const items = (hasMore ? rows.slice(0, limit) : rows).map((request) =>
      toQueueItem(request, now),
    );

    return Result.ok({ items, limit, offset, hasMore });
  }
}

/**
 * The statuses this query lists, recording a field error instead when the
 * caller asked for a status the queue does not list.
 */
function resolveStatuses(
  status: VerificationStatusValue | undefined,
  errors: ValidationErrorAggregator,
): readonly VerificationStatusValue[] | undefined {
  if (status === undefined) {
    return REVIEWABLE_STATUSES;
  }
  if (!REVIEWABLE_STATUSES.includes(status)) {
    errors.merge({ status: ["not_reviewable"] });
    return undefined;
  }
  return [status];
}

/**
 * Projects a request onto a queue row, dropping a claim that has lapsed.
 *
 * `assignment: "any"` lists requests whose claim has expired on purpose — they
 * are back in the queue and a reviewer should see them. But the expired lease
 * is not an assignment, and reporting it would tell the UI a case is taken when
 * it is free to claim. The row reports the claim only while it is live at
 * `now`, which is the same question `VerificationRequest.isClaimableAt` asks.
 */
function toQueueItem(request: VerificationRequest, now: Date): ReviewQueueItem {
  const claim = request.assignment;

  return {
    requestId: request.id,
    subjectUserId: request.subjectUserId,
    organizationId: request.organizationId,
    verificationType: request.type.value,
    status: request.status.value,
    createdAt: request.createdAt,
    updatedAt: request.updatedAt,
    claim:
      claim === undefined || !claim.isActiveAt(now)
        ? undefined
        : {
            reviewerId: claim.reviewerId,
            claimedAt: claim.assignedAt,
            expiresAt: claim.claimExpiresAt,
          },
  };
}
