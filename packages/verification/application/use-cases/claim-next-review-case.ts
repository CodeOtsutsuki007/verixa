import { DEFAULT_CLAIM_TTL_MS, type ReviewerId } from "../../domain/entities/review-assignment.js";
import type {
  ClaimNextOutcome,
  VerificationRequestRepository,
} from "../ports/verification-request-repository.js";

export interface ClaimNextReviewCaseCommand {
  readonly reviewerId: ReviewerId;
  /** Injected clock for tests; defaults to `new Date()`. */
  readonly now?: Date;
}

/**
 * Queue policy, configurable per composition root rather than hard-coded, so
 * a deployment can run strict one-case-per-reviewer or allow a reviewer to
 * stack a few cases while they wait on slow evidence.
 */
export interface ClaimNextReviewCasePolicy {
  /** How long the resulting claim lives. Defaults to `ReviewAssignment`'s fifteen minutes. */
  readonly claimTtlMs?: number;
  /** When `true` (the default), a reviewer holding any active claim is refused another. */
  readonly oneAtATime?: boolean;
}

/**
 * Hands the oldest claimable `in_review` request to the calling reviewer.
 *
 * ## Why this is not "list the queue and pick one"
 *
 * A shared list that reviewers browse and click is the obvious design and the
 * wrong one: two reviewers open the same case, both start work, and whichever
 * saves last silently overwrites the other. The collision is invisible in
 * development (one reviewer) and routine in production (many).
 *
 * So the *assignment* happens inside the repository, atomically, over a
 * locked candidate row. This use case stays deliberately thin — it owns the
 * policy (how long a claim lasts, whether one case at a time) and nothing
 * else, because the part that must be race-free cannot be expressed in
 * application code at all. See the port's `claimNextInReview` contract.
 *
 * The outcome is returned, not thrown: an empty queue and "you already hold a
 * case" are both ordinary, and neither is an error.
 */
export class ClaimNextReviewCase {
  constructor(
    private readonly requests: VerificationRequestRepository,
    private readonly policy: ClaimNextReviewCasePolicy = {},
  ) {}

  async execute(command: ClaimNextReviewCaseCommand): Promise<ClaimNextOutcome> {
    return this.requests.claimNextInReview({
      reviewerId: command.reviewerId,
      now: command.now ?? new Date(),
      claimTtlMs: this.policy.claimTtlMs ?? DEFAULT_CLAIM_TTL_MS,
      // One at a time by default. Fairness across reviewers is better served by
      // making someone finish a case than by letting the fastest clicker stack
      // the queue, and it bounds how much a vanished reviewer can hold.
      oneAtATime: this.policy.oneAtATime ?? true,
    });
  }
}
