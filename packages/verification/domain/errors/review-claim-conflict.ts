import { DomainError } from "@verixa/shared-kernel";

import type { ReviewerId } from "../entities/review-assignment.js";
import type { VerificationRequestId } from "../entities/verification-request.js";

/**
 * A claim was attempted on a request that another reviewer is already
 * actively working.
 *
 * A conflict, not a validation failure: the caller's request was fine, and
 * the case existed; the queue simply moved on. Returning this rather than
 * silently overwriting the existing claim is the whole point of the
 * assignment model — two reviewers must never be looking at the same case
 * believing they own it.
 */
export class ReviewClaimConflictError extends DomainError {
  readonly code = "REVIEW_CLAIM_CONFLICT";
  readonly httpStatusHint = 409;
  readonly requestId: VerificationRequestId;
  readonly heldBy: ReviewerId;

  constructor(requestId: VerificationRequestId, heldBy: ReviewerId) {
    super(`Verification request ${requestId} is already claimed by reviewer ${heldBy}.`);
    this.requestId = requestId;
    this.heldBy = heldBy;
  }

  override toJSON(): ReturnType<DomainError["toJSON"]> & { requestId: string; heldBy: string } {
    return { ...super.toJSON(), requestId: this.requestId, heldBy: this.heldBy };
  }
}
