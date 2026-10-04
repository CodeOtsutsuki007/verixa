import { DomainError } from "@verixa/shared-kernel";

import type { VerificationRequestId } from "../entities/verification-request.js";

/**
 * A reviewer tried to decide (approve, reject, or ask for more information)
 * a request they do not hold an active claim on.
 *
 * 403 rather than 409: the caller is not permitted to make this decision on
 * this resource right now. That is an authorization outcome, and it is
 * deliberately distinct from `InvalidStatusTransitionError` — "someone else
 * owns this case" is an operational fact a queue UI should retry around,
 * while "the request is already decided" is final and should not.
 *
 * Note that this is *claim* authorization, not role authorization: whether
 * the caller has the reviewer role at all is Phase 07's RBAC concern, checked
 * before the use case is reached. This error is about the specific case.
 */
export class ReviewDecisionNotPermittedError extends DomainError {
  readonly code = "REVIEW_DECISION_NOT_PERMITTED";
  readonly httpStatusHint = 403;
  readonly requestId: VerificationRequestId;

  constructor(requestId: VerificationRequestId) {
    super(
      `Reviewer does not hold an active claim on verification request ${requestId}, so cannot decide it.`,
    );
    this.requestId = requestId;
  }

  override toJSON(): ReturnType<DomainError["toJSON"]> & { requestId: string } {
    return { ...super.toJSON(), requestId: this.requestId };
  }
}
