import { DomainError } from "@verixa/shared-kernel";

import type { VerificationStatusValue } from "../value-objects/verification-status.js";

/**
 * A status change the request's state machine does not permit — deciding an
 * unclaimed request, re-deciding a terminal one, submitting evidence for a
 * request that is already under review.
 *
 * Returned rather than thrown, because an illegal transition is a *rejected
 * request* from the caller's point of view, not a broken invariant: two
 * reviewers racing to approve the same case is routine, and the loser should
 * receive a clear conflict rather than a 500. See `docs/guides/error-handling.md`.
 *
 * 409 rather than 400: the request was well-formed and the caller was allowed
 * to make it, but the resource's current state refuses it — the definition of
 * a conflict. A 400 would say the *input* was wrong, which would send a client
 * to fix a field that has nothing to do with the problem.
 */
export class InvalidStatusTransitionError extends DomainError {
  readonly code = "INVALID_STATUS_TRANSITION";
  readonly httpStatusHint = 409;
  readonly from: VerificationStatusValue;
  readonly to: string;

  constructor(from: VerificationStatusValue, to: string) {
    super(`Cannot transition verification request from "${from}" to "${to}".`);
    this.from = from;
    this.to = to;
  }

  override toJSON(): ReturnType<DomainError["toJSON"]> & { from: string; to: string } {
    return { ...super.toJSON(), from: this.from, to: this.to };
  }
}
