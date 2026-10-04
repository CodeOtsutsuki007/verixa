import { BaseDomainEvent } from "@verixa/shared-kernel";

import type { ReviewerId } from "../entities/review-assignment.js";
import type {
  VerificationOrganizationId,
  VerificationRequestId,
  VerificationSubjectId,
} from "../entities/verification-request.js";
import type { VerificationTypeValue } from "../value-objects/verification-type.js";

/** The two terminal outcomes of a review. `needs_more_info` is not a decision — it re-opens the request. */
export type VerificationDecisionValue = "approved" | "rejected";

export interface VerificationDecidedParams {
  readonly requestId: VerificationRequestId;
  readonly subjectUserId: VerificationSubjectId;
  readonly organizationId: VerificationOrganizationId;
  readonly verificationType: VerificationTypeValue;
  readonly decision: VerificationDecisionValue;
  readonly decidedBy: ReviewerId;
  readonly decidedAt: Date;
  readonly note: string;
}

/**
 * A reviewer reached a terminal decision on a request.
 *
 * ## Why it carries more than the request id
 *
 * The audit trail (Phase 10) is the primary consumer, and it records an event
 * *after the fact*, possibly in a different process, possibly days later if
 * delivery was retried. An event holding only `requestId` would force the
 * audit writer to make a follow-up query to learn what was decided, by whom,
 * and why — and that query would read the request's *current* state, which may
 * already have moved on (a re-opened request, a re-run of the queue). The
 * event would then be recorded against a state that never existed.
 *
 * So the event is self-contained and immutable: it is a statement about what
 * happened at a moment, and it stays true regardless of what the aggregate
 * does next. `note` is included specifically because the rationale is the
 * thing a regulator or a subject dispute actually turns on — see Issue 175.
 */
export class VerificationDecided extends BaseDomainEvent {
  readonly eventName = "verification.request.decided";
  readonly subjectUserId: VerificationSubjectId;
  readonly organizationId: VerificationOrganizationId;
  readonly verificationType: VerificationTypeValue;
  readonly decision: VerificationDecisionValue;
  readonly decidedBy: ReviewerId;
  readonly decidedAt: Date;
  readonly note: string;

  constructor(params: VerificationDecidedParams) {
    super(params.requestId);
    this.subjectUserId = params.subjectUserId;
    this.organizationId = params.organizationId;
    this.verificationType = params.verificationType;
    this.decision = params.decision;
    this.decidedBy = params.decidedBy;
    this.decidedAt = params.decidedAt;
    this.note = params.note;
  }
}
