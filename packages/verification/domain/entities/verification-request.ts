import {
  createId,
  type DomainEvent,
  type Id,
  Result,
  ValidationError,
} from "@verixa/shared-kernel";

import { InvalidStatusTransitionError } from "../errors/invalid-status-transition.js";
import { ReviewClaimConflictError } from "../errors/review-claim-conflict.js";
import { ReviewDecisionNotPermittedError } from "../errors/review-decision-not-permitted.js";
import { VerificationDecided } from "../events/verification-decided.js";
import {
  TERMINAL_STATUSES,
  VerificationStatus,
  type VerificationStatusValue,
} from "../value-objects/verification-status.js";
import type { VerificationType } from "../value-objects/verification-type.js";

import { ReviewAssignment, type ReviewerId } from "./review-assignment.js";

export type VerificationRequestId = Id<"VerificationRequestId">;
/** The user whose identity is being verified. A plain branded id, not identity's `UserId`, to keep this context's persistence mapping decoupled. */
export type VerificationSubjectId = Id<"VerificationSubjectId">;
/** The tenant the request belongs to. Row-level security scopes every read by it. */
export type VerificationOrganizationId = Id<"VerificationOrganizationId">;

/** The recorded outcome of a terminal review, including the rationale that justifies it. */
export interface VerificationDecision {
  readonly decidedBy: ReviewerId;
  readonly decidedAt: Date;
  readonly note: string;
}

export interface VerificationRequestProps {
  readonly id: VerificationRequestId;
  readonly subjectUserId: VerificationSubjectId;
  readonly organizationId: VerificationOrganizationId;
  readonly type: VerificationType;
  readonly status: VerificationStatus;
  readonly assignment: ReviewAssignment | undefined;
  readonly decision: VerificationDecision | undefined;
  readonly needsMoreInfoNote: string | undefined;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly domainEvents?: readonly DomainEvent[] | undefined;
}

/**
 * The verification aggregate root: one subject's request to prove one thing,
 * from first evidence to terminal decision.
 *
 * ## Why an aggregate and not fields on `User`
 *
 * Identity (`packages/identity`) is a bounded context with its own lifecycle;
 * verification is a different one. Putting `verificationStatus` on `User`
 * would mean every consumer of the identity aggregate carries PII-adjacent
 * verification state it has no business knowing, and would tie the two
 * contexts' release cycles together. `User` is referenced by id for the same
 * reason `Credential` references it by id.
 *
 * ## Why behaviour methods and not setters
 *
 * Every status change goes through a method that consults the transition
 * table (`VerificationStatus`) and the claim (`ReviewAssignment`) before it
 * returns a new instance. There is no `setStatus`. That is what makes
 * "deciding an unclaimed request" or "re-deciding an approved one"
 * structurally impossible rather than a rule each use case has to remember —
 * see Issue 162.
 *
 * The aggregate is immutable: every operation returns a new
 * `VerificationRequest`, and `pullDomainEvents` exposes only what the action
 * that produced *this* instance recorded, exactly like `User`.
 */
export class VerificationRequest {
  readonly id: VerificationRequestId;
  readonly subjectUserId: VerificationSubjectId;
  readonly organizationId: VerificationOrganizationId;
  readonly type: VerificationType;
  readonly status: VerificationStatus;
  readonly assignment: ReviewAssignment | undefined;
  readonly decision: VerificationDecision | undefined;
  readonly needsMoreInfoNote: string | undefined;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  private readonly domainEvents: readonly DomainEvent[];

  private constructor(props: VerificationRequestProps) {
    this.id = props.id;
    this.subjectUserId = props.subjectUserId;
    this.organizationId = props.organizationId;
    this.type = props.type;
    this.status = props.status;
    this.assignment = props.assignment;
    this.decision = props.decision;
    this.needsMoreInfoNote = props.needsMoreInfoNote;
    this.createdAt = props.createdAt;
    this.updatedAt = props.updatedAt;
    this.domainEvents = props.domainEvents ?? [];
  }

  /** Opens a new request, always in `pending_evidence` — nothing has been submitted yet. */
  static request(params: {
    subjectUserId: VerificationSubjectId;
    organizationId: VerificationOrganizationId;
    type: VerificationType;
  }): VerificationRequest {
    const now = new Date();
    return new VerificationRequest({
      id: createId<"VerificationRequestId">(),
      subjectUserId: params.subjectUserId,
      organizationId: params.organizationId,
      type: params.type,
      status: VerificationStatus.reconstitute("pending_evidence"),
      assignment: undefined,
      decision: undefined,
      needsMoreInfoNote: undefined,
      createdAt: now,
      updatedAt: now,
    });
  }

  /**
   * Rebuilds a request from already-trusted data (e.g. a database row).
   *
   * Does not re-run transition validation — the stored status is history, not
   * a decision being made now. It does check that the stored fields agree
   * with each other, because a row where they disagree means the database and
   * the domain have diverged: a data-integrity failure, not recoverable
   * input, so it throws (see `docs/guides/error-handling.md`).
   */
  static reconstitute(props: VerificationRequestProps): VerificationRequest {
    const isTerminal = TERMINAL_STATUSES.includes(props.status.value);
    if (isTerminal !== (props.decision !== undefined)) {
      throw new Error(
        `VerificationRequest ${props.id} has status "${props.status.value}" but ` +
          `${props.decision === undefined ? "no" : "a"} recorded decision. Review state is inconsistent.`,
      );
    }

    if ((props.status.value === "needs_more_info") !== (props.needsMoreInfoNote !== undefined)) {
      throw new Error(
        `VerificationRequest ${props.id} has status "${props.status.value}" but ` +
          `${props.needsMoreInfoNote === undefined ? "no" : "a"} needs-more-info note.`,
      );
    }

    if (props.assignment !== undefined && props.status.value !== "in_review") {
      throw new Error(
        `VerificationRequest ${props.id} holds a review assignment but is not in_review.`,
      );
    }

    return new VerificationRequest({ ...props, domainEvents: [] });
  }

  /** Whether this request has reached a terminal decision and can never change again. */
  get isTerminal(): boolean {
    return this.status.isTerminal;
  }

  /** Whether this request could be handed to a reviewer at `now` — `in_review`, and unclaimed or with an expired claim. */
  isClaimableAt(now: Date): boolean {
    if (this.status.value !== "in_review") {
      return false;
    }
    return this.assignment === undefined || this.assignment.isExpiredAt(now);
  }

  /**
   * `pending_evidence → submitted`. Called by the evidence-completeness flow
   * (Issue 168) once every required evidence type is present; it is a
   * deliberate transition rather than a client-asserted flag.
   */
  submit(): Result<VerificationRequest, InvalidStatusTransitionError> {
    return this.transitionTo("submitted");
  }

  /** `submitted → in_review`. Called once the automated provider check has run (Issue 172). */
  startReview(): Result<VerificationRequest, InvalidStatusTransitionError> {
    return this.transitionTo("in_review");
  }

  /** `needs_more_info → pending_evidence`: the subject re-enters the evidence flow after a reviewer asked for more. */
  reopenForEvidence(): Result<VerificationRequest, InvalidStatusTransitionError> {
    const transitioned = this.transitionTo("pending_evidence");
    if (Result.isErr(transitioned)) {
      return transitioned;
    }
    // The note has been acted on; clearing it keeps "a note exists iff the
    // request is needs_more_info" true, which `reconstitute` enforces.
    return Result.ok(transitioned.value.copy({ needsMoreInfoNote: undefined }));
  }

  /**
   * Takes a temporary, expiring claim on an `in_review` request.
   *
   * Refuses if an active claim already exists — by anyone, including the same
   * reviewer. Returning the existing claim to the same reviewer would make
   * "claim" silently non-idempotent (it would extend the lease), and the
   * reviewer's *other* pending case is what `ClaimNextReviewCase`'s
   * one-at-a-time policy is for. A conflict here is honest: someone holds it.
   */
  claimBy(params: {
    reviewerId: ReviewerId;
    now: Date;
    ttlMs?: number | undefined;
  }): Result<
    VerificationRequest,
    InvalidStatusTransitionError | ReviewClaimConflictError | ValidationError
  > {
    if (this.status.value !== "in_review") {
      return Result.err(new InvalidStatusTransitionError(this.status.value, "in_review"));
    }

    const existing = this.assignment;
    if (existing !== undefined && existing.isActiveAt(params.now)) {
      return Result.err(new ReviewClaimConflictError(this.id, existing.reviewerId));
    }

    const claim = ReviewAssignment.claim({
      requestId: this.id,
      reviewerId: params.reviewerId,
      assignedAt: params.now,
      ttlMs: params.ttlMs,
    });
    if (Result.isErr(claim)) {
      return claim;
    }

    return Result.ok(this.copy({ assignment: claim.value, updatedAt: params.now }));
  }

  /**
   * Approves the request. Only the reviewer holding the active claim may do
   * so, and the request must be `in_review` (never terminal).
   *
   * The rationale `note` is validated as mandatory by the calling use case,
   * not here — the same split `SuspendUser` uses for its reason: "structurally
   * possible" is the domain's business, "this action requires a reason" is
   * the application's. See `docs/guides/use-cases.md`.
   */
  approve(params: {
    reviewerId: ReviewerId;
    note: string;
    now: Date;
  }): Result<VerificationRequest, InvalidStatusTransitionError | ReviewDecisionNotPermittedError> {
    return this.decide("approved", params);
  }

  /** Rejects the request, under the same claim and transition rules as {@link approve}. */
  reject(params: {
    reviewerId: ReviewerId;
    note: string;
    now: Date;
  }): Result<VerificationRequest, InvalidStatusTransitionError | ReviewDecisionNotPermittedError> {
    return this.decide("rejected", params);
  }

  /**
   * `in_review → needs_more_info`, with a note describing what is missing.
   * Not a decision: the request stays open and re-enters the evidence flow via
   * {@link reopenForEvidence}. See Issue 176.
   */
  requestMoreInformation(params: {
    reviewerId: ReviewerId;
    note: string;
    now: Date;
  }): Result<VerificationRequest, InvalidStatusTransitionError | ReviewDecisionNotPermittedError> {
    const next = VerificationStatus.reconstitute("needs_more_info");
    if (!this.status.canTransitionTo(next)) {
      return Result.err(new InvalidStatusTransitionError(this.status.value, next.value));
    }

    const notPermitted = this.decisionNotPermitted(params.reviewerId, params.now);
    if (notPermitted !== undefined) {
      return Result.err(notPermitted);
    }

    return Result.ok(
      this.copy({
        status: next,
        assignment: undefined,
        needsMoreInfoNote: params.note,
        updatedAt: params.now,
      }),
    );
  }

  /** Returns the domain events recorded by the action that produced this instance. */
  pullDomainEvents(): readonly DomainEvent[] {
    return this.domainEvents;
  }

  private decide(
    outcome: "approved" | "rejected",
    params: { reviewerId: ReviewerId; note: string; now: Date },
  ): Result<VerificationRequest, InvalidStatusTransitionError | ReviewDecisionNotPermittedError> {
    const next = VerificationStatus.reconstitute(outcome);
    // Checked before the claim: deciding an already-terminal request must
    // report an illegal transition, not a missing claim, or the caller cannot
    // tell "already decided" (final) from "someone else has it" (retry later).
    if (!this.status.canTransitionTo(next)) {
      return Result.err(new InvalidStatusTransitionError(this.status.value, next.value));
    }

    const notPermitted = this.decisionNotPermitted(params.reviewerId, params.now);
    if (notPermitted !== undefined) {
      return Result.err(notPermitted);
    }

    return Result.ok(
      this.copy({
        status: next,
        assignment: undefined,
        decision: {
          decidedBy: params.reviewerId,
          decidedAt: params.now,
          note: params.note,
        },
        updatedAt: params.now,
        domainEvents: [
          new VerificationDecided({
            requestId: this.id,
            subjectUserId: this.subjectUserId,
            organizationId: this.organizationId,
            verificationType: this.type.value,
            decision: outcome,
            decidedBy: params.reviewerId,
            decidedAt: params.now,
            note: params.note,
          }),
        ],
      }),
    );
  }

  private decisionNotPermitted(
    reviewerId: ReviewerId,
    now: Date,
  ): ReviewDecisionNotPermittedError | undefined {
    const claim = this.assignment;
    if (claim === undefined || !claim.isActiveAt(now) || !claim.isHeldBy(reviewerId)) {
      return new ReviewDecisionNotPermittedError(this.id);
    }
    return undefined;
  }

  private transitionTo(
    next: VerificationStatusValue,
  ): Result<VerificationRequest, InvalidStatusTransitionError> {
    const nextStatus = VerificationStatus.reconstitute(next);
    if (!this.status.canTransitionTo(nextStatus)) {
      return Result.err(new InvalidStatusTransitionError(this.status.value, next));
    }
    return Result.ok(this.copy({ status: nextStatus }));
  }

  /**
   * Returns a new instance with the given overrides. Explicit `in` checks
   * rather than `??` so that clearing an optional field (setting `assignment`
   * to `undefined` on a decision) is distinguishable from leaving it alone —
   * `??` would silently keep a stale claim.
   */
  private copy(overrides: {
    status?: VerificationStatus;
    assignment?: ReviewAssignment | undefined;
    decision?: VerificationDecision | undefined;
    needsMoreInfoNote?: string | undefined;
    updatedAt?: Date;
    domainEvents?: readonly DomainEvent[];
  }): VerificationRequest {
    return new VerificationRequest({
      id: this.id,
      subjectUserId: this.subjectUserId,
      organizationId: this.organizationId,
      type: this.type,
      status: overrides.status ?? this.status,
      assignment: "assignment" in overrides ? overrides.assignment : this.assignment,
      decision: "decision" in overrides ? overrides.decision : this.decision,
      needsMoreInfoNote:
        "needsMoreInfoNote" in overrides ? overrides.needsMoreInfoNote : this.needsMoreInfoNote,
      createdAt: this.createdAt,
      updatedAt: overrides.updatedAt ?? new Date(),
      domainEvents: overrides.domainEvents ?? [],
    });
  }
}
