import { createId, Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { InvalidStatusTransitionError } from "../errors/invalid-status-transition.js";
import { ReviewClaimConflictError } from "../errors/review-claim-conflict.js";
import { ReviewDecisionNotPermittedError } from "../errors/review-decision-not-permitted.js";
import { VerificationDecided } from "../events/verification-decided.js";
import { VerificationStatus } from "../value-objects/verification-status.js";
import { VerificationType } from "../value-objects/verification-type.js";

import { ReviewAssignment } from "./review-assignment.js";
import { VerificationRequest } from "./verification-request.js";

const NOW = new Date("2026-09-28T12:00:00.000Z");
const CLAIM_TTL_MS = 60_000;

function newReviewer() {
  return createId<"ReviewerId">();
}

function newRequest(): VerificationRequest {
  return VerificationRequest.request({
    subjectUserId: createId<"VerificationSubjectId">(),
    organizationId: createId<"VerificationOrganizationId">(),
    type: VerificationType.reconstitute("identity-document"),
  });
}

function inReview(): VerificationRequest {
  const submitted = newRequest().submit();
  if (Result.isErr(submitted)) throw new Error("fixture setup failed");
  const reviewing = submitted.value.startReview();
  if (Result.isErr(reviewing)) throw new Error("fixture setup failed");
  return reviewing.value;
}

function claimed(reviewerId = newReviewer(), now = NOW): VerificationRequest {
  const request = inReview().claimBy({ reviewerId, now, ttlMs: CLAIM_TTL_MS });
  if (Result.isErr(request)) throw new Error("fixture setup failed");
  return request.value;
}

function unwrap<T>(result: Result<T, unknown>): T {
  if (Result.isErr(result)) throw new Error("expected success");
  return result.value;
}

describe("VerificationRequest", () => {
  it("starts in pending_evidence, with no claim and no decision", () => {
    const request = newRequest();

    expect(request.status.value).toBe("pending_evidence");
    expect(request.type.value).toBe("identity-document");
    expect(request.assignment).toBeUndefined();
    expect(request.decision).toBeUndefined();
    expect(request.isTerminal).toBe(false);
    expect(request.pullDomainEvents()).toEqual([]);
  });

  it("moves pending_evidence -> submitted -> in_review along the legal edges", () => {
    const submitted = unwrap(newRequest().submit());
    const reviewing = unwrap(submitted.startReview());

    expect(submitted.status.value).toBe("submitted");
    expect(reviewing.status.value).toBe("in_review");
  });

  it("rejects an illegal jump straight from pending_evidence to in_review", () => {
    const result = unwrap(newRequest().submit()).startReview();
    const illegal = unwrap(result).submit();

    expect(Result.isErr(illegal)).toBe(true);
    if (Result.isErr(illegal)) {
      expect(illegal.error).toBeInstanceOf(InvalidStatusTransitionError);
    }
  });

  it("refuses to claim a request that is not in_review", () => {
    const result = newRequest().claimBy({ reviewerId: newReviewer(), now: NOW });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBeInstanceOf(InvalidStatusTransitionError);
    }
  });

  it("records a claim while in_review, making the request unclaimable", () => {
    const reviewerId = newReviewer();
    const request = claimed(reviewerId);

    expect(request.assignment?.reviewerId).toBe(reviewerId);
    expect(request.assignment?.isHeldBy(reviewerId)).toBe(true);
    expect(request.isClaimableAt(NOW)).toBe(false);
  });

  it("refuses a second claim while another reviewer's claim is active", () => {
    const request = claimed(newReviewer());

    const second = request.claimBy({ reviewerId: newReviewer(), now: NOW, ttlMs: CLAIM_TTL_MS });

    expect(Result.isErr(second)).toBe(true);
    if (Result.isErr(second)) {
      expect(second.error).toBeInstanceOf(ReviewClaimConflictError);
    }
  });

  it("allows a fresh claim once the previous one has lapsed", () => {
    const request = claimed(newReviewer());
    const later = new Date(NOW.getTime() + CLAIM_TTL_MS + 1);
    const nextReviewer = newReviewer();

    const second = request.claimBy({ reviewerId: nextReviewer, now: later, ttlMs: CLAIM_TTL_MS });

    expect(Result.isOk(second)).toBe(true);
    if (Result.isOk(second)) {
      expect(second.value.assignment?.reviewerId).toBe(nextReviewer);
    }
  });

  it("refuses a decision from a reviewer who does not hold the claim", () => {
    const request = claimed(newReviewer());

    const result = request.approve({ reviewerId: newReviewer(), note: "looks fine", now: NOW });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBeInstanceOf(ReviewDecisionNotPermittedError);
    }
  });

  it("refuses a decision once the claim has expired", () => {
    const reviewerId = newReviewer();
    const request = claimed(reviewerId);
    const afterExpiry = new Date(NOW.getTime() + CLAIM_TTL_MS + 1);

    const result = request.reject({ reviewerId, note: "expired claim", now: afterExpiry });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBeInstanceOf(ReviewDecisionNotPermittedError);
    }
  });

  it("approves an in_review request held by the deciding reviewer, recording the decision and event", () => {
    const reviewerId = newReviewer();
    const request = claimed(reviewerId);

    const approved = unwrap(
      request.approve({ reviewerId, note: "ID matches the selfie", now: NOW }),
    );

    expect(approved.status.value).toBe("approved");
    expect(approved.isTerminal).toBe(true);
    expect(approved.assignment).toBeUndefined();
    expect(approved.decision).toEqual({
      decidedBy: reviewerId,
      decidedAt: NOW,
      note: "ID matches the selfie",
    });

    const events = approved.pullDomainEvents();
    expect(events).toHaveLength(1);
    const event = events[0];
    expect(event).toBeInstanceOf(VerificationDecided);
    if (event instanceof VerificationDecided) {
      expect(event.eventName).toBe("verification.request.decided");
      expect(event.aggregateId).toBe(request.id);
      expect(event.decision).toBe("approved");
      expect(event.decidedBy).toBe(reviewerId);
      expect(event.decidedAt).toEqual(NOW);
      expect(event.note).toBe("ID matches the selfie");
      // Self-contained for the audit trail: no follow-up query needed.
      expect(event.subjectUserId).toBe(request.subjectUserId);
      expect(event.organizationId).toBe(request.organizationId);
      expect(event.verificationType).toBe("identity-document");
    }
  });

  it("rejects an in_review request held by the deciding reviewer, emitting a rejection event", () => {
    const reviewerId = newReviewer();
    const request = claimed(reviewerId);

    const rejected = unwrap(request.reject({ reviewerId, note: "document unreadable", now: NOW }));

    expect(rejected.status.value).toBe("rejected");
    const event = rejected.pullDomainEvents()[0];
    expect(event).toBeInstanceOf(VerificationDecided);
    if (event instanceof VerificationDecided) {
      expect(event.decision).toBe("rejected");
    }
  });

  it("refuses to re-decide a terminal request, reporting an illegal transition", () => {
    const reviewerId = newReviewer();
    const approved = unwrap(claimed(reviewerId).approve({ reviewerId, note: "fine", now: NOW }));

    const second = approved.reject({ reviewerId, note: "changed my mind", now: NOW });

    expect(Result.isErr(second)).toBe(true);
    if (Result.isErr(second)) {
      // Illegal transition, not "not permitted": the case is final for
      // everyone, which the caller must be able to tell apart from "someone
      // else holds it".
      expect(second.error).toBeInstanceOf(InvalidStatusTransitionError);
    }
  });

  it("asks for more information without deciding, then re-opens the evidence flow", () => {
    const reviewerId = newReviewer();
    const request = claimed(reviewerId);

    const needMore = unwrap(
      request.requestMoreInformation({ reviewerId, note: "ID back is missing", now: NOW }),
    );

    expect(needMore.status.value).toBe("needs_more_info");
    expect(needMore.needsMoreInfoNote).toBe("ID back is missing");
    expect(needMore.assignment).toBeUndefined();
    expect(needMore.isTerminal).toBe(false);

    const reopened = unwrap(needMore.reopenForEvidence());

    expect(reopened.status.value).toBe("pending_evidence");
    // Prior decision history is preserved (there is none yet) and the note is
    // cleared so "a note exists iff needs_more_info" stays true.
    expect(reopened.needsMoreInfoNote).toBeUndefined();
    expect(reopened.decision).toBeUndefined();
  });

  it("restricts asking for more information to the reviewer holding the claim", () => {
    const request = claimed(newReviewer());

    const result = request.requestMoreInformation({
      reviewerId: newReviewer(),
      note: "give me more",
      now: NOW,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBeInstanceOf(ReviewDecisionNotPermittedError);
    }
  });

  it("throws when reconstituting a terminal request with no recorded decision", () => {
    expect(() =>
      VerificationRequest.reconstitute({
        id: createId<"VerificationRequestId">(),
        subjectUserId: createId<"VerificationSubjectId">(),
        organizationId: createId<"VerificationOrganizationId">(),
        type: VerificationType.reconstitute("identity-document"),
        status: VerificationStatus.reconstitute("approved"),
        assignment: undefined,
        decision: undefined,
        needsMoreInfoNote: undefined,
        createdAt: NOW,
        updatedAt: NOW,
      }),
    ).toThrow();
  });

  it("throws when reconstituting a claim on a request that is not in_review", () => {
    expect(() =>
      VerificationRequest.reconstitute({
        id: createId<"VerificationRequestId">(),
        subjectUserId: createId<"VerificationSubjectId">(),
        organizationId: createId<"VerificationOrganizationId">(),
        type: VerificationType.reconstitute("identity-document"),
        status: VerificationStatus.reconstitute("submitted"),
        assignment: ReviewAssignment.reconstitute({
          requestId: createId<"VerificationRequestId">(),
          reviewerId: newReviewer(),
          assignedAt: NOW,
          claimExpiresAt: new Date(NOW.getTime() + CLAIM_TTL_MS),
        }),
        decision: undefined,
        needsMoreInfoNote: undefined,
        createdAt: NOW,
        updatedAt: NOW,
      }),
    ).toThrow();
  });
});
