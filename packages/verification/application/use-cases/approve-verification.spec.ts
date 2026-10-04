import { createId, NotFoundError, Result, ValidationError } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { ReviewerId } from "../../domain/entities/review-assignment.js";
import { VerificationRequest } from "../../domain/entities/verification-request.js";
import { InvalidStatusTransitionError } from "../../domain/errors/invalid-status-transition.js";
import { ReviewDecisionNotPermittedError } from "../../domain/errors/review-decision-not-permitted.js";
import { VerificationDecided } from "../../domain/events/verification-decided.js";
import { VerificationType } from "../../domain/value-objects/verification-type.js";
import { InMemoryVerificationRequestRepository } from "../../infrastructure/testing/in-memory-verification-request-repository.js";

import { ApproveVerification } from "./approve-verification.js";

const NOW = new Date("2026-09-28T12:00:00.000Z");
const CLAIM_TTL_MS = 60_000;

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

async function setup(): Promise<{
  repository: InMemoryVerificationRequestRepository;
  request: VerificationRequest;
  reviewerId: ReviewerId;
}> {
  const repository = new InMemoryVerificationRequestRepository();
  const reviewerId = createId<"ReviewerId">();
  const claimed = inReview().claimBy({ reviewerId, now: NOW, ttlMs: CLAIM_TTL_MS });
  if (Result.isErr(claimed)) throw new Error("fixture setup failed");
  await repository.save(claimed.value);
  return { repository, request: claimed.value, reviewerId };
}

describe("ApproveVerification", () => {
  it("approves a claimed in_review request and persists the decision", async () => {
    const { repository, request, reviewerId } = await setup();

    const result = await new ApproveVerification(repository).execute({
      requestId: request.id,
      reviewerId,
      note: "ID matches the selfie",
      now: NOW,
    });

    expect(Result.isOk(result)).toBe(true);
    const persisted = await repository.findById(request.id);
    expect(persisted?.status.value).toBe("approved");
    expect(persisted?.decision?.note).toBe("ID matches the selfie");
    expect(persisted?.decision?.decidedBy).toBe(reviewerId);
  });

  it("carries a self-contained VerificationDecided event for the audit trail", async () => {
    const { repository, request, reviewerId } = await setup();

    const result = await new ApproveVerification(repository).execute({
      requestId: request.id,
      reviewerId,
      note: "  verified by hand  ",
      now: NOW,
    });
    if (Result.isErr(result)) throw new Error("expected approval");

    const event = result.value.pullDomainEvents()[0];
    expect(event).toBeInstanceOf(VerificationDecided);
    if (event instanceof VerificationDecided) {
      expect(event.decision).toBe("approved");
      expect(event.note).toBe("verified by hand");
      expect(event.subjectUserId).toBe(request.subjectUserId);
      expect(event.organizationId).toBe(request.organizationId);
      expect(event.decidedAt).toEqual(NOW);
    }
  });

  it("rejects a decision with no rationale, leaving the request untouched", async () => {
    const { repository, request, reviewerId } = await setup();

    const result = await new ApproveVerification(repository).execute({
      requestId: request.id,
      reviewerId,
      note: "   ",
      now: NOW,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBeInstanceOf(ValidationError);
      if (result.error instanceof ValidationError) {
        expect(result.error.fieldErrors["note"]).toEqual(["required"]);
      }
    }

    const persisted = await repository.findById(request.id);
    expect(persisted?.status.value).toBe("in_review");
  });

  it("returns NotFoundError for an unknown request", async () => {
    const repository = new InMemoryVerificationRequestRepository();

    const result = await new ApproveVerification(repository).execute({
      requestId: createId<"VerificationRequestId">(),
      reviewerId: createId<"ReviewerId">(),
      note: "fine",
      now: NOW,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBeInstanceOf(NotFoundError);
    }
  });

  it("refuses a decision from a reviewer who does not hold the claim", async () => {
    const { repository, request } = await setup();

    const result = await new ApproveVerification(repository).execute({
      requestId: request.id,
      reviewerId: createId<"ReviewerId">(),
      note: "not my case",
      now: NOW,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBeInstanceOf(ReviewDecisionNotPermittedError);
    }
    const persisted = await repository.findById(request.id);
    expect(persisted?.status.value).toBe("in_review");
  });

  it("refuses to approve a request that has not reached review", async () => {
    const repository = new InMemoryVerificationRequestRepository();
    const pending = newRequest();
    await repository.save(pending);

    const result = await new ApproveVerification(repository).execute({
      requestId: pending.id,
      reviewerId: createId<"ReviewerId">(),
      note: "jumping the queue",
      now: NOW,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBeInstanceOf(InvalidStatusTransitionError);
    }
  });
});
