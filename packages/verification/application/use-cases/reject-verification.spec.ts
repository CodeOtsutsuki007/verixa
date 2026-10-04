import { createId, Result, ValidationError } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { ReviewerId } from "../../domain/entities/review-assignment.js";
import { VerificationRequest } from "../../domain/entities/verification-request.js";
import { ReviewDecisionNotPermittedError } from "../../domain/errors/review-decision-not-permitted.js";
import { VerificationDecided } from "../../domain/events/verification-decided.js";
import { VerificationType } from "../../domain/value-objects/verification-type.js";
import { InMemoryVerificationRequestRepository } from "../../infrastructure/testing/in-memory-verification-request-repository.js";

import { RejectVerification } from "./reject-verification.js";

const NOW = new Date("2026-09-28T12:00:00.000Z");

function inReview(): VerificationRequest {
  const submitted = VerificationRequest.request({
    subjectUserId: createId<"VerificationSubjectId">(),
    organizationId: createId<"VerificationOrganizationId">(),
    type: VerificationType.reconstitute("liveness"),
  }).submit();
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
  const claimed = inReview().claimBy({ reviewerId, now: NOW, ttlMs: 60_000 });
  if (Result.isErr(claimed)) throw new Error("fixture setup failed");
  await repository.save(claimed.value);
  return { repository, request: claimed.value, reviewerId };
}

describe("RejectVerification", () => {
  it("rejects a claimed in_review request and persists the rationale", async () => {
    const { repository, request, reviewerId } = await setup();

    const result = await new RejectVerification(repository).execute({
      requestId: request.id,
      reviewerId,
      note: "liveness video is a still image",
      now: NOW,
    });

    expect(Result.isOk(result)).toBe(true);
    const persisted = await repository.findById(request.id);
    expect(persisted?.status.value).toBe("rejected");
    expect(persisted?.decision?.note).toBe("liveness video is a still image");
  });

  it("emits a rejection VerificationDecided event", async () => {
    const { repository, request, reviewerId } = await setup();

    const result = await new RejectVerification(repository).execute({
      requestId: request.id,
      reviewerId,
      note: "document expired",
      now: NOW,
    });
    if (Result.isErr(result)) throw new Error("expected rejection");

    const event = result.value.pullDomainEvents()[0];
    expect(event).toBeInstanceOf(VerificationDecided);
    if (event instanceof VerificationDecided) {
      expect(event.decision).toBe("rejected");
      expect(event.note).toBe("document expired");
    }
  });

  it("requires a rationale note", async () => {
    const { repository, request, reviewerId } = await setup();

    const result = await new RejectVerification(repository).execute({
      requestId: request.id,
      reviewerId,
      note: "",
      now: NOW,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBeInstanceOf(ValidationError);
    }
    const persisted = await repository.findById(request.id);
    expect(persisted?.status.value).toBe("in_review");
  });

  it("refuses a rejection from a reviewer who does not hold the claim", async () => {
    const { repository, request } = await setup();

    const result = await new RejectVerification(repository).execute({
      requestId: request.id,
      reviewerId: createId<"ReviewerId">(),
      note: "not my case",
      now: NOW,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBeInstanceOf(ReviewDecisionNotPermittedError);
    }
  });
});
