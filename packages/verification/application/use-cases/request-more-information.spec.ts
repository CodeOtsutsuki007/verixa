import { createId, Result, ValidationError } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { ReviewerId } from "../../domain/entities/review-assignment.js";
import { VerificationRequest } from "../../domain/entities/verification-request.js";
import { ReviewDecisionNotPermittedError } from "../../domain/errors/review-decision-not-permitted.js";
import { VerificationType } from "../../domain/value-objects/verification-type.js";
import { InMemoryVerificationRequestRepository } from "../../infrastructure/testing/in-memory-verification-request-repository.js";

import { RequestMoreInformation } from "./request-more-information.js";

const NOW = new Date("2026-09-28T12:00:00.000Z");

function inReview(): VerificationRequest {
  const submitted = VerificationRequest.request({
    subjectUserId: createId<"VerificationSubjectId">(),
    organizationId: createId<"VerificationOrganizationId">(),
    type: VerificationType.reconstitute("identity-document"),
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

describe("RequestMoreInformation", () => {
  it("moves the request to needs_more_info and records the note for the subject", async () => {
    const { repository, request, reviewerId } = await setup();

    const result = await new RequestMoreInformation(repository).execute({
      requestId: request.id,
      reviewerId,
      note: "Please re-upload the back of your ID.",
      now: NOW,
    });

    expect(Result.isOk(result)).toBe(true);
    const persisted = await repository.findById(request.id);
    expect(persisted?.status.value).toBe("needs_more_info");
    expect(persisted?.needsMoreInfoNote).toBe("Please re-upload the back of your ID.");
    expect(persisted?.isTerminal).toBe(false);
  });

  it("requires a note describing what is missing", async () => {
    const { repository, request, reviewerId } = await setup();

    const result = await new RequestMoreInformation(repository).execute({
      requestId: request.id,
      reviewerId,
      note: "   ",
      now: NOW,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBeInstanceOf(ValidationError);
    }
    const persisted = await repository.findById(request.id);
    expect(persisted?.status.value).toBe("in_review");
  });

  it("restricts the request to the reviewer holding the claim", async () => {
    const { repository, request } = await setup();

    const result = await new RequestMoreInformation(repository).execute({
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
