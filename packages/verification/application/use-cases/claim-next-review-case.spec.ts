import { createId } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import {
  VerificationRequest,
  type VerificationOrganizationId,
  type VerificationSubjectId,
} from "../../domain/entities/verification-request.js";
import { VerificationStatus } from "../../domain/value-objects/verification-status.js";
import { VerificationType } from "../../domain/value-objects/verification-type.js";
import { InMemoryVerificationRequestRepository } from "../../infrastructure/testing/in-memory-verification-request-repository.js";

import { ClaimNextReviewCase } from "./claim-next-review-case.js";

const EPOCH_MS = Date.UTC(2026, 8, 28, 12, 0, 0);
const NOW = new Date(EPOCH_MS + 60_000);

function newReviewer() {
  return createId<"ReviewerId">();
}

function subjectId(): VerificationSubjectId {
  return createId<"VerificationSubjectId">();
}

function organizationId(): VerificationOrganizationId {
  return createId<"VerificationOrganizationId">();
}

function inReview(offsetMs: number): VerificationRequest {
  const createdAt = new Date(EPOCH_MS + offsetMs);
  return VerificationRequest.reconstitute({
    id: createId<"VerificationRequestId">(),
    subjectUserId: subjectId(),
    organizationId: organizationId(),
    type: VerificationType.reconstitute("identity-document"),
    status: VerificationStatus.reconstitute("in_review"),
    assignment: undefined,
    decision: undefined,
    needsMoreInfoNote: undefined,
    createdAt,
    updatedAt: createdAt,
  });
}

describe("ClaimNextReviewCase", () => {
  it("hands the oldest claimable in_review request to the reviewer", async () => {
    const repository = new InMemoryVerificationRequestRepository();
    const oldest = inReview(0);
    const newer = inReview(5_000);
    // Saved newest-first on purpose: the queue orders by createdAt, not by
    // insertion order, so a repository that simply returned the Map in
    // insertion order would fail this.
    await repository.save(newer);
    await repository.save(oldest);

    const useCase = new ClaimNextReviewCase(repository);
    const outcome = await useCase.execute({ reviewerId: newReviewer(), now: NOW });

    expect(outcome.kind).toBe("claimed");
    if (outcome.kind === "claimed") {
      expect(outcome.request.id).toBe(oldest.id);
    }
  });

  it("returns none when the queue is empty", async () => {
    const repository = new InMemoryVerificationRequestRepository();

    const outcome = await new ClaimNextReviewCase(repository).execute({
      reviewerId: newReviewer(),
      now: NOW,
    });

    expect(outcome.kind).toBe("none");
  });

  it("refuses a second case to a reviewer who already holds one, by default", async () => {
    const repository = new InMemoryVerificationRequestRepository();
    await repository.save(inReview(0));
    await repository.save(inReview(5_000));

    const useCase = new ClaimNextReviewCase(repository);
    const reviewerId = newReviewer();
    const first = await useCase.execute({ reviewerId, now: NOW });
    const second = await useCase.execute({ reviewerId, now: NOW });

    expect(first.kind).toBe("claimed");
    expect(second.kind).toBe("already_claiming");
  });

  it("allows stacking cases when the one-at-a-time policy is disabled", async () => {
    const repository = new InMemoryVerificationRequestRepository();
    await repository.save(inReview(0));
    await repository.save(inReview(5_000));

    const useCase = new ClaimNextReviewCase(repository, { oneAtATime: false });
    const reviewerId = newReviewer();
    const first = await useCase.execute({ reviewerId, now: NOW });
    const second = await useCase.execute({ reviewerId, now: NOW });

    expect(first.kind).toBe("claimed");
    expect(second.kind).toBe("claimed");
    if (first.kind === "claimed" && second.kind === "claimed") {
      expect(first.request.id).not.toBe(second.request.id);
    }
  });

  it("applies the configured claim lease to the assignment it hands back", async () => {
    const repository = new InMemoryVerificationRequestRepository();
    await repository.save(inReview(0));

    const useCase = new ClaimNextReviewCase(repository, { claimTtlMs: 5 * 60 * 1000 });
    const outcome = await useCase.execute({ reviewerId: newReviewer(), now: NOW });

    expect(outcome.kind).toBe("claimed");
    if (outcome.kind === "claimed") {
      const assignment = outcome.request.assignment;
      expect(assignment?.claimExpiresAt.getTime()).toBe(NOW.getTime() + 5 * 60 * 1000);
    }
  });
});
