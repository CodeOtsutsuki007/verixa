import { createId, Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import {
  VerificationRequest,
  type VerificationOrganizationId,
  type VerificationSubjectId,
} from "../../domain/entities/verification-request.js";
import { VerificationStatus } from "../../domain/value-objects/verification-status.js";
import {
  VerificationType,
  type VerificationTypeValue,
} from "../../domain/value-objects/verification-type.js";
import { InMemoryVerificationRequestRepository } from "../../infrastructure/testing/in-memory-verification-request-repository.js";

import { ListReviewQueue, MAX_QUEUE_PAGE_SIZE } from "./list-review-queue.js";

const EPOCH_MS = Date.UTC(2026, 8, 28, 12, 0, 0);
const NOW = new Date(EPOCH_MS + 600_000);

function subjectId(): VerificationSubjectId {
  return createId<"VerificationSubjectId">();
}

function organizationId(): VerificationOrganizationId {
  return createId<"VerificationOrganizationId">();
}

/**
 * Fixtures are built through the domain's own transitions (`submit`,
 * `startReview`) rather than by writing a status straight onto the aggregate,
 * so a fixture cannot describe a request the domain could not have produced.
 */
function pending(offsetMs: number, type: VerificationTypeValue = "identity-document") {
  const createdAt = new Date(EPOCH_MS + offsetMs);
  return VerificationRequest.reconstitute({
    id: createId<"VerificationRequestId">(),
    subjectUserId: subjectId(),
    organizationId: organizationId(),
    type: VerificationType.reconstitute(type),
    status: VerificationStatus.reconstitute("pending_evidence"),
    assignment: undefined,
    decision: undefined,
    needsMoreInfoNote: undefined,
    createdAt,
    updatedAt: createdAt,
  });
}

function unwrap(result: Result<VerificationRequest, unknown>): VerificationRequest {
  if (Result.isErr(result)) {
    throw new Error("fixture setup failed");
  }
  return result.value;
}

function submitted(offsetMs: number, type: VerificationTypeValue = "identity-document") {
  return unwrap(pending(offsetMs, type).submit());
}

function inReview(offsetMs: number, type: VerificationTypeValue = "identity-document") {
  return unwrap(submitted(offsetMs, type).startReview());
}

function needsMoreInfo(offsetMs: number) {
  const createdAt = new Date(EPOCH_MS + offsetMs);
  return VerificationRequest.reconstitute({
    id: createId<"VerificationRequestId">(),
    subjectUserId: subjectId(),
    organizationId: organizationId(),
    type: VerificationType.reconstitute("identity-document"),
    status: VerificationStatus.reconstitute("needs_more_info"),
    assignment: undefined,
    decision: undefined,
    needsMoreInfoNote: "The back of the ID is missing.",
    createdAt,
    updatedAt: createdAt,
  });
}

function approved(offsetMs: number) {
  const createdAt = new Date(EPOCH_MS + offsetMs);
  return VerificationRequest.reconstitute({
    id: createId<"VerificationRequestId">(),
    subjectUserId: subjectId(),
    organizationId: organizationId(),
    type: VerificationType.reconstitute("identity-document"),
    status: VerificationStatus.reconstitute("approved"),
    assignment: undefined,
    decision: {
      decidedBy: createId<"ReviewerId">(),
      decidedAt: createdAt,
      note: "Documents matched the subject.",
    },
    needsMoreInfoNote: undefined,
    createdAt,
    updatedAt: createdAt,
  });
}

async function seed(
  requests: readonly VerificationRequest[],
): Promise<InMemoryVerificationRequestRepository> {
  const repository = new InMemoryVerificationRequestRepository();
  // Saved newest-first on purpose: the queue order comes from `createdAt`, not
  // from insertion order, so a store that returned the Map as-is would fail.
  for (const request of [...requests].reverse()) {
    await repository.save(request);
  }
  return repository;
}

/** A repository that fails loudly, to prove an invalid query never reaches the store. */
class UnreachableRepository extends InMemoryVerificationRequestRepository {
  override findQueueCandidates(): Promise<VerificationRequest[]> {
    throw new Error("an invalid queue query must not reach the repository");
  }
}

describe("ListReviewQueue", () => {
  it("lists reviewable work oldest first, and nothing that is not reviewable", async () => {
    const oldest = inReview(0);
    const middle = submitted(5_000);
    const newest = inReview(10_000);
    const repository = await seed([
      oldest,
      middle,
      newest,
      pending(15_000),
      needsMoreInfo(20_000),
      approved(25_000),
    ]);

    const result = await new ListReviewQueue(repository).execute({ now: NOW });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isErr(result)) return;
    expect(result.value.items.map((item) => item.requestId)).toEqual([
      oldest.id,
      middle.id,
      newest.id,
    ]);
    expect(result.value.items.map((item) => item.status)).toEqual([
      "in_review",
      "submitted",
      "in_review",
    ]);
  });

  it("narrows to a single reviewable status when asked for one", async () => {
    const oldest = inReview(0);
    const awaitingCheck = submitted(5_000);
    const repository = await seed([oldest, awaitingCheck]);

    const result = await new ListReviewQueue(repository).execute({
      status: "submitted",
      now: NOW,
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isErr(result)) return;
    expect(result.value.items.map((item) => item.requestId)).toEqual([awaitingCheck.id]);
  });

  it("filters by verification type", async () => {
    const identity = inReview(0);
    const liveness = inReview(5_000, "liveness");
    const address = inReview(10_000, "address");
    const repository = await seed([identity, liveness, address]);

    const result = await new ListReviewQueue(repository).execute({
      verificationType: "liveness",
      now: NOW,
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isErr(result)) return;
    expect(result.value.items.map((item) => item.requestId)).toEqual([liveness.id]);
  });

  it("combines the status, type and assignment filters", async () => {
    const claimed = inReview(0, "liveness");
    const free = inReview(5_000, "liveness");
    const wrongType = inReview(10_000, "address");
    const repository = await seed([claimed, free, wrongType]);

    await repository.claimNextInReview({
      reviewerId: createId<"ReviewerId">(),
      now: NOW,
      claimTtlMs: 30_000,
      oneAtATime: false,
    });

    const result = await new ListReviewQueue(repository).execute({
      status: "in_review",
      verificationType: "liveness",
      assignment: "assigned",
      now: NOW,
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isErr(result)) return;
    expect(result.value.items.map((item) => item.requestId)).toEqual([claimed.id]);
  });

  it("separates claimed work from what a reviewer could pick up next", async () => {
    const claimed = inReview(0);
    const free = inReview(5_000);
    const repository = await seed([claimed, free]);
    const reviewerId = createId<"ReviewerId">();

    await repository.claimNextInReview({
      reviewerId,
      now: NOW,
      claimTtlMs: 30_000,
      oneAtATime: false,
    });

    const assigned = await new ListReviewQueue(repository).execute({
      assignment: "assigned",
      now: NOW,
    });
    const unassigned = await new ListReviewQueue(repository).execute({
      assignment: "unassigned",
      now: NOW,
    });

    expect(Result.isOk(assigned) && Result.isOk(unassigned)).toBe(true);
    if (Result.isErr(assigned) || Result.isErr(unassigned)) return;

    expect(assigned.value.items.map((item) => item.requestId)).toEqual([claimed.id]);
    expect(unassigned.value.items.map((item) => item.requestId)).toEqual([free.id]);

    const claim = assigned.value.items[0]?.claim;
    expect(claim?.reviewerId).toBe(reviewerId);
    expect(claim?.claimedAt.getTime()).toBe(NOW.getTime());
    expect(claim?.expiresAt.getTime()).toBe(NOW.getTime() + 30_000);
  });

  it("treats a lapsed lease as unassigned, and stops reporting it as a claim", async () => {
    const previouslyClaimed = inReview(0);
    const repository = await seed([previouslyClaimed]);

    await repository.claimNextInReview({
      reviewerId: createId<"ReviewerId">(),
      now: NOW,
      claimTtlMs: 30_000,
      oneAtATime: false,
    });

    const stillClaimed = await new ListReviewQueue(repository).execute({
      assignment: "assigned",
      now: NOW,
    });
    const afterExpiry = new Date(NOW.getTime() + 30_001);
    const backInQueue = await new ListReviewQueue(repository).execute({
      assignment: "unassigned",
      now: afterExpiry,
    });

    expect(Result.isOk(stillClaimed) && Result.isOk(backInQueue)).toBe(true);
    if (Result.isErr(stillClaimed) || Result.isErr(backInQueue)) return;

    expect(stillClaimed.value.items.map((item) => item.requestId)).toEqual([previouslyClaimed.id]);
    expect(backInQueue.value.items.map((item) => item.requestId)).toEqual([previouslyClaimed.id]);
    // The row still holds an assignment; the item does not report it, because a
    // lease that has run out is not a claim a reviewer can rely on.
    expect(backInQueue.value.items[0]?.claim).toBeUndefined();
  });

  it("pages through the queue without dropping or repeating a row", async () => {
    const requests = [0, 1_000, 2_000, 3_000, 4_000].map((offsetMs) => inReview(offsetMs));
    const repository = await seed(requests);
    const useCase = new ListReviewQueue(repository);

    const first = await useCase.execute({ limit: 2, now: NOW });
    const second = await useCase.execute({ limit: 2, offset: 2, now: NOW });
    const third = await useCase.execute({ limit: 2, offset: 4, now: NOW });
    const past = await useCase.execute({ limit: 2, offset: 6, now: NOW });

    if (Result.isErr(first) || Result.isErr(second) || Result.isErr(third) || Result.isErr(past)) {
      throw new Error("expected every page to be valid");
    }

    expect(first.value.items.map((item) => item.requestId)).toEqual(
      requests.slice(0, 2).map((request) => request.id),
    );
    expect(second.value.items.map((item) => item.requestId)).toEqual(
      requests.slice(2, 4).map((request) => request.id),
    );
    expect(third.value.items.map((item) => item.requestId)).toEqual(
      requests.slice(4).map((request) => request.id),
    );
    expect(past.value.items).toEqual([]);

    // `hasMore` is answered from the extra row that was read, so the last
    // non-empty page is the one that reports the end.
    expect([first.value.hasMore, second.value.hasMore, third.value.hasMore]).toEqual([
      true,
      true,
      false,
    ]);
    expect(past.value.hasMore).toBe(false);
    expect(first.value).toMatchObject({ limit: 2, offset: 0 });
    expect(second.value).toMatchObject({ limit: 2, offset: 2 });
  });

  it("defaults to the documented page size and reports no further page", async () => {
    const repository = await seed([inReview(0)]);

    const result = await new ListReviewQueue(repository).execute({ now: NOW });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isErr(result)) return;
    expect(result.value).toMatchObject({ limit: 25, offset: 0, hasMore: false });
  });

  it("returns summary rows and no evidence detail", async () => {
    const request = inReview(0);
    const repository = await seed([request]);

    const result = await new ListReviewQueue(repository).execute({
      assignment: "unassigned",
      now: NOW,
    });

    expect(Result.isOk(result)).toBe(true);
    if (Result.isErr(result)) return;

    const item = result.value.items[0];
    // Asserted as an exact key set rather than as absent fields: a new field
    // added to the row shape has to be a deliberate edit here, because the
    // queue is the read path a reviewer's browser sees first, and "#177
    // response shape omits sensitive fields" is a property of this projection
    // rather than of whichever serializer comes later. Evidence detail — and
    // any signed URL for it — belongs to the per-request detail fetch (Issue
    // 178) and to `EvidenceStorage` (Issue 166), not to a list.
    expect(Object.keys(item ?? {}).sort()).toEqual([
      "claim",
      "createdAt",
      "organizationId",
      "requestId",
      "status",
      "subjectUserId",
      "updatedAt",
      "verificationType",
    ]);
    expect(item).toMatchObject({
      requestId: request.id,
      subjectUserId: request.subjectUserId,
      organizationId: request.organizationId,
      verificationType: "identity-document",
      status: "in_review",
      createdAt: request.createdAt,
      claim: undefined,
    });
  });

  it("rejects a status the queue does not list", async () => {
    const result = await new ListReviewQueue(new UnreachableRepository()).execute({
      status: "approved",
      now: NOW,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isOk(result)) return;
    expect(result.error.fieldErrors["status"]).toEqual(["not_reviewable"]);
  });

  it("rejects a page size outside the supported range", async () => {
    const useCase = new ListReviewQueue(new UnreachableRepository());

    for (const limit of [0, -1, 2.5, MAX_QUEUE_PAGE_SIZE + 1]) {
      const result = await useCase.execute({ limit, now: NOW });
      expect(Result.isErr(result)).toBe(true);
      if (Result.isOk(result)) continue;
      expect(result.error.fieldErrors["limit"]).toBeDefined();
    }
  });

  it("rejects a negative or fractional offset", async () => {
    const useCase = new ListReviewQueue(new UnreachableRepository());

    for (const offset of [-1, 1.5]) {
      const result = await useCase.execute({ offset, now: NOW });
      expect(Result.isErr(result)).toBe(true);
      if (Result.isOk(result)) continue;
      expect(result.error.fieldErrors["offset"]).toBeDefined();
    }
  });

  it("aggregates every invalid field into one error instead of returning the first", async () => {
    const result = await new ListReviewQueue(new UnreachableRepository()).execute({
      status: "rejected",
      limit: 0,
      offset: -1,
      now: NOW,
    });

    expect(Result.isErr(result)).toBe(true);
    if (Result.isOk(result)) return;
    expect(Object.keys(result.error.fieldErrors).sort()).toEqual(["limit", "offset", "status"]);
  });
});
