import { createId, Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type {
  ClaimNextOutcome,
  VerificationRequestRepository,
} from "../../../application/ports/verification-request-repository.js";
import type { ReviewerId } from "../../../domain/entities/review-assignment.js";
import {
  VerificationRequest,
  type VerificationOrganizationId,
  type VerificationSubjectId,
} from "../../../domain/entities/verification-request.js";
import {
  VerificationStatus,
  type VerificationStatusValue,
} from "../../../domain/value-objects/verification-status.js";
import {
  VerificationType,
  type VerificationTypeValue,
} from "../../../domain/value-objects/verification-type.js";

/**
 * Foreign-key fixtures. Against the in-memory fake these ids are arbitrary,
 * because a `Map` has no referential integrity; against Postgres they must
 * name rows that actually exist, so the caller seeds them and hands the ids
 * back. `docs/guides/testing.md` covers why both adapters run this same suite.
 */
export interface VerificationRequestContractContext {
  readonly subjectUserId: VerificationSubjectId;
  /** A second subject in the same tenant, so "finds by subject" can prove it excludes others without tripping a foreign key. */
  readonly otherSubjectUserId: VerificationSubjectId;
  readonly organizationId: VerificationOrganizationId;
}

const CONTRACT_EPOCH_MS = Date.UTC(2026, 0, 1, 12, 0, 0);

function buildRequest(params: {
  context: VerificationRequestContractContext;
  status: VerificationStatusValue;
  offsetMs: number;
  type?: VerificationTypeValue;
}): VerificationRequest {
  const createdAt = new Date(CONTRACT_EPOCH_MS + params.offsetMs);
  return VerificationRequest.reconstitute({
    id: createId<"VerificationRequestId">(),
    subjectUserId: params.context.subjectUserId,
    organizationId: params.context.organizationId,
    type: VerificationType.reconstitute(params.type ?? "identity-document"),
    status: VerificationStatus.reconstitute(params.status),
    assignment: undefined,
    decision: undefined,
    needsMoreInfoNote: undefined,
    createdAt,
    updatedAt: createdAt,
  });
}

function reviewer(): ReviewerId {
  return createId<"ReviewerId">();
}

/**
 * The shared behavioural contract every `VerificationRequestRepository`
 * implementation must satisfy — asserted against the in-memory fake on every
 * run and against the Prisma adapter wherever Postgres is reachable. "The
 * fake behaves like the real thing" is load-bearing here: every claim and
 * decision use-case test runs against the fake, so if its queue semantics
 * drifted from the adapter's, those tests would be quietly meaningless.
 */
export function verificationRequestRepositoryContract(
  createRepository: () => VerificationRequestRepository,
  createContext: () => Promise<VerificationRequestContractContext>,
): void {
  describe("VerificationRequestRepository contract", () => {
    it("returns undefined for a request that was never saved", async () => {
      const repository = createRepository();

      await expect(
        repository.findById(createId<"VerificationRequestId">()),
      ).resolves.toBeUndefined();
    });

    it("finds a saved request by id, with its state intact", async () => {
      const repository = createRepository();
      const context = await createContext();
      const request = buildRequest({ context, status: "in_review", offsetMs: 0 });

      await repository.save(request);
      const found = await repository.findById(request.id);

      expect(found?.id).toBe(request.id);
      expect(found?.status.value).toBe("in_review");
      expect(found?.type.value).toBe("identity-document");
      expect(found?.subjectUserId).toBe(context.subjectUserId);
      expect(found?.organizationId).toBe(context.organizationId);
    });

    it("save is an idempotent upsert", async () => {
      const repository = createRepository();
      const context = await createContext();
      const pending = buildRequest({ context, status: "pending_evidence", offsetMs: 0 });

      await repository.save(pending);
      const submitted = pending.submit();
      if (Result.isErr(submitted)) throw new Error("contract fixture setup failed");
      await repository.save(submitted.value);

      const found = await repository.findById(pending.id);
      expect(found?.status.value).toBe("submitted");
    });

    it("finds every request belonging to a subject, and no other", async () => {
      const repository = createRepository();
      const context = await createContext();
      const otherSubject = buildRequest({
        context: { ...context, subjectUserId: context.otherSubjectUserId },
        status: "pending_evidence",
        offsetMs: 0,
      });

      const first = buildRequest({ context, status: "pending_evidence", offsetMs: 0 });
      const second = buildRequest({ context, status: "in_review", offsetMs: 1_000 });
      await repository.save(first);
      await repository.save(second);
      await repository.save(otherSubject);

      const found = await repository.findBySubject(context.subjectUserId);

      expect(found.map((request) => request.id).sort()).toEqual([first.id, second.id].sort());
    });

    it("lists queue candidates oldest first, filtered and paginated", async () => {
      const repository = createRepository();
      const context = await createContext();

      const oldest = buildRequest({ context, status: "in_review", offsetMs: 0 });
      const middle = buildRequest({
        context,
        status: "in_review",
        offsetMs: 5_000,
        type: "liveness",
      });
      const newest = buildRequest({ context, status: "in_review", offsetMs: 10_000 });
      const notYetUnderReview = buildRequest({ context, status: "submitted", offsetMs: 15_000 });
      await repository.save(oldest);
      await repository.save(middle);
      await repository.save(newest);
      await repository.save(notYetUnderReview);

      const inReview = await repository.findQueueCandidates({ status: "in_review" });
      expect(inReview.map((request) => request.id)).toEqual([oldest.id, middle.id, newest.id]);

      const livenessOnly = await repository.findQueueCandidates({
        status: "in_review",
        verificationType: "liveness",
      });
      expect(livenessOnly.map((request) => request.id)).toEqual([middle.id]);

      const page = await repository.findQueueCandidates({
        status: "in_review",
        limit: 2,
        offset: 1,
      });
      expect(page.map((request) => request.id)).toEqual([middle.id, newest.id]);
    });

    it("claims the oldest claimable in_review request", async () => {
      const repository = createRepository();
      const context = await createContext();
      const oldest = buildRequest({ context, status: "in_review", offsetMs: 0 });
      const newer = buildRequest({ context, status: "in_review", offsetMs: 5_000 });
      await repository.save(oldest);
      await repository.save(newer);

      const outcome = await repository.claimNextInReview({
        reviewerId: reviewer(),
        now: new Date(CONTRACT_EPOCH_MS + 60_000),
        claimTtlMs: 60_000,
        oneAtATime: true,
      });

      expect(outcome.kind).toBe("claimed");
      if (outcome.kind === "claimed") {
        expect(outcome.request.id).toBe(oldest.id);
      }
    });

    it("never hands the same request to a second reviewer", async () => {
      const repository = createRepository();
      const context = await createContext();
      await repository.save(buildRequest({ context, status: "in_review", offsetMs: 0 }));
      await repository.save(buildRequest({ context, status: "in_review", offsetMs: 5_000 }));

      const now = new Date(CONTRACT_EPOCH_MS + 60_000);
      const first = await repository.claimNextInReview({
        reviewerId: reviewer(),
        now,
        claimTtlMs: 60_000,
        oneAtATime: true,
      });
      const second = await repository.claimNextInReview({
        reviewerId: reviewer(),
        now,
        claimTtlMs: 60_000,
        oneAtATime: true,
      });

      expect(first.kind).toBe("claimed");
      expect(second.kind).toBe("claimed");
      const firstId = first.kind === "claimed" ? first.request.id : undefined;
      const secondId = second.kind === "claimed" ? second.request.id : undefined;
      expect(firstId).toBeDefined();
      expect(secondId).toBeDefined();
      expect(firstId).not.toBe(secondId);
    });

    it("refuses a second case to a reviewer who already holds one, unless policy allows it", async () => {
      const repository = createRepository();
      const context = await createContext();
      await repository.save(buildRequest({ context, status: "in_review", offsetMs: 0 }));
      await repository.save(buildRequest({ context, status: "in_review", offsetMs: 5_000 }));

      const now = new Date(CONTRACT_EPOCH_MS + 60_000);
      const reviewerId = reviewer();
      const first = await repository.claimNextInReview({
        reviewerId,
        now,
        claimTtlMs: 60_000,
        oneAtATime: true,
      });
      expect(first.kind).toBe("claimed");

      const blocked = await repository.claimNextInReview({
        reviewerId,
        now,
        claimTtlMs: 60_000,
        oneAtATime: true,
      });
      expect(blocked.kind).toBe("already_claiming");

      const allowed = await repository.claimNextInReview({
        reviewerId,
        now,
        claimTtlMs: 60_000,
        oneAtATime: false,
      });
      expect(allowed.kind).toBe("claimed");
    });

    it("reports an active claim and stops reporting it once it expires", async () => {
      const repository = createRepository();
      const context = await createContext();
      await repository.save(buildRequest({ context, status: "in_review", offsetMs: 0 }));

      const now = new Date(CONTRACT_EPOCH_MS + 60_000);
      const reviewerId = reviewer();
      await repository.claimNextInReview({
        reviewerId,
        now,
        claimTtlMs: 30_000,
        oneAtATime: true,
      });

      const active = await repository.findActiveClaimByReviewer(reviewerId, now);
      expect(active).toBeDefined();

      const expired = await repository.findActiveClaimByReviewer(
        reviewerId,
        new Date(now.getTime() + 30_001),
      );
      expect(expired).toBeUndefined();
    });

    it("returns none when nothing is claimable", async () => {
      const repository = createRepository();

      const outcome: ClaimNextOutcome = await repository.claimNextInReview({
        reviewerId: reviewer(),
        now: new Date(CONTRACT_EPOCH_MS + 60_000),
        claimTtlMs: 60_000,
        oneAtATime: true,
      });

      expect(outcome.kind).toBe("none");
    });
  });
}
