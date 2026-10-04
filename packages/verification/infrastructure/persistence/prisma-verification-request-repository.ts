import type {
  PrismaClient,
  VerificationStatus as DbVerificationStatus,
  VerificationType as DbVerificationType,
} from "@verixa/database";

import type {
  ClaimNextInReviewParams,
  ClaimNextOutcome,
  QueueCandidateOptions,
  VerificationRequestRepository,
} from "../../application/ports/verification-request-repository.js";
import type { ReviewerId } from "../../domain/entities/review-assignment.js";
import type {
  VerificationRequest,
  VerificationRequestId,
  VerificationSubjectId,
} from "../../domain/entities/verification-request.js";

import { withMappedErrors } from "./error-mapper.js";
import { toDbVerificationType, VerificationRequestMapper } from "./verification-request-mapper.js";

/**
 * Prisma-backed `VerificationRequestRepository`. Satisfies the same port — and
 * passes the same behavioral contract — as
 * `InMemoryVerificationRequestRepository`, which is what makes the two
 * substitutable rather than merely similar.
 *
 * Takes a `PrismaClient` rather than constructing one, so a caller can hand it
 * a transaction client instead.
 */
export class PrismaVerificationRequestRepository implements VerificationRequestRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async save(request: VerificationRequest): Promise<void> {
    const row = VerificationRequestMapper.toRow(request);
    const { id, ...withoutId } = row;

    await withMappedErrors("VerificationRequest", () =>
      this.prisma.verificationRequest.upsert({
        where: { id },
        create: row,
        update: withoutId,
      }),
    );
  }

  async findById(id: VerificationRequestId): Promise<VerificationRequest | undefined> {
    const row = await this.prisma.verificationRequest.findUnique({ where: { id } });
    return row === null ? undefined : VerificationRequestMapper.toDomain(row);
  }

  async findBySubject(subjectUserId: VerificationSubjectId): Promise<VerificationRequest[]> {
    const rows = await this.prisma.verificationRequest.findMany({
      where: { subjectUserId },
      orderBy: { createdAt: "asc" },
    });
    return rows.map((row) => VerificationRequestMapper.toDomain(row));
  }

  async findQueueCandidates(options: QueueCandidateOptions = {}): Promise<VerificationRequest[]> {
    const where: { status?: DbVerificationStatus; type?: DbVerificationType } = {};
    if (options.status !== undefined) {
      where.status = options.status;
    }
    if (options.verificationType !== undefined) {
      where.type = toDbVerificationType(options.verificationType);
    }

    const rows = await this.prisma.verificationRequest.findMany({
      where,
      orderBy: { createdAt: "asc" },
      ...(options.limit !== undefined ? { take: options.limit } : {}),
      ...(options.offset !== undefined && options.offset > 0 ? { skip: options.offset } : {}),
    });
    return rows.map((row) => VerificationRequestMapper.toDomain(row));
  }

  async findActiveClaimByReviewer(
    reviewerId: ReviewerId,
    now: Date,
  ): Promise<VerificationRequest | undefined> {
    const row = await this.prisma.verificationRequest.findFirst({
      where: { assignedReviewerId: reviewerId, claimExpiresAt: { gt: now } },
      orderBy: { assignedAt: "asc" },
    });
    return row === null ? undefined : VerificationRequestMapper.toDomain(row);
  }

  /**
   * The race-safe claim, and the reason this adapter exists rather than only
   * the in-memory fake.
   *
   * The candidate is selected with `FOR UPDATE SKIP LOCKED`, which is the
   * standard "many workers, one queue, no double-processing" pattern:
   *
   * - `FOR UPDATE` locks the chosen row, so a concurrent claim by another
   *   reviewer blocks on it rather than reading a stale value.
   * - `SKIP LOCKED` makes that concurrent claim *step over* the locked row
   *   instead of waiting, then find the next candidate. Waiting would be
   *   correct but needlessly slow — a queue claim is not a critical section
   *   worth serialising reviewers over.
   *
   * Combined with the `status = 'in_review'` filter and the expiry check, two
   * reviewers calling this at the same instant can never be handed the same
   * request. Doing the equivalent with an application-level read-then-write
   * would leave a window between the two in which both read the same row.
   *
   * Everything is inside one transaction so the lock is held only as long as
   * the claim itself takes, and released with the commit.
   */
  async claimNextInReview(params: ClaimNextInReviewParams): Promise<ClaimNextOutcome> {
    return this.prisma.$transaction(async (tx): Promise<ClaimNextOutcome> => {
      if (params.oneAtATime) {
        const existing = await tx.verificationRequest.findFirst({
          where: {
            assignedReviewerId: params.reviewerId,
            claimExpiresAt: { gt: params.now },
          },
          select: { id: true },
        });
        if (existing !== null) {
          return { kind: "already_claiming" };
        }
      }

      const candidates = await tx.$queryRaw<{ id: string }[]>`
        SELECT "id"
        FROM "verification_requests"
        WHERE "status" = 'in_review'::"verification_status"
          AND ("assigned_reviewer_id" IS NULL OR "claim_expires_at" <= ${params.now})
        ORDER BY "created_at" ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED
      `;

      const candidate = candidates[0];
      if (candidate === undefined) {
        return { kind: "none" };
      }

      const updated = await tx.verificationRequest.update({
        where: { id: candidate.id },
        data: {
          assignedReviewerId: params.reviewerId,
          assignedAt: params.now,
          claimExpiresAt: new Date(params.now.getTime() + params.claimTtlMs),
          updatedAt: params.now,
        },
      });

      return { kind: "claimed", request: VerificationRequestMapper.toDomain(updated) };
    });
  }
}
