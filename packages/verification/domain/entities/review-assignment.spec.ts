import { createId, Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { DEFAULT_CLAIM_TTL_MS, ReviewAssignment } from "./review-assignment.js";
import type { VerificationRequestId } from "./verification-request.js";

const ASSIGNED_AT = new Date("2026-09-28T12:00:00.000Z");

function claim(ttlMs?: number): ReviewAssignment {
  const result = ReviewAssignment.claim({
    requestId: createId<"VerificationRequestId">(),
    reviewerId: createId<"ReviewerId">(),
    assignedAt: ASSIGNED_AT,
    ttlMs,
  });
  if (Result.isErr(result)) throw new Error("fixture setup failed");
  return result.value;
}

describe("ReviewAssignment", () => {
  it("expires the claim the configured duration after it was taken", () => {
    const assignment = claim(60_000);

    expect(assignment.assignedAt).toEqual(ASSIGNED_AT);
    expect(assignment.claimExpiresAt).toEqual(new Date(ASSIGNED_AT.getTime() + 60_000));
  });

  it("uses the default lease when no duration is given", () => {
    const assignment = claim();

    expect(assignment.claimExpiresAt).toEqual(
      new Date(ASSIGNED_AT.getTime() + DEFAULT_CLAIM_TTL_MS),
    );
  });

  it("is active right up to the expiry instant, and expired from it", () => {
    const assignment = claim(60_000);
    const justBefore = new Date(ASSIGNED_AT.getTime() + 59_999);
    const atExpiry = new Date(ASSIGNED_AT.getTime() + 60_000);
    const after = new Date(ASSIGNED_AT.getTime() + 120_000);

    expect(assignment.isActiveAt(ASSIGNED_AT)).toBe(true);
    expect(assignment.isActiveAt(justBefore)).toBe(true);
    // The boundary is deliberately exclusive: the claim is over the moment it
    // expires, so `isActiveAt(expiry) === false` and `isExpiredAt` agree
    // without overlapping.
    expect(assignment.isActiveAt(atExpiry)).toBe(false);
    expect(assignment.isExpiredAt(atExpiry)).toBe(true);
    expect(assignment.isExpiredAt(after)).toBe(true);
  });

  it("knows which reviewer holds it", () => {
    const assignment = claim(60_000);
    const holder = assignment.reviewerId;

    expect(assignment.isHeldBy(holder)).toBe(true);
    expect(assignment.isHeldBy(createId<"ReviewerId">())).toBe(false);
  });

  it("refuses a non-positive or non-finite lease", () => {
    for (const ttlMs of [0, -1, Number.POSITIVE_INFINITY, Number.NaN]) {
      const result = ReviewAssignment.claim({
        requestId: createId<"VerificationRequestId">(),
        reviewerId: createId<"ReviewerId">(),
        assignedAt: ASSIGNED_AT,
        ttlMs,
      });

      expect(Result.isErr(result), `ttlMs=${String(ttlMs)}`).toBe(true);
    }
  });

  it("reconstitutes a claim read back from storage without re-deriving its expiry", () => {
    const requestId = createId<"VerificationRequestId">() as VerificationRequestId;
    const reviewerId = createId<"ReviewerId">();
    const claimExpiresAt = new Date(ASSIGNED_AT.getTime() + 90_000);

    const reconstituted = ReviewAssignment.reconstitute({
      requestId,
      reviewerId,
      assignedAt: ASSIGNED_AT,
      claimExpiresAt,
    });

    expect(reconstituted.requestId).toBe(requestId);
    expect(reconstituted.claimExpiresAt).toEqual(claimExpiresAt);
  });
});
