import { createId } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";
import {
  ReviewAssignment,
  type ReviewerId,
  type VerificationRequestId,
} from "./review-assignment.js";

describe("ReviewAssignment", () => {
  const requestId = createId<"VerificationRequestId">();
  const reviewerId = createId<"ReviewerId">();

  it("creates a valid review assignment with future expiration", () => {
    const assignedAt = new Date("2026-01-01T00:00:00Z");
    const claimExpiresAt = new Date("2026-01-01T00:30:00Z");

    const result = ReviewAssignment.create({
      requestId,
      reviewerId,
      assignedAt,
      claimExpiresAt,
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.requestId).toBe(requestId);
      expect(result.value.reviewerId).toBe(reviewerId);
      expect(result.value.isActive(new Date("2026-01-01T00:15:00Z"))).toBe(true);
      expect(result.value.isExpired(new Date("2026-01-01T00:15:00Z"))).toBe(false);
    }
  });

  it("rejects assignment where expiration is before or equal to assignment time", () => {
    const assignedAt = new Date("2026-01-01T00:30:00Z");
    const claimExpiresAt = new Date("2026-01-01T00:00:00Z");

    const result = ReviewAssignment.create({
      requestId,
      reviewerId,
      assignedAt,
      claimExpiresAt,
    });

    expect(result.ok).toBe(false);
  });

  it("correctly identifies expiration status", () => {
    const assignedAt = new Date("2026-01-01T00:00:00Z");
    const claimExpiresAt = new Date("2026-01-01T00:30:00Z");

    const assignment = ReviewAssignment.create({
      requestId,
      reviewerId,
      assignedAt,
      claimExpiresAt,
    });

    if (!assignment.ok) throw new Error("setup failed");

    expect(assignment.value.isExpired(new Date("2026-01-01T00:29:59Z"))).toBe(false);
    expect(assignment.value.isExpired(new Date("2026-01-01T00:30:00Z"))).toBe(true);
    expect(assignment.value.isExpired(new Date("2026-01-01T00:35:00Z"))).toBe(true);
  });

  it("allows extending an active claim", () => {
    const assignedAt = new Date("2026-01-01T00:00:00Z");
    const claimExpiresAt = new Date("2026-01-01T00:30:00Z");

    const assignment = ReviewAssignment.create({
      requestId,
      reviewerId,
      assignedAt,
      claimExpiresAt,
    });

    if (!assignment.ok) throw new Error("setup failed");

    const extended = assignment.value.extend(new Date("2026-01-01T01:00:00Z"));
    expect(extended.ok).toBe(true);
    if (extended.ok) {
      expect(extended.value.claimExpiresAt).toEqual(new Date("2026-01-01T01:00:00Z"));
    }
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
