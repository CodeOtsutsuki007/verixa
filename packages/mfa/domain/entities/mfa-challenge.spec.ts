import { asId } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { MfaChallenge, type MfaChallengeUserId } from "./mfa-challenge.js";

const userId: MfaChallengeUserId = asId("11111111-1111-1111-1111-111111111111");

describe("MfaChallenge", () => {
  it("creates a challenge with a 5-minute default expiration", () => {
    const now = new Date("2025-01-01T00:00:00.000Z");
    const challenge = MfaChallenge.create({ userId, now });

    expect(challenge.userId).toBe(userId);
    expect(challenge.isConsumed).toBe(false);
    expect(challenge.isExpired(now)).toBe(false);
    expect(challenge.isValid(now)).toBe(true);
    expect(challenge.expiresAt.getTime()).toBe(now.getTime() + 5 * 60 * 1000);
  });

  it("detects expiration correctly", () => {
    const now = new Date("2025-01-01T00:00:00.000Z");
    const challenge = MfaChallenge.create({
      userId,
      expiresAt: new Date("2025-01-01T00:05:00.000Z"),
      now,
    });

    expect(challenge.isExpired(new Date("2025-01-01T00:04:59.000Z"))).toBe(false);
    expect(challenge.isExpired(new Date("2025-01-01T00:05:00.000Z"))).toBe(true);
    expect(challenge.isExpired(new Date("2025-01-01T00:06:00.000Z"))).toBe(true);
    expect(challenge.isValid(new Date("2025-01-01T00:05:00.000Z"))).toBe(false);
  });

  it("supports single-use consumption and rejects reuse", () => {
    const now = new Date("2025-01-01T00:00:00.000Z");
    const challenge = MfaChallenge.create({ userId, now });

    expect(challenge.isConsumed).toBe(false);

    const consumed = challenge.consume(now);
    expect(consumed.isConsumed).toBe(true);
    expect(consumed.consumedAt).toEqual(now);
    expect(consumed.isValid(now)).toBe(false);

    expect(() => consumed.consume(now)).toThrow("MfaChallenge has already been consumed.");
  });

  it("rejects consumption of an expired challenge", () => {
    const now = new Date("2025-01-01T00:00:00.000Z");
    const challenge = MfaChallenge.create({
      userId,
      expiresAt: new Date("2025-01-01T00:05:00.000Z"),
      now,
    });

    const future = new Date("2025-01-01T00:06:00.000Z");
    expect(() => challenge.consume(future)).toThrow("MfaChallenge has expired.");
  });
});
