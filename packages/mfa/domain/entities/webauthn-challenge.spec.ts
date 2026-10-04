import { asId } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { WebAuthnChallenge } from "./webauthn-challenge.js";

describe("WebAuthnChallenge", () => {
  const userId = asId<"UserId">("user-1");

  it("creates challenge with 5 minute default TTL", () => {
    const now = new Date("2026-09-25T12:00:00Z");
    const challenge = WebAuthnChallenge.create({
      userId,
      challenge: "random-challenge-str",
      ceremonyType: "registration",
      now,
    });

    expect(challenge.id).toBeDefined();
    expect(challenge.challenge).toBe("random-challenge-str");
    expect(challenge.ceremonyType).toBe("registration");
    expect(challenge.used).toBe(false);
    expect(challenge.isExpired(now)).toBe(false);

    const after3Min = new Date(now.getTime() + 3 * 60 * 1000);
    expect(challenge.isExpired(after3Min)).toBe(false);

    const after6Min = new Date(now.getTime() + 6 * 60 * 1000);
    expect(challenge.isExpired(after6Min)).toBe(true);
  });

  it("consumes challenge and prevents reuse", () => {
    const challenge = WebAuthnChallenge.create({
      userId,
      challenge: "ch-123",
      ceremonyType: "registration",
    });

    const consumed = challenge.consume();
    expect(consumed.used).toBe(true);
    expect(() => consumed.consume()).toThrow("Challenge has already been consumed.");
  });

  it("reconstitutes from persisted data", () => {
    const now = new Date();
    const challenge = WebAuthnChallenge.reconstitute({
      id: asId("ch-id"),
      userId,
      challenge: "ch-val",
      ceremonyType: "registration",
      createdAt: now,
      expiresAt: new Date(now.getTime() + 60000),
      used: true,
    });

    expect(challenge.id).toBe("ch-id");
    expect(challenge.used).toBe(true);
  });
});
