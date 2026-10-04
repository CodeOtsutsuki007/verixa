import { asId } from "@verixa/shared-kernel";
import { describe, expect, it, vi } from "vitest";

import { MfaChallenge, type MfaChallengeUserId } from "../../domain/entities/mfa-challenge.js";
import { ConsumeMfaChallenge, type MfaChallengeRepository } from "./consume-mfa-challenge.js";

const userId: MfaChallengeUserId = asId("11111111-1111-1111-1111-111111111111");

describe("ConsumeMfaChallenge", () => {
  it("consumes a valid challenge and calls IssueSession exactly once", async () => {
    const now = new Date("2025-01-01T00:00:00.000Z");
    const challenge = MfaChallenge.create({ userId, now });

    const challengeRepo: MfaChallengeRepository = {
      findById: async () => challenge,
      save: async () => {},
    };

    const issueSessionMock = {
      execute: vi.fn().mockResolvedValue({
        isOk: true,
        value: { session: {}, accessToken: "token", rawRefreshToken: "refresh" },
      }),
    } as any;

    const useCase = new ConsumeMfaChallenge(challengeRepo, issueSessionMock);

    const result = await useCase.execute({
      challengeId: challenge.id,
      issueSessionCommand: {
        userId: userId,
        metadata: { ipAddress: "127.0.0.1", userAgent: "test" },
        now,
      },
      now,
    });

    expect(result.isOk).toBe(true);
    expect(issueSessionMock.execute).toHaveBeenCalledTimes(1);
  });

  it("rejects an expired challenge and does not call IssueSession", async () => {
    const now = new Date(
      "2025-01-01T00:00:00.000Z"
    );
    const challenge = MfaChallenge.create({
      userId,
      expiresAt: new Date("2025-01-01T00:05:00.000Z"),
      now,
    });

    const challengeRepo: MfaChallengeRepository = {
      findById: async () => challenge,
      save: async () => {},
    };

    const issueSessionMock = {
      execute: vi.fn(),
    } as any;

    const useCase = new ConsumeMfaChallenge(challengeRepo, issueSessionMock);

    const future = new Date("2025-01-01T00:06:00.000Z");
    const result = await useCase.execute({
      challengeId: challenge.id,
      issueSessionCommand: {
        userId: userId,
        metadata: { ipAddress: "127.0.0.1", userAgent: "test" },
        now: future,
      },
      now: future,
    });

    expect(result.isErr).toBe(true);
    expect(result.error).toBe("CHALLENGE_EXPIRED");
    expect(issueSessionMock.execute).not.toHaveBeenCalled();
  });

  it("rejects an already consumed challenge (single-use enforcement) and does not call IssueSession", async () => {
    const now = new Date("2025-01-01T00:00:00.000Z");
    const challenge = MfaChallenge.create({ userId, now }).consume(now);

    const challengeRepo: MfaChallengeRepository = {
      findById: async () => challenge,
      save: async () => {},
    };

    const issueSessionMock = {
      execute: vi.fn(),
    } as any;

    const useCase = new ConsumeMfaChallenge(challengeRepo, issueSessionMock);

    const result = await useCase.execute({
      challengeId: challenge.id,
      issueSessionCommand: {
        userId: userId,
        metadata: { ipAddress: "127.0.0.1", userAgent: "test" },
        now,
      },
      now,
    });

    expect(result.isErr).toBe(true);
    expect(result.error).toBe("CHALLENGE_ALREADY_CONSUMED");
    expect(issueSessionMock.execute).not.toHaveBeenCalled();
  });
});
