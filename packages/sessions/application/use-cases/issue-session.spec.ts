import { asId } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import type { SessionUserId } from "../../domain/entities/session.js";
import { InMemoryRevocationList } from "../../infrastructure/testing/in-memory-revocation-list.js";
import { InMemorySessionAuditLogger } from "../../infrastructure/testing/in-memory-session-audit-logger.js";
import { InMemorySessionRepository } from "../../infrastructure/testing/in-memory-session-repository.js";
import { InMemoryTokenSigner } from "../../infrastructure/testing/in-memory-token-signer.js";

import { IssueSession } from "./issue-session.js";

const userId: SessionUserId = asId("11111111-1111-1111-1111-111111111111");

describe("IssueSession", () => {
  let sessionRepository: InMemorySessionRepository;
  let revocationList: InMemoryRevocationList;
  let auditLogger: InMemorySessionAuditLogger;
  let tokenSigner: InMemoryTokenSigner;

  beforeEach(() => {
    sessionRepository = new InMemorySessionRepository();
    revocationList = new InMemoryRevocationList();
    auditLogger = new InMemorySessionAuditLogger();
    tokenSigner = new InMemoryTokenSigner();
  });

  it("issues a session carrying the supplied metadata", async () => {
    const useCase = new IssueSession(sessionRepository, tokenSigner, revocationList, auditLogger);

    const result = await useCase.execute({
      userId,
      metadata: { ipAddress: "203.0.113.10", userAgent: "curl/8.0" },
    });

    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") throw new Error("unreachable");
    expect(result.value.session.userId).toBe(userId);
    expect(result.value.session.currentMetadata).toEqual({
      ipAddress: "203.0.113.10",
      userAgent: "curl/8.0",
    });
    expect(result.value.accessToken).toBeTruthy();
    expect(result.value.rawRefreshToken).toBeTruthy();

    const stored = await sessionRepository.findById(result.value.session.id);
    expect(stored).toBeDefined();
  });

  describe("concurrent session limit", () => {
    it("does not evict anything when the limit is 0 (disabled)", async () => {
      const useCase = new IssueSession(
        sessionRepository,
        tokenSigner,
        revocationList,
        auditLogger,
        0,
      );

      for (let i = 0; i < 5; i++) {
        await useCase.execute({ userId, metadata: {} });
      }

      const active = await sessionRepository.findActiveByUserId(userId, new Date());
      expect(active).toHaveLength(5);
      expect(auditLogger.entries).toHaveLength(0);
    });

    it("evicts the oldest session once a login would exceed the limit", async () => {
      const useCase = new IssueSession(
        sessionRepository,
        tokenSigner,
        revocationList,
        auditLogger,
        2,
      );

      const first = await useCase.execute({
        userId,
        metadata: {},
        now: new Date("2026-01-01T00:00:00Z"),
      });
      await useCase.execute({ userId, metadata: {}, now: new Date("2026-01-01T00:01:00Z") });
      await useCase.execute({ userId, metadata: {}, now: new Date("2026-01-01T00:02:00Z") });

      if (first.kind !== "ok") throw new Error("unreachable");

      const active = await sessionRepository.findActiveByUserId(
        userId,
        new Date("2026-01-01T00:03:00Z"),
      );
      expect(active).toHaveLength(2);
      expect(active.some((session) => session.id === first.value.session.id)).toBe(false);

      const evicted = await sessionRepository.findById(first.value.session.id);
      expect(evicted!.isRevoked).toBe(true);
    });

    it("denylists the evicted session's access token", async () => {
      const useCase = new IssueSession(
        sessionRepository,
        tokenSigner,
        revocationList,
        auditLogger,
        1,
      );

      const first = await useCase.execute({ userId, metadata: {} });
      await useCase.execute({ userId, metadata: {} });

      if (first.kind !== "ok") throw new Error("unreachable");

      const evicted = await sessionRepository.findById(first.value.session.id);
      const evictedTokenId = evicted!.currentAccessToken!.tokenId;
      expect(await revocationList.isRevoked(evictedTokenId)).toBe(true);
    });

    it("logs each eviction", async () => {
      const useCase = new IssueSession(
        sessionRepository,
        tokenSigner,
        revocationList,
        auditLogger,
        1,
      );

      await useCase.execute({ userId, metadata: {} });
      await useCase.execute({ userId, metadata: {} });

      expect(auditLogger.entries).toHaveLength(1);
      expect(auditLogger.entries[0]!.action).toBe("session.evicted");
      expect(auditLogger.entries[0]!.actorId).toBe(userId);
      expect(auditLogger.entries[0]!.metadata?.["reason"]).toBe("concurrent_session_limit");
    });

    it("evicts more than one session if the limit was lowered below the existing count", async () => {
      // Simulates three sessions issued while unbounded, then a login
      // arriving after an admin has since lowered the limit to 1.
      const unbounded = new IssueSession(
        sessionRepository,
        tokenSigner,
        revocationList,
        auditLogger,
        0,
      );
      await unbounded.execute({ userId, metadata: {}, now: new Date("2026-01-01T00:00:00Z") });
      await unbounded.execute({ userId, metadata: {}, now: new Date("2026-01-01T00:01:00Z") });
      await unbounded.execute({ userId, metadata: {}, now: new Date("2026-01-01T00:02:00Z") });

      const limited = new IssueSession(
        sessionRepository,
        tokenSigner,
        revocationList,
        auditLogger,
        1,
      );
      await limited.execute({ userId, metadata: {}, now: new Date("2026-01-01T00:03:00Z") });

      const active = await sessionRepository.findActiveByUserId(
        userId,
        new Date("2026-01-01T00:04:00Z"),
      );
      expect(active).toHaveLength(1);
    });
  });
});
