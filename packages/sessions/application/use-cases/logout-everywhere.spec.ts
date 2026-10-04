import { asId } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { Session, type SessionUserId } from "../../domain/entities/session.js";
import { InMemoryRevocationList } from "../../infrastructure/testing/in-memory-revocation-list.js";
import { InMemorySessionRepository } from "../../infrastructure/testing/in-memory-session-repository.js";

import { LogoutEverywhere } from "./logout-everywhere.js";

const userId: SessionUserId = asId("11111111-1111-1111-1111-111111111111");
const otherUserId: SessionUserId = asId("22222222-2222-2222-2222-222222222222");

function issueSessionFor(userId: SessionUserId, tokenId: string, now = new Date()) {
  return Session.issue({
    userId,
    metadata: {},
    accessToken: { tokenId, expiresAt: new Date(now.getTime() + 60_000) },
    now,
  }).session;
}

describe("LogoutEverywhere", () => {
  let sessionRepository: InMemorySessionRepository;
  let revocationList: InMemoryRevocationList;
  let logoutEverywhere: LogoutEverywhere;

  beforeEach(() => {
    sessionRepository = new InMemorySessionRepository();
    revocationList = new InMemoryRevocationList();
    logoutEverywhere = new LogoutEverywhere(sessionRepository, revocationList);
  });

  it("revokes every active session for the user across multiple concurrent sessions", async () => {
    const sessionA = issueSessionFor(userId, "token-a");
    const sessionB = issueSessionFor(userId, "token-b");
    const sessionC = issueSessionFor(userId, "token-c");
    await sessionRepository.save(sessionA);
    await sessionRepository.save(sessionB);
    await sessionRepository.save(sessionC);

    const result = await logoutEverywhere.execute({ userId });

    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") throw new Error("unreachable");
    expect(result.value.revokedCount).toBe(3);

    for (const session of [sessionA, sessionB, sessionC]) {
      const stored = await sessionRepository.findById(session.id);
      expect(stored!.isRevoked).toBe(true);
    }
  });

  it("denylists every revoked session's current access token", async () => {
    await sessionRepository.save(issueSessionFor(userId, "token-a"));
    await sessionRepository.save(issueSessionFor(userId, "token-b"));

    await logoutEverywhere.execute({ userId });

    expect(await revocationList.isRevoked("token-a")).toBe(true);
    expect(await revocationList.isRevoked("token-b")).toBe(true);
  });

  it("does not touch another user's sessions", async () => {
    const ownSession = issueSessionFor(userId, "token-a");
    const otherSession = issueSessionFor(otherUserId, "token-other");
    await sessionRepository.save(ownSession);
    await sessionRepository.save(otherSession);

    await logoutEverywhere.execute({ userId });

    const stored = await sessionRepository.findById(otherSession.id);
    expect(stored!.isRevoked).toBe(false);
  });

  it("leaves a session created after the call unaffected", async () => {
    await sessionRepository.save(issueSessionFor(userId, "token-a"));

    await logoutEverywhere.execute({ userId });

    const newSession = issueSessionFor(userId, "token-b");
    await sessionRepository.save(newSession);

    const stored = await sessionRepository.findById(newSession.id);
    expect(stored!.isRevoked).toBe(false);
  });

  it("succeeds with a zero count when the user has no active sessions", async () => {
    const result = await logoutEverywhere.execute({ userId });

    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") throw new Error("unreachable");
    expect(result.value.revokedCount).toBe(0);
  });
});
