import { asId } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { Session, type SessionUserId } from "../../domain/entities/session.js";
import { InMemoryRevocationList } from "../../infrastructure/testing/in-memory-revocation-list.js";
import { InMemorySessionRepository } from "../../infrastructure/testing/in-memory-session-repository.js";

import { Logout } from "./logout.js";

const userId: SessionUserId = asId("11111111-1111-1111-1111-111111111111");

describe("Logout", () => {
  let sessionRepository: InMemorySessionRepository;
  let revocationList: InMemoryRevocationList;
  let logout: Logout;

  beforeEach(() => {
    sessionRepository = new InMemorySessionRepository();
    revocationList = new InMemoryRevocationList();
    logout = new Logout(sessionRepository, revocationList);
  });

  it("revokes the session so it can no longer be used to refresh", async () => {
    const now = new Date();
    const { session } = Session.issue({
      userId,
      metadata: {},
      accessToken: { tokenId: "token-1", expiresAt: new Date(now.getTime() + 60_000) },
      now,
    });
    await sessionRepository.save(session);

    const result = await logout.execute({ sessionId: session.id });

    expect(result.kind).toBe("ok");
    const stored = await sessionRepository.findById(session.id);
    expect(stored!.isRevoked).toBe(true);
  });

  it("denylists the session's current access token so it fails isRevoked checks", async () => {
    const now = new Date();
    const { session } = Session.issue({
      userId,
      metadata: {},
      accessToken: { tokenId: "token-1", expiresAt: new Date(now.getTime() + 60_000) },
      now,
    });
    await sessionRepository.save(session);

    await logout.execute({ sessionId: session.id });

    expect(await revocationList.isRevoked("token-1")).toBe(true);
  });

  it("succeeds idempotently when the session does not exist", async () => {
    const result = await logout.execute({ sessionId: "does-not-exist" });

    expect(result.kind).toBe("ok");
  });

  it("succeeds idempotently when the session is already revoked", async () => {
    const now = new Date();
    const { session } = Session.issue({
      userId,
      metadata: {},
      accessToken: { tokenId: "token-1", expiresAt: new Date(now.getTime() + 60_000) },
      now,
    });
    await sessionRepository.save(session.revoke(now));

    const result = await logout.execute({ sessionId: session.id });

    expect(result.kind).toBe("ok");
  });
});
