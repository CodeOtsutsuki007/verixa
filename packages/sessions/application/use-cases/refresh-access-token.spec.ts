import { asId } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";

import { Session, type SessionUserId } from "../../domain/entities/session.js";
import { InMemorySessionRepository } from "../../infrastructure/testing/in-memory-session-repository.js";
import { InMemoryTokenSigner } from "../../infrastructure/testing/in-memory-token-signer.js";

import { RefreshAccessToken } from "./refresh-access-token.js";

const userId: SessionUserId = asId("11111111-1111-1111-1111-111111111111");

describe("RefreshAccessToken", () => {
  let sessionRepository: InMemorySessionRepository;
  let tokenSigner: InMemoryTokenSigner;
  let refreshAccessToken: RefreshAccessToken;

  beforeEach(() => {
    sessionRepository = new InMemorySessionRepository();
    tokenSigner = new InMemoryTokenSigner();
    refreshAccessToken = new RefreshAccessToken(sessionRepository, tokenSigner);
  });

  it("issues a new access token for a valid session and refresh token", async () => {
    const now = new Date();
    const { session, rawRefreshToken } = Session.issue({
      userId,
      metadata: { ipAddress: "203.0.113.10" },
      accessToken: { tokenId: "token-1", expiresAt: new Date(now.getTime() + 60_000) },
      now,
    });
    await sessionRepository.save(session);

    const result = await refreshAccessToken.execute({
      sessionId: session.id,
      refreshToken: rawRefreshToken,
      metadata: { ipAddress: "203.0.113.10" },
    });

    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") throw new Error("unreachable");
    expect(result.value.accessToken).toBeTruthy();
    expect(result.value.session.currentAccessToken!.tokenId).not.toBe("token-1");
  });

  it("records a new metadata observation when the presented IP/user-agent changed", async () => {
    const now = new Date("2026-01-01T00:00:00Z");
    const { session, rawRefreshToken } = Session.issue({
      userId,
      metadata: { ipAddress: "203.0.113.10" },
      accessToken: { tokenId: "token-1", expiresAt: new Date(now.getTime() + 60_000) },
      now,
    });
    await sessionRepository.save(session);

    const result = await refreshAccessToken.execute({
      sessionId: session.id,
      refreshToken: rawRefreshToken,
      metadata: { ipAddress: "198.51.100.20" },
      now: new Date(now.getTime() + 60_000),
    });

    if (result.kind !== "ok") throw new Error("unreachable");
    expect(result.value.session.metadataHistory).toHaveLength(2);
    expect(result.value.session.currentMetadata).toEqual({ ipAddress: "198.51.100.20" });
  });

  it("does not add a metadata observation when nothing changed", async () => {
    const now = new Date();
    const metadata = { ipAddress: "203.0.113.10" };
    const { session, rawRefreshToken } = Session.issue({
      userId,
      metadata,
      accessToken: { tokenId: "token-1", expiresAt: new Date(now.getTime() + 60_000) },
      now,
    });
    await sessionRepository.save(session);

    const result = await refreshAccessToken.execute({
      sessionId: session.id,
      refreshToken: rawRefreshToken,
      metadata,
    });

    if (result.kind !== "ok") throw new Error("unreachable");
    expect(result.value.session.metadataHistory).toHaveLength(1);
  });

  it("rejects an unknown session id", async () => {
    const result = await refreshAccessToken.execute({
      sessionId: "does-not-exist",
      refreshToken: "whatever",
      metadata: {},
    });

    expect(result.kind).toBe("err");
  });

  it("rejects a refresh token that does not match the session", async () => {
    const now = new Date();
    const { session } = Session.issue({
      userId,
      metadata: {},
      accessToken: { tokenId: "token-1", expiresAt: new Date(now.getTime() + 60_000) },
      now,
    });
    await sessionRepository.save(session);

    const result = await refreshAccessToken.execute({
      sessionId: session.id,
      refreshToken: "wrong-token",
      metadata: {},
    });

    expect(result.kind).toBe("err");
  });

  it("rejects a revoked session", async () => {
    const now = new Date();
    const { session, rawRefreshToken } = Session.issue({
      userId,
      metadata: {},
      accessToken: { tokenId: "token-1", expiresAt: new Date(now.getTime() + 60_000) },
      now,
    });
    await sessionRepository.save(session.revoke(now));

    const result = await refreshAccessToken.execute({
      sessionId: session.id,
      refreshToken: rawRefreshToken,
      metadata: {},
    });

    expect(result.kind).toBe("err");
  });

  it("rejects an expired session", async () => {
    const now = new Date("2026-01-01T00:00:00Z");
    const { session, rawRefreshToken } = Session.issue({
      userId,
      metadata: {},
      accessToken: { tokenId: "token-1", expiresAt: new Date(now.getTime() + 60_000) },
      ttlMs: 1000,
      now,
    });
    await sessionRepository.save(session);

    const result = await refreshAccessToken.execute({
      sessionId: session.id,
      refreshToken: rawRefreshToken,
      metadata: {},
      now: new Date(now.getTime() + 2000),
    });

    expect(result.kind).toBe("err");
  });
});
