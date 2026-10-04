import { describe, expect, it } from "vitest";

import { createSessionId } from "../../domain/value-objects/session-id.js";

import { revocationListContract } from "./contracts/revocation-list.contract.js";
import { InMemoryRevocationList } from "./in-memory-revocation-list.js";

describe("InMemoryRevocationList", () => {
  revocationListContract(() => new InMemoryRevocationList());

  it("stops reporting a session as revoked once its TTL elapses", async () => {
    // A controllable clock lets us cross the expiry boundary without sleeping.
    let now = 1_000_000;
    const list = new InMemoryRevocationList(() => now);
    const sessionId = createSessionId();

    await list.revoke(sessionId, 30);
    expect(await list.isRevoked(sessionId)).toBe(true);

    now += 29_000; // still inside the 30s window
    expect(await list.isRevoked(sessionId)).toBe(true);

    now += 2_000; // now past it
    expect(await list.isRevoked(sessionId)).toBe(false);
  });
});
