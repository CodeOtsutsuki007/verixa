import { describe, expect, it } from "vitest";

import { asSessionId, createSessionId } from "./session-id.js";

describe("SessionId", () => {
  it("generates a syntactically valid UUID", () => {
    const id = createSessionId();

    // v4 UUID shape. The brand is compile-time only, so at runtime the value
    // is just the string createId produced — this asserts that much is real.
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  it("generates a distinct id on each call", () => {
    const ids = new Set(Array.from({ length: 1000 }, () => createSessionId()));

    expect(ids.size).toBe(1000);
  });

  it("preserves the underlying string when branding a trusted value", () => {
    const raw = "11111111-1111-4111-8111-111111111111";

    expect(asSessionId(raw)).toBe(raw);
  });
});
