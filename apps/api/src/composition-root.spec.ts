import { describe, expect, it } from "vitest";

import { buildContainer } from "./composition-root.js";

describe("Composition Root boot smoke test", () => {
  it("resolves all domain contexts and use cases including MFA", async () => {
    const container = buildContainer();

    // Identity context
    expect(container.identity).toBeDefined();
    expect(container.identity.registerUser).toBeDefined();
    expect(container.identity.updateUserProfile).toBeDefined();

    // Credentials context
    expect(container.credentials).toBeDefined();
    expect(container.credentials.authenticateWithPassword).toBeDefined();
    expect(container.credentials.registerUserWithPassword).toBeDefined();

    // Audit context
    expect(container.audit).toBeDefined();
    expect(container.audit.recordEvent).toBeDefined();

    // MFA context (Issue 119)
    expect(container.mfa).toBeDefined();
    expect(container.mfa.registerWebAuthnCredential).toBeDefined();
    expect(container.mfa.verifyWebAuthnAssertion).toBeDefined();

    await container.dispose();
  });
});
