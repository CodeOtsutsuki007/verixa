import type { SigningKeyConfig } from "@verixa/config";
import { describe, expect, it } from "vitest";

import { createConfigSigningKeyProvider } from "./signing-key-provider.js";
import { asCurrent, asRetired, generateTestKey } from "./testing/signing-key-fixtures.js";

describe("createConfigSigningKeyProvider", () => {
  it("exposes the single current key as the signing key", async () => {
    const current = generateTestKey("current");
    const provider = await createConfigSigningKeyProvider([asCurrent(current)]);

    expect(provider.signingKey().kid).toBe("current");
  });

  it("verifies against both the current key and retired keys", async () => {
    const current = generateTestKey("current");
    const retired = generateTestKey("retired");

    const provider = await createConfigSigningKeyProvider([asCurrent(current), asRetired(retired)]);

    expect(provider.verificationKey("current")).toBeDefined();
    expect(provider.verificationKey("retired")).toBeDefined();
    expect(new Set(provider.verificationKids())).toEqual(new Set(["current", "retired"]));
  });

  it("returns undefined for a kid it does not hold", async () => {
    const current = generateTestKey("current");
    const provider = await createConfigSigningKeyProvider([asCurrent(current)]);

    expect(provider.verificationKey("never-heard-of-it")).toBeUndefined();
  });

  it("reports the distinct algorithms across the key set", async () => {
    const current = generateTestKey("current", "ES256");
    const retired = generateTestKey("retired", "RS256");

    const provider = await createConfigSigningKeyProvider([asCurrent(current), asRetired(retired)]);

    expect(new Set(provider.algorithms())).toEqual(new Set(["ES256", "RS256"]));
  });

  it("refuses to build with no keys", async () => {
    await expect(createConfigSigningKeyProvider([])).rejects.toThrow(/no keys/i);
  });

  it("refuses to build when the current key has no private half", async () => {
    // A hand-built set that never went through loadSigningKeys — the factory
    // still defends itself rather than trusting the caller.
    const current = generateTestKey("current");
    const brokenCurrent: SigningKeyConfig = {
      kid: current.kid,
      algorithm: current.algorithm,
      publicKey: current.publicKey,
      current: true,
    };

    await expect(createConfigSigningKeyProvider([brokenCurrent])).rejects.toThrow(
      /exactly one current key with a private key/i,
    );
  });

  it("names the offending kid when a PEM cannot be imported", async () => {
    const broken: SigningKeyConfig = {
      kid: "corrupt",
      algorithm: "ES256",
      publicKey: "-----BEGIN PUBLIC KEY-----\nnot-real-base64!!\n-----END PUBLIC KEY-----\n",
      privateKey: generateTestKey("corrupt").privateKey,
      current: true,
    };

    await expect(createConfigSigningKeyProvider([broken])).rejects.toThrow(/kid "corrupt"/);
  });
});
