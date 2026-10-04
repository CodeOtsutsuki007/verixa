import { describe, expect, it } from "vitest";

import { ConfigError } from "./config-error.js";
import { loadSigningKeys, SIGNING_KEYS_ENV_VAR, type SigningKeyConfig } from "./signing-keys.js";

// Stand-in PEM bodies. loadSigningKeys validates structure, not cryptography —
// whether these are importable keys is the signing-key provider's concern, so
// here any non-empty string exercises the same code paths without the cost of
// generating real key pairs.
const PUBLIC_PEM = "-----BEGIN PUBLIC KEY-----\nMEE=\n-----END PUBLIC KEY-----\n";
const PRIVATE_PEM = "-----BEGIN PRIVATE KEY-----\nMEE=\n-----END PRIVATE KEY-----\n";

function env(keys: unknown): Record<string, string | undefined> {
  return { [SIGNING_KEYS_ENV_VAR]: JSON.stringify(keys) };
}

const currentKey = {
  kid: "2026-09-current",
  algorithm: "RS256",
  publicKey: PUBLIC_PEM,
  privateKey: PRIVATE_PEM,
  current: true,
};

const retiredKey = {
  kid: "2026-06-retired",
  algorithm: "RS256",
  publicKey: PUBLIC_PEM,
  current: false,
};

describe("loadSigningKeys", () => {
  it("returns an empty set when the variable is unset", () => {
    expect(loadSigningKeys({})).toEqual([]);
  });

  it("returns an empty set when the variable is blank", () => {
    expect(loadSigningKeys({ [SIGNING_KEYS_ENV_VAR]: "   " })).toEqual([]);
  });

  it("parses a single current key", () => {
    const keys = loadSigningKeys(env([currentKey]));

    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatchObject({
      kid: "2026-09-current",
      algorithm: "RS256",
      current: true,
      privateKey: PRIVATE_PEM,
      publicKey: PUBLIC_PEM,
    });
  });

  it("parses a current key alongside a verification-only retired key", () => {
    const keys = loadSigningKeys(env([currentKey, retiredKey]));

    expect(keys.map((key: SigningKeyConfig) => key.kid)).toEqual([
      "2026-09-current",
      "2026-06-retired",
    ]);
    // The retired key carries no private half — verification only.
    expect(keys[1]?.privateKey).toBeUndefined();
  });

  it("defaults `current` to false when omitted", () => {
    const keys = loadSigningKeys(
      env([currentKey, { kid: "k2", algorithm: "ES256", publicKey: PUBLIC_PEM }]),
    );

    expect(keys[1]?.current).toBe(false);
  });

  it("throws when the value is not valid JSON", () => {
    expect(() => loadSigningKeys({ [SIGNING_KEYS_ENV_VAR]: "{not json" })).toThrowError(
      ConfigError,
    );
  });

  it("throws when two keys share a kid", () => {
    const clash = { ...retiredKey, kid: currentKey.kid };

    expect(() => loadSigningKeys(env([currentKey, clash]))).toThrowError(/Duplicate key ids/);
  });

  it("throws when no key is marked current", () => {
    expect(() => loadSigningKeys(env([retiredKey]))).toThrowError(/Exactly one key must be marked/);
  });

  it("throws when more than one key is marked current", () => {
    const second = { ...currentKey, kid: "another-current" };

    expect(() => loadSigningKeys(env([currentKey, second]))).toThrowError(
      /Exactly one key must be marked/,
    );
  });

  it("throws when the current key has no private key to sign with", () => {
    const withoutPrivate = {
      kid: currentKey.kid,
      algorithm: currentKey.algorithm,
      publicKey: currentKey.publicKey,
      current: true,
    };

    expect(() => loadSigningKeys(env([withoutPrivate]))).toThrowError(/must include a privateKey/);
  });

  it("throws on an unsupported algorithm", () => {
    const symmetric = { ...currentKey, algorithm: "HS256" };

    expect(() => loadSigningKeys(env([symmetric]))).toThrowError(ConfigError);
  });

  it("rejects unknown properties rather than silently ignoring them", () => {
    const typo = { ...currentKey, piblicKey: PUBLIC_PEM };

    expect(() => loadSigningKeys(env([typo]))).toThrowError(ConfigError);
  });

  it("returns a frozen set", () => {
    const keys = loadSigningKeys(env([currentKey]));

    expect(Object.isFrozen(keys)).toBe(true);
    expect(() => {
      (keys as SigningKeyConfig[]).push(retiredKey as SigningKeyConfig);
    }).toThrow(TypeError);
  });
});
