import { generateKeyPairSync } from "node:crypto";

import type { SigningKeyAlgorithm, SigningKeyConfig } from "@verixa/config";

/**
 * Real, freshly generated key material for tests, plus builders that turn it
 * into the two shapes a rotation scenario needs: a *current* key (carries its
 * private half, signs new tokens) and a *retired* key (public half only, still
 * verifies old tokens). Kept out of the specs themselves so a test reads as the
 * rotation story it is telling, not as key-generation boilerplate.
 *
 * These are generated per call and never persisted — no fixture key is ever
 * committed, which also keeps the repo's secret scanner from firing on a PEM.
 */
export interface TestKeyPair {
  readonly kid: string;
  readonly algorithm: SigningKeyAlgorithm;
  readonly publicKey: string;
  readonly privateKey: string;
}

/**
 * Generates a key pair as SPKI/PKCS#8 PEM for the given algorithm. Defaults to
 * ES256 (elliptic-curve P-256) because it generates in well under a millisecond
 * — RSA generation is hundreds of times slower, and a test suite that mints a
 * fresh key per case should not pay that unless it is specifically exercising
 * RSA. One RS256 case still runs, to prove the production-default algorithm
 * round-trips.
 */
export function generateTestKey(
  kid: string,
  algorithm: SigningKeyAlgorithm = "ES256",
): TestKeyPair {
  const { publicKey, privateKey } = generatePem(algorithm);
  return { kid, algorithm, publicKey, privateKey };
}

/** The pair as the current signing key: private half included, `current: true`. */
export function asCurrent(pair: TestKeyPair): SigningKeyConfig {
  return {
    kid: pair.kid,
    algorithm: pair.algorithm,
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    current: true,
  };
}

/** The pair as a retired, verification-only key: no private half, `current: false`. */
export function asRetired(pair: TestKeyPair): SigningKeyConfig {
  return {
    kid: pair.kid,
    algorithm: pair.algorithm,
    publicKey: pair.publicKey,
    current: false,
  };
}

function generatePem(algorithm: SigningKeyAlgorithm): { publicKey: string; privateKey: string } {
  const publicKeyEncoding = { type: "spki", format: "pem" } as const;
  const privateKeyEncoding = { type: "pkcs8", format: "pem" } as const;

  if (algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
    return generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding,
      privateKeyEncoding,
    });
  }
  if (algorithm === "EdDSA") {
    return generateKeyPairSync("ed25519", { publicKeyEncoding, privateKeyEncoding });
  }
  const namedCurve = algorithm === "ES384" ? "P-384" : algorithm === "ES512" ? "P-521" : "P-256";
  return generateKeyPairSync("ec", { namedCurve, publicKeyEncoding, privateKeyEncoding });
}
