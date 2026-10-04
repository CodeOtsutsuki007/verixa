import type { SigningKeyAlgorithm, SigningKeyConfig } from "@verixa/config";
import { importPKCS8, importSPKI } from "jose";

/**
 * The key type `jose` hands back from its import functions, derived rather than
 * named so this file does not depend on whether that type is called `KeyLike`,
 * `CryptoKey`, or something else in the installed major version — and so nothing
 * above this adapter ever learns which library produced the key. That total
 * wrapping is the point of the pattern this file follows: see
 * `packages/credentials/infrastructure/argon2-password-hasher.ts` and
 * `packages/stellar-anchor/infrastructure/stellar/stellar-hash-anchor.ts`.
 */
type ImportedKey = Awaited<ReturnType<typeof importSPKI>>;

/** The one key currently minting tokens: it alone holds a private half. */
export interface ActiveSigningKey {
  readonly kid: string;
  readonly algorithm: SigningKeyAlgorithm;
  readonly privateKey: ImportedKey;
}

/** Any key a token may legitimately have been signed by — current or retired. */
export interface VerificationKey {
  readonly kid: string;
  readonly algorithm: SigningKeyAlgorithm;
  readonly publicKey: ImportedKey;
}

/**
 * Supplies the keys the token signer signs and verifies with, addressed by
 * `kid`.
 *
 * ## Why this is the whole game for zero-downtime rotation
 *
 * Every access token carries, in its JWS header, the `kid` of the key that
 * signed it. Verification therefore does not have to guess: it reads the `kid`
 * and asks this provider for exactly that key. So the set of keys a verifier
 * *holds* — not the single key it currently *signs* with — is what decides
 * which tokens still verify.
 *
 * Rotation falls straight out of that. To rotate: add a new key, mark it
 * current (it starts signing new tokens), and keep the previous key in the set
 * as **verification-only** (no private half). Tokens minted seconds before the
 * switch still name the old `kid`, the provider still holds that key, so they
 * keep verifying until they expire on their own. Nothing is invalidated, no
 * request 401s mid-flight, no user is logged out by a key change. Once the old
 * key's last token has expired, drop it from the set for good — at which point
 * any token still bearing its `kid` (only forgeries and long-expired stragglers
 * remain) fails as an unknown key.
 *
 * A `kid` that this provider does not hold returns `undefined` from
 * {@link verificationKey}; the signer turns that into a rejection. That single
 * behavior is what the tests pin: retired-but-held keys verify, removed or
 * forged `kid`s do not.
 */
export interface SigningKeyProvider {
  /** The current signing key. Only this key can produce new tokens. */
  signingKey(): ActiveSigningKey;
  /** The verification key for `kid`, or `undefined` if this provider holds none. */
  verificationKey(kid: string): VerificationKey | undefined;
  /** Every `kid` this provider can verify — current plus retired. */
  verificationKids(): readonly string[];
  /**
   * The distinct algorithms across the held keys. The verifier pins its
   * accepted-algorithm list to this, closing the algorithm-substitution class
   * of attack (a forged token declaring `alg: none`, or swapping an RS256 key
   * into an HS256 verify where the "signature" is an HMAC of the public key).
   */
  algorithms(): readonly SigningKeyAlgorithm[];
}

/**
 * A {@link SigningKeyProvider} built from validated {@link SigningKeyConfig}
 * records (see `@verixa/config`'s `loadSigningKeys`). Imports each PEM into a
 * key object once, at construction, so signing and verification never re-parse.
 *
 * Async because key import is async. Construction — not first use — is where a
 * bad or missing key surfaces, matching the fail-fast-at-startup posture the
 * rest of the config loading takes: a deployment with unusable keys should die
 * on boot, loudly, not on the first login attempt hours later.
 */
export async function createConfigSigningKeyProvider(
  keys: readonly SigningKeyConfig[],
): Promise<SigningKeyProvider> {
  if (keys.length === 0) {
    // Reachable when TOKEN_SIGNING_KEYS is unset. loadSigningKeys treats that
    // as a valid empty set (a not-yet-wired package is fine); the component
    // that actually needs to *sign* is the one that must refuse to, and this is
    // it.
    throw new Error(
      "Cannot build a SigningKeyProvider with no keys. Set TOKEN_SIGNING_KEYS with at least one current key.",
    );
  }

  const currentConfig = keys.find((key) => key.current);
  if (currentConfig === undefined || currentConfig.privateKey === undefined) {
    // loadSigningKeys already guarantees exactly one current key with a private
    // half. Re-checked here so this factory is safe against a hand-built key
    // set that never went through that loader (a test, a future caller).
    throw new Error("The signing key set must contain exactly one current key with a private key.");
  }

  const verificationKeys = new Map<string, VerificationKey>();
  for (const key of keys) {
    const publicKey = await importKey(
      () => importSPKI(key.publicKey, key.algorithm),
      key.kid,
      "public",
    );
    verificationKeys.set(key.kid, { kid: key.kid, algorithm: key.algorithm, publicKey });
  }

  const privateKey = await importKey(
    () => importPKCS8(currentConfig.privateKey as string, currentConfig.algorithm),
    currentConfig.kid,
    "private",
  );
  const activeSigningKey: ActiveSigningKey = {
    kid: currentConfig.kid,
    algorithm: currentConfig.algorithm,
    privateKey,
  };

  const distinctAlgorithms = [...new Set(keys.map((key) => key.algorithm))];

  return {
    signingKey: () => activeSigningKey,
    verificationKey: (kid) => verificationKeys.get(kid),
    verificationKids: () => [...verificationKeys.keys()],
    algorithms: () => distinctAlgorithms,
  };
}

async function importKey(
  load: () => Promise<ImportedKey>,
  kid: string,
  half: "public" | "private",
): Promise<ImportedKey> {
  try {
    return await load();
  } catch (error) {
    // A parse failure here is a configuration mistake — a truncated PEM, the
    // wrong PEM format (SEC1 where PKCS#8 was expected), a public key pasted
    // where a private one belongs. Naming the offending kid and half turns an
    // opaque library error into something an operator can act on.
    throw new Error(`Failed to import the ${half} key for kid "${kid}".`, { cause: error });
  }
}
