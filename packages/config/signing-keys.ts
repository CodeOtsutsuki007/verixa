import { z } from "zod";

import { ConfigError } from "./config-error.js";

/**
 * Signing algorithms a key may declare.
 *
 * All asymmetric on purpose. A symmetric algorithm (HS256) signs and verifies
 * with the *same* secret, so every service that needs to verify a token would
 * also hold the power to mint one — fine for a single process, a liability the
 * moment a second service (or a public JWKS endpoint) verifies tokens it should
 * never be able to forge. Asymmetric signing keeps the private key in one place
 * and hands out only the public half. See `docs/security/token-design.md`.
 */
export const SIGNING_KEY_ALGORITHMS = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
] as const;

export type SigningKeyAlgorithm = (typeof SIGNING_KEY_ALGORITHMS)[number];

/**
 * One key in the rotation set, as it arrives from configuration.
 *
 * `publicKey` (SPKI PEM) is always present — every key in the set has to be
 * able to *verify*, which is the whole point of keeping retired keys around.
 * `privateKey` (PKCS#8 PEM) is present only for the key currently minting
 * tokens; retired keys are verification-only and carry no private half, so a
 * leaked config file for an old key cannot be used to sign anything.
 */
export interface SigningKeyConfig {
  readonly kid: string;
  readonly algorithm: SigningKeyAlgorithm;
  readonly publicKey: string;
  readonly privateKey?: string;
  readonly current: boolean;
}

const signingKeySchema = z
  .object({
    kid: z.string().min(1, "kid must not be empty"),
    algorithm: z.enum(SIGNING_KEY_ALGORITHMS),
    publicKey: z.string().min(1, "publicKey (SPKI PEM) is required"),
    privateKey: z.string().min(1).optional(),
    current: z.boolean().default(false),
  })
  .strict();

const signingKeySetSchema = z.array(signingKeySchema).superRefine((keys, ctx) => {
  const kids = keys.map((key) => key.kid);
  const duplicates = kids.filter((kid, index) => kids.indexOf(kid) !== index);
  if (duplicates.length > 0) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      // A `kid` is how a verifier picks which key to check a token against.
      // Two keys sharing one makes that lookup ambiguous — the verifier would
      // silently pick whichever it happened to index first, so a token could
      // verify or not depending on load order. Reject it at the door.
      message: `Duplicate key ids are not allowed: ${[...new Set(duplicates)].join(", ")}.`,
    });
  }

  const currentKeys = keys.filter((key) => key.current);
  if (currentKeys.length !== 1) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      // Exactly one, never zero (nothing could sign) and never many (which
      // one signs the next token?). Rotation is "promote a new current and
      // demote the old to verification-only", not "have two currents."
      message: `Exactly one key must be marked "current", found ${String(currentKeys.length)}.`,
    });
  }

  for (const key of currentKeys) {
    if (key.privateKey === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `The current key "${key.kid}" must include a privateKey to sign with.`,
      });
    }
  }
});

/**
 * The environment variable holding the signing-key set.
 *
 * Its value is a JSON array of {@link SigningKeyConfig} objects. JSON, rather
 * than one env var per key, because the set is a variable-length list of
 * structured records with multi-line PEM bodies — exactly what a flat
 * `KEY_1_KID`, `KEY_1_PEM`, `KEY_2_...` scheme handles badly. JSON strings
 * carry the PEM newlines as `\n` natively, so no escaping dance is needed.
 */
export const SIGNING_KEYS_ENV_VAR = "TOKEN_SIGNING_KEYS";

/**
 * Loads and validates the JWT signing-key set from the environment.
 *
 * Deliberately *not* folded into {@link import("./index.js").loadConfig}. That
 * loader's job is scalar, non-secret runtime settings, and its return value is
 * snapshot-asserted field-by-field in tests; threading a list of PEM key
 * material through it would both widen that contract awkwardly and drag secrets
 * into a structure other code logs freely. Key material is its own concern with
 * its own loader.
 *
 * Returns an empty array when the variable is unset — a package that is not yet
 * wired into a running app (as of this issue, nothing mints tokens yet) is a
 * normal state, not a misconfiguration. The consumer that actually needs to
 * *sign* is the one positioned to reject an empty set, and it does.
 *
 * @throws {ConfigError} when the value is present but not valid JSON, or is
 * valid JSON that violates the key-set rules (duplicate kids, not exactly one
 * current key, a current key without a private key).
 */
export function loadSigningKeys(
  env: Record<string, string | undefined> = process.env,
): readonly SigningKeyConfig[] {
  const raw = env[SIGNING_KEYS_ENV_VAR];
  if (raw === undefined || raw.trim() === "") {
    return Object.freeze([]);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new ConfigError(
      `${SIGNING_KEYS_ENV_VAR} must be a JSON array of signing keys, but it is not valid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  const result = signingKeySetSchema.safeParse(parsed);
  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `  - ${issue.path.join(".") || "(root)"}: ${issue.message}`)
      .join("\n");
    throw new ConfigError(`Invalid ${SIGNING_KEYS_ENV_VAR}:\n${details}`);
  }

  // Rebuild each record so an absent private key is a *missing* property, not a
  // property set to `undefined` — the distinction exactOptionalPropertyTypes
  // enforces, and the honest one: a retired key has no private half at all.
  return Object.freeze(
    result.data.map((key): SigningKeyConfig => {
      const base = {
        kid: key.kid,
        algorithm: key.algorithm,
        publicKey: key.publicKey,
        current: key.current,
      };
      return Object.freeze(
        key.privateKey === undefined ? base : { ...base, privateKey: key.privateKey },
      );
    }),
  );
}
