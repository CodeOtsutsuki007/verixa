import crypto from "node:crypto";

import { Result, ValidationError } from "@verixa/shared-kernel";

import type {
  AssertionVerifier,
  VerifiedAssertion,
  VerifyAssertionOptions,
} from "../../application/ports/assertion-verifier.js";

import { decodeCbor } from "./cbor.js";

function toUint8Array(input: string | Uint8Array): Uint8Array {
  if (input instanceof Uint8Array) {
    return input;
  }
  if (typeof input === "string") {
    const trimmed = input.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      return new TextEncoder().encode(input);
    }
    try {
      const base64 = trimmed.replace(/-/g, "+").replace(/_/g, "/");
      const padLen = (4 - (base64.length % 4)) % 4;
      const padded = base64 + "=".repeat(padLen);
      return new Uint8Array(Buffer.from(padded, "base64"));
    } catch {
      return new TextEncoder().encode(input);
    }
  }
  throw new Error("Invalid input format: expected string or Uint8Array");
}

function parseCoseKeyToPublicKey(keyBytes: Uint8Array): crypto.KeyObject {
  try {
    const decoded: unknown = decodeCbor(keyBytes);
    if (decoded instanceof Map) {
      const keyMap = decoded as Map<unknown, unknown>;
      const kty: unknown = keyMap.get(1); // 2 = EC2
      if (kty === 2) {
        const x: unknown = keyMap.get(-2);
        const y: unknown = keyMap.get(-3);
        if (x instanceof Uint8Array && y instanceof Uint8Array) {
          return crypto.createPublicKey({
            key: {
              kty: "EC",
              crv: "P-256",
              x: Buffer.from(x).toString("base64url"),
              y: Buffer.from(y).toString("base64url"),
            },
            format: "jwk",
          });
        }
      }
    }
  } catch {
    // Fall back to DER if not CBOR
  }

  // Try SPKI DER
  return crypto.createPublicKey({
    key: Buffer.from(keyBytes),
    format: "der",
    type: "spki",
  });
}

function importPublicKey(keyInput: string): crypto.KeyObject {
  const trimmed = keyInput.trim();
  if (trimmed.startsWith("-----BEGIN")) {
    return crypto.createPublicKey(trimmed);
  }
  const keyBytes = toUint8Array(trimmed);
  return parseCoseKeyToPublicKey(keyBytes);
}

export class WebAuthnAssertionVerifier implements AssertionVerifier {
  verify(options: VerifyAssertionOptions): Promise<Result<VerifiedAssertion, Error>> {
    // 1. Parse clientDataJSON
    let clientDataBytes: Uint8Array;
    let clientDataString: string;
    try {
      if (
        typeof options.clientDataJSON === "string" &&
        options.clientDataJSON.trim().startsWith("{")
      ) {
        clientDataString = options.clientDataJSON;
        clientDataBytes = new TextEncoder().encode(clientDataString);
      } else {
        clientDataBytes = toUint8Array(options.clientDataJSON);
        clientDataString = new TextDecoder("utf-8").decode(clientDataBytes);
      }
    } catch (err) {
      return Promise.resolve(
        Result.err(
          new ValidationError(`Malformed clientDataJSON buffer: ${(err as Error).message}`),
        ),
      );
    }

    let clientData: {
      type?: string;
      challenge?: string;
      origin?: string;
    };
    try {
      clientData = JSON.parse(clientDataString) as {
        type?: string;
        challenge?: string;
        origin?: string;
      };
    } catch (err) {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            `Invalid clientDataJSON: JSON parse error - ${(err as Error).message}`,
          ),
        ),
      );
    }

    // 2. Validate clientDataJSON type
    if (clientData.type !== "webauthn.get") {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            `Invalid clientDataJSON type: expected "webauthn.get", got "${clientData.type}"`,
          ),
        ),
      );
    }

    // 3. Validate challenge match
    if (clientData.challenge !== options.expectedChallenge) {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            `Challenge mismatch: expected "${options.expectedChallenge}", got "${clientData.challenge}"`,
          ),
        ),
      );
    }

    // 4. Validate origin match
    if (clientData.origin !== options.expectedOrigin) {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            `Origin mismatch: expected "${options.expectedOrigin}", got "${clientData.origin}"`,
          ),
        ),
      );
    }

    // 5. Parse authenticatorData
    let authDataBytes: Uint8Array;
    try {
      authDataBytes = toUint8Array(options.authenticatorData);
    } catch (err) {
      return Promise.resolve(
        Result.err(new ValidationError(`Malformed authenticatorData: ${(err as Error).message}`)),
      );
    }

    if (authDataBytes.length < 37) {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            `Malformed authenticatorData: length ${authDataBytes.length} is less than required 37 bytes`,
          ),
        ),
      );
    }

    // 6. Verify RP ID hash
    const expectedRpIdHash = crypto.createHash("sha256").update(options.expectedRpId).digest();
    const actualRpIdHash = authDataBytes.subarray(0, 32);
    if (!expectedRpIdHash.equals(Buffer.from(actualRpIdHash))) {
      return Promise.resolve(
        Result.err(
          new ValidationError(`RP ID hash mismatch for expected RP ID "${options.expectedRpId}"`),
        ),
      );
    }

    // 7. Verify flags
    const flags = authDataBytes[32]!;
    const userPresent = Boolean(flags & 0x01);
    const userVerified = Boolean(flags & 0x04);

    if (!userPresent) {
      return Promise.resolve(
        Result.err(new ValidationError("User Present (UP) flag is not set in authenticatorData")),
      );
    }

    // 8. Parse signCount
    const signCountView = new DataView(authDataBytes.buffer, authDataBytes.byteOffset + 33, 4);
    const signCounter = signCountView.getUint32(0, false);

    // 9. Verify cryptographic signature
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = toUint8Array(options.signature);
    } catch (err) {
      return Promise.resolve(
        Result.err(new ValidationError(`Malformed signature: ${(err as Error).message}`)),
      );
    }

    let publicKeyObject: crypto.KeyObject;
    try {
      publicKeyObject = importPublicKey(options.credentialPublicKey);
    } catch (err) {
      return Promise.resolve(
        Result.err(new ValidationError(`Invalid credential public key: ${(err as Error).message}`)),
      );
    }

    const clientDataHash = crypto.createHash("sha256").update(clientDataBytes).digest();
    const verifyData = Buffer.concat([Buffer.from(authDataBytes), clientDataHash]);

    try {
      const isSignatureValid = crypto.verify(
        "sha256",
        verifyData,
        publicKeyObject,
        Buffer.from(signatureBytes),
      );

      if (!isSignatureValid) {
        return Promise.resolve(
          Result.err(new ValidationError("WebAuthn assertion signature verification failed")),
        );
      }
    } catch (err) {
      return Promise.resolve(
        Result.err(
          new ValidationError(`Error during signature verification: ${(err as Error).message}`),
        ),
      );
    }

    return Promise.resolve(
      Result.ok({
        credentialId: options.credentialId,
        signCounter,
        userPresent,
        userVerified,
        rpId: options.expectedRpId,
        origin: options.expectedOrigin,
      }),
    );
  }
}
