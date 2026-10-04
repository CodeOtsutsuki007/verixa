import crypto from "node:crypto";

import { Result, ValidationError } from "@verixa/shared-kernel";

import type {
  AttestationVerifier,
  VerifiedAttestation,
  VerifyAttestationOptions,
} from "../../application/ports/attestation-verifier.js";

import { decodeCbor } from "./cbor.js";

/**
 * Normalizes an input (string or Uint8Array) into a Uint8Array.
 * If input is a string:
 * - If it starts with '{' or '[', treats it as raw UTF-8 text.
 * - Otherwise decodes from base64url/base64.
 */
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

function bufferToHex(buffer: Uint8Array): string {
  return Buffer.from(buffer).toString("hex");
}

function formatAaguid(bytes: Uint8Array): string {
  const hex = bufferToHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export class WebAuthnAttestationVerifier implements AttestationVerifier {
  verify(options: VerifyAttestationOptions): Promise<Result<VerifiedAttestation, Error>> {
    // 1. Parse clientDataJSON
    let clientDataString: string;
    try {
      if (
        typeof options.clientDataJSON === "string" &&
        options.clientDataJSON.trim().startsWith("{")
      ) {
        clientDataString = options.clientDataJSON;
      } else {
        const clientDataBytes = toUint8Array(options.clientDataJSON);
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
      crossOrigin?: boolean;
    };
    try {
      clientData = JSON.parse(clientDataString) as {
        type?: string;
        challenge?: string;
        origin?: string;
        crossOrigin?: boolean;
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
    if (clientData.type !== "webauthn.create") {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            `Invalid clientDataJSON type: expected "webauthn.create", got "${clientData.type}"`,
          ),
        ),
      );
    }

    // 3. Validate challenge binding
    if (clientData.challenge !== options.expectedChallenge) {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            `Challenge mismatch: expected "${options.expectedChallenge}", got "${clientData.challenge}"`,
          ),
        ),
      );
    }

    // 4. Validate origin binding (critical phishing resistance check)
    if (clientData.origin !== options.expectedOrigin) {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            `Origin mismatch: expected "${options.expectedOrigin}", got "${clientData.origin}"`,
          ),
        ),
      );
    }

    // 5. Decode attestationObject from CBOR
    let attestationBytes: Uint8Array;
    try {
      attestationBytes = toUint8Array(options.attestationObject);
    } catch (err) {
      return Promise.resolve(
        Result.err(
          new ValidationError(`Failed to parse attestationObject bytes: ${(err as Error).message}`),
        ),
      );
    }

    let attestationMap: Map<unknown, unknown>;
    try {
      const decoded = decodeCbor(attestationBytes);
      if (!(decoded instanceof Map)) {
        return Promise.resolve(
          Result.err(
            new ValidationError("Malformed attestationObject: root CBOR value is not a map"),
          ),
        );
      }
      attestationMap = decoded;
    } catch (err) {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            `Malformed attestationObject: CBOR decode failed - ${(err as Error).message}`,
          ),
        ),
      );
    }

    const fmt = attestationMap.get("fmt");
    const attStmt = attestationMap.get("attStmt");
    const authData = attestationMap.get("authData");

    if (typeof fmt !== "string") {
      return Promise.resolve(
        Result.err(
          new ValidationError('Malformed attestationObject: missing or invalid "fmt" field'),
        ),
      );
    }

    if (!(authData instanceof Uint8Array)) {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            'Malformed attestationObject: missing or invalid "authData" byte string',
          ),
        ),
      );
    }

    // 6. Validate authData length (min 37 bytes: 32 rpIdHash + 1 flags + 4 signCount)
    if (authData.length < 37) {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            `Malformed authData: length ${authData.length} is less than minimum 37 bytes`,
          ),
        ),
      );
    }

    // 7. Verify rpIdHash binding
    const rpIdHash = authData.subarray(0, 32);
    const expectedRpIdHash = crypto.createHash("sha256").update(options.expectedRpId).digest();

    if (!crypto.timingSafeEqual(rpIdHash, expectedRpIdHash)) {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            `RP ID hash mismatch: authenticator RP ID hash does not match expected "${options.expectedRpId}"`,
          ),
        ),
      );
    }

    // 8. Verify flags: UP (bit 0) and AT (bit 6) must both be set
    const flags = authData[32];
    if (flags === undefined) {
      return Promise.resolve(
        Result.err(new ValidationError("Malformed authData: missing flags byte")),
      );
    }

    const userPresent = (flags & 0x01) !== 0;
    const attestedCredentialDataIncluded = (flags & 0x40) !== 0;

    if (!userPresent) {
      return Promise.resolve(
        Result.err(new ValidationError("User Present (UP) flag was not set by the authenticator")),
      );
    }

    if (!attestedCredentialDataIncluded) {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            "Attested Credential Data (AT) flag was not set in registration authData",
          ),
        ),
      );
    }

    // 9. Read signCount (bytes 33..36)
    const signCountView = new DataView(authData.buffer, authData.byteOffset + 33, 4);
    const signCounter = signCountView.getUint32(0, false);

    // 10. Parse Attested Credential Data (starting at byte 37)
    if (authData.length < 55) {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            "Malformed authData: insufficient length for attested credential data header",
          ),
        ),
      );
    }

    const aaguidBytes = authData.subarray(37, 53);
    const aaguid = formatAaguid(aaguidBytes);

    const credIdLenView = new DataView(authData.buffer, authData.byteOffset + 53, 2);
    const credentialIdLength = credIdLenView.getUint16(0, false);

    if (authData.length < 55 + credentialIdLength) {
      return Promise.resolve(
        Result.err(
          new ValidationError(
            `Malformed authData: credentialId extends past buffer length (length ${credentialIdLength})`,
          ),
        ),
      );
    }

    const credentialIdBytes = authData.subarray(55, 55 + credentialIdLength);
    const credentialId = Buffer.from(credentialIdBytes).toString("base64url");

    const credentialPublicKeyBytes = authData.subarray(55 + credentialIdLength);
    if (credentialPublicKeyBytes.length === 0) {
      return Promise.resolve(
        Result.err(
          new ValidationError("Malformed authData: missing public key in attested credential data"),
        ),
      );
    }
    const credentialPublicKey = Buffer.from(credentialPublicKeyBytes).toString("base64url");

    // 11. Format-specific attestation verification
    if (fmt === "none") {
      const isMap = attStmt instanceof Map;
      const isEmpty = isMap ? attStmt.size === 0 : !attStmt || Object.keys(attStmt).length === 0;
      if (!isEmpty) {
        return Promise.resolve(
          Result.err(new ValidationError('Attestation statement for "none" format must be empty')),
        );
      }
    }

    return Promise.resolve(
      Result.ok({
        credentialId,
        credentialPublicKey,
        signCounter,
        aaguid,
        attestationType: fmt,
        rpId: options.expectedRpId,
        origin: options.expectedOrigin,
      }),
    );
  }
}
