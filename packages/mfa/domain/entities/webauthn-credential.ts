import { createId, type Id, Result, ValidationError } from "@verixa/shared-kernel";

import type { MfaMethodId, UserId } from "./mfa-method.js";

export type WebAuthnCredentialId = Id<"WebAuthnCredentialId">;

export type AuthenticatorTransport = "usb" | "nfc" | "ble" | "smart-card" | "hybrid" | "internal";

interface WebAuthnCredentialProps {
  readonly id: WebAuthnCredentialId;
  readonly userId: UserId;
  readonly mfaMethodId: MfaMethodId;
  readonly credentialId: string; // base64url or hex encoded credential ID bytes
  readonly publicKey: string; // PEM or raw public key bytes stored as string
  readonly signCounter: number;
  readonly transports: readonly AuthenticatorTransport[];
  readonly attestationType: string;
  readonly createdAt: Date;
  readonly lastUsedAt?: Date | undefined;
}

export class WebAuthnCredential {
  readonly id: WebAuthnCredentialId;
  readonly userId: UserId;
  readonly mfaMethodId: MfaMethodId;
  readonly credentialId: string;
  readonly publicKey: string;
  readonly signCounter: number;
  readonly transports: readonly AuthenticatorTransport[];
  readonly attestationType: string;
  readonly createdAt: Date;
  readonly lastUsedAt: Date | undefined;

  private constructor(props: WebAuthnCredentialProps) {
    this.id = props.id;
    this.userId = props.userId;
    this.mfaMethodId = props.mfaMethodId;
    this.credentialId = props.credentialId;
    this.publicKey = props.publicKey;
    this.signCounter = props.signCounter;
    this.transports = props.transports;
    this.attestationType = props.attestationType;
    this.createdAt = props.createdAt;
    this.lastUsedAt = props.lastUsedAt;
  }

  static register(params: {
    userId: UserId;
    mfaMethodId: MfaMethodId;
    credentialId: string;
    publicKey: string;
    signCounter?: number;
    transports?: readonly AuthenticatorTransport[];
    attestationType?: string;
  }): Result<WebAuthnCredential, ValidationError> {
    if (!params.credentialId || params.credentialId.trim() === "") {
      return Result.err(
        new ValidationError("Credential ID is required.", { credentialId: ["required"] }),
      );
    }
    if (!params.publicKey || params.publicKey.trim() === "") {
      return Result.err(
        new ValidationError("Public key is required.", { publicKey: ["required"] }),
      );
    }

    return Result.ok(
      new WebAuthnCredential({
        id: createId<"WebAuthnCredentialId">(),
        userId: params.userId,
        mfaMethodId: params.mfaMethodId,
        credentialId: params.credentialId,
        publicKey: params.publicKey,
        signCounter: params.signCounter ?? 0,
        transports: params.transports ?? [],
        attestationType: params.attestationType ?? "none",
        createdAt: new Date(),
      }),
    );
  }

  static reconstitute(props: WebAuthnCredentialProps): WebAuthnCredential {
    return new WebAuthnCredential(props);
  }

  updateSignCounter(newCounter: number): Result<WebAuthnCredential, ValidationError> {
    if (newCounter < this.signCounter) {
      return Result.err(
        new ValidationError(
          `Sign counter regression detected (clone detection): current=${this.signCounter}, received=${newCounter}.`,
          { signCounter: ["clone_detected"] },
        ),
      );
    }

    return Result.ok(
      new WebAuthnCredential({
        ...this,
        signCounter: newCounter,
        lastUsedAt: new Date(),
      }),
    );
  }
}
