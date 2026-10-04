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
import { createId, type Id } from "@verixa/shared-kernel";

import type { MfaMethodId } from "./mfa-method.js";

export type WebAuthnCredentialId = Id<"WebAuthnCredentialId">;

export interface WebAuthnCredentialProps {
  readonly id: WebAuthnCredentialId;
  readonly credentialId: string;
  readonly userId: Id<"UserId">;
  readonly mfaMethodId: MfaMethodId;
  readonly publicKey: string;
  readonly signCounter: number;
  readonly transports: readonly string[];
  readonly attestationType: string;
  readonly aaguid?: string | undefined;
  readonly deviceName?: string | undefined;
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
  private constructor(public readonly props: WebAuthnCredentialProps) {}

  get id(): WebAuthnCredentialId {
    return this.props.id;
  }

  get credentialId(): string {
    return this.props.credentialId;
  }

  get userId(): Id<"UserId"> {
    return this.props.userId;
  }

  get mfaMethodId(): MfaMethodId {
    return this.props.mfaMethodId;
  }

  get publicKey(): string {
    return this.props.publicKey;
  }

  get signCounter(): number {
    return this.props.signCounter;
  }

  get transports(): readonly string[] {
    return this.props.transports;
  }

  get attestationType(): string {
    return this.props.attestationType;
  }

  get aaguid(): string | undefined {
    return this.props.aaguid;
  }

  get deviceName(): string | undefined {
    return this.props.deviceName;
  }

  get createdAt(): Date {
    return this.props.createdAt;
  }

  get lastUsedAt(): Date | undefined {
    return this.props.lastUsedAt;
  }

  static create(props: {
    readonly credentialId: string;
    readonly userId: Id<"UserId">;
    readonly mfaMethodId: MfaMethodId;
    readonly publicKey: string;
    readonly signCounter?: number | undefined;
    readonly transports?: readonly string[] | undefined;
    readonly attestationType: string;
    readonly aaguid?: string | undefined;
    readonly deviceName?: string | undefined;
    readonly createdAt?: Date | undefined;
  }): WebAuthnCredential {
    return new WebAuthnCredential({
      id: createId<"WebAuthnCredentialId">(),
      credentialId: props.credentialId,
      userId: props.userId,
      mfaMethodId: props.mfaMethodId,
      publicKey: props.publicKey,
      signCounter: props.signCounter ?? 0,
      transports: props.transports ?? [],
      attestationType: props.attestationType,
      aaguid: props.aaguid,
      deviceName: props.deviceName,
      createdAt: props.createdAt ?? new Date(),
      lastUsedAt: undefined,
    });
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
  updateSignCounter(newCounter: number, now: Date = new Date()): WebAuthnCredential {
    return new WebAuthnCredential({
      ...this.props,
      signCounter: newCounter,
      lastUsedAt: now,
    });
  }
}
