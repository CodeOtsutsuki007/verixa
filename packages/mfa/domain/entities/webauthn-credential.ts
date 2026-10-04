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

  updateSignCounter(newCounter: number, now: Date = new Date()): WebAuthnCredential {
    return new WebAuthnCredential({
      ...this.props,
      signCounter: newCounter,
      lastUsedAt: now,
    });
  }
}
