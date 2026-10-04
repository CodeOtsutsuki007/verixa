import { asId, type Id } from "@verixa/shared-kernel";
import type { WebAuthnCredential as PrismaWebAuthnCredential } from "@prisma/client";

import { WebAuthnCredential, type AuthenticatorTransport } from "../../domain/entities/webauthn-credential.js";
import type { MfaMethodId } from "../../domain/entities/mfa-method.js";

export class WebAuthnCredentialMapper {
  static toDomain(raw: PrismaWebAuthnCredential): WebAuthnCredential {
    return WebAuthnCredential.reconstitute({
      id: asId<"WebAuthnCredentialId">(raw.id),
      userId: asId<"UserId">(raw.userId),
      mfaMethodId: asId<"MfaMethodId">(raw.mfaMethodId),
      credentialId: raw.credentialId,
      publicKey: raw.publicKey,
      signCounter: raw.signCounter,
      transports: (raw.transports ?? []) as AuthenticatorTransport[],
      attestationType: raw.attestationType,
      createdAt: raw.createdAt,
      lastUsedAt: raw.lastUsedAt ?? undefined,
    });
  }

  static toPersistence(credential: WebAuthnCredential): PrismaWebAuthnCredential {
    return {
      id: credential.id,
      userId: credential.userId,
      mfaMethodId: credential.mfaMethodId,
      credentialId: credential.credentialId,
      publicKey: credential.publicKey,
      signCounter: credential.signCounter,
      transports: [...credential.transports],
      attestationType: credential.attestationType,
      createdAt: credential.createdAt,
      lastUsedAt: credential.lastUsedAt ?? null,
    };
  }
}
