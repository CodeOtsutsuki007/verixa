import type { UserId } from "../../domain/entities/mfa-method.js";
import type { WebAuthnCredential, WebAuthnCredentialId } from "../../domain/entities/webauthn-credential.js";

export interface WebAuthnCredentialRepository {
  findById(id: WebAuthnCredentialId): Promise<WebAuthnCredential | undefined>;
  findByCredentialId(credentialId: string): Promise<WebAuthnCredential | undefined>;
  findByUserId(userId: UserId): Promise<readonly WebAuthnCredential[]>;
  save(credential: WebAuthnCredential): Promise<void>;
  delete(id: WebAuthnCredentialId): Promise<void>;
import type { Id } from "@verixa/shared-kernel";

import type { MfaMethodId } from "../../domain/entities/mfa-method.js";
import type { WebAuthnCredential } from "../../domain/entities/webauthn-credential.js";

export interface WebAuthnCredentialRepository {
  save(credential: WebAuthnCredential): Promise<void>;
  findByCredentialId(credentialId: string): Promise<WebAuthnCredential | null>;
  findByUserId(userId: Id<"UserId">): Promise<WebAuthnCredential[]>;
  findByMfaMethodId(mfaMethodId: MfaMethodId): Promise<WebAuthnCredential | null>;
}
