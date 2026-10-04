import type { Id } from "@verixa/shared-kernel";

import type { MfaMethodId } from "../../domain/entities/mfa-method.js";
import type { WebAuthnCredential } from "../../domain/entities/webauthn-credential.js";

export interface WebAuthnCredentialRepository {
  save(credential: WebAuthnCredential): Promise<void>;
  findByCredentialId(credentialId: string): Promise<WebAuthnCredential | null>;
  findByUserId(userId: Id<"UserId">): Promise<WebAuthnCredential[]>;
  findByMfaMethodId(mfaMethodId: MfaMethodId): Promise<WebAuthnCredential | null>;
}
