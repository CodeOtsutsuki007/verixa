import type { Id } from "@verixa/shared-kernel";

import type { WebAuthnCredentialRepository } from "../../application/ports/webauthn-credential-repository.js";
import type { MfaMethodId } from "../../domain/entities/mfa-method.js";
import type { WebAuthnCredential } from "../../domain/entities/webauthn-credential.js";

export class InMemoryWebAuthnCredentialRepository implements WebAuthnCredentialRepository {
  private readonly credentials = new Map<string, WebAuthnCredential>();

  save(credential: WebAuthnCredential): Promise<void> {
    this.credentials.set(credential.credentialId, credential);
    return Promise.resolve();
  }

  findByCredentialId(credentialId: string): Promise<WebAuthnCredential | null> {
    return Promise.resolve(this.credentials.get(credentialId) ?? null);
  }

  findByUserId(userId: Id<"UserId">): Promise<WebAuthnCredential[]> {
    return Promise.resolve(
      Array.from(this.credentials.values()).filter((c) => c.userId === userId),
    );
  }

  findByMfaMethodId(mfaMethodId: MfaMethodId): Promise<WebAuthnCredential | null> {
    return Promise.resolve(
      Array.from(this.credentials.values()).find((c) => c.mfaMethodId === mfaMethodId) ?? null,
    );
  }

  clear(): void {
    this.credentials.clear();
  }
}
