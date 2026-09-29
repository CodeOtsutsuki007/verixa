import type { WebAuthnCredentialRepository } from "../../application/ports/webauthn-credential-repository.js";
import type { UserId } from "../../domain/entities/mfa-method.js";
import type { WebAuthnCredential, WebAuthnCredentialId } from "../../domain/entities/webauthn-credential.js";

export class InMemoryWebAuthnCredentialRepository implements WebAuthnCredentialRepository {
  private readonly credentials = new Map<string, WebAuthnCredential>();

  async findById(id: WebAuthnCredentialId): Promise<WebAuthnCredential | undefined> {
    return this.credentials.get(id);
  }

  async findByCredentialId(credentialId: string): Promise<WebAuthnCredential | undefined> {
    for (const cred of this.credentials.values()) {
      if (cred.credentialId === credentialId) {
        return cred;
      }
    }
    return undefined;
  }

  async findByUserId(userId: UserId): Promise<readonly WebAuthnCredential[]> {
    const result: WebAuthnCredential[] = [];
    for (const cred of this.credentials.values()) {
      if (cred.userId === userId) {
        result.push(cred);
      }
    }
    return result;
  }

  async save(credential: WebAuthnCredential): Promise<void> {
    this.credentials.set(credential.id, credential);
  }

  async delete(id: WebAuthnCredentialId): Promise<void> {
    this.credentials.delete(id);
  }
}
