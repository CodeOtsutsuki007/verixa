import type { WebAuthnChallengeRepository } from "../../application/ports/webauthn-challenge-repository.js";
import type { WebAuthnChallenge } from "../../domain/entities/webauthn-challenge.js";

export class InMemoryWebAuthnChallengeRepository implements WebAuthnChallengeRepository {
  private readonly challenges = new Map<string, WebAuthnChallenge>();

  save(challenge: WebAuthnChallenge): Promise<void> {
    this.challenges.set(challenge.challenge, challenge);
    return Promise.resolve();
  }

  findByChallenge(challenge: string): Promise<WebAuthnChallenge | null> {
    return Promise.resolve(this.challenges.get(challenge) ?? null);
  }

  consume(challenge: string): Promise<boolean> {
    const existing = this.challenges.get(challenge);
    if (!existing || existing.used) {
      return Promise.resolve(false);
    }
    const consumed = existing.consume();
    this.challenges.set(challenge, consumed);
    return Promise.resolve(true);
  }

  clear(): void {
    this.challenges.clear();
  }
}
