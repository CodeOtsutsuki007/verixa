import type { WebAuthnChallenge } from "../../domain/entities/webauthn-challenge.js";

export interface WebAuthnChallengeRepository {
  save(challenge: WebAuthnChallenge): Promise<void>;
  findByChallenge(challenge: string): Promise<WebAuthnChallenge | null>;
  consume(challenge: string): Promise<boolean>;
}
