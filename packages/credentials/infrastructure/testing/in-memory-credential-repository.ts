import type {
  CredentialRepository,
  StaleCredentialMetrics,
} from "../../application/ports/credential-repository.js";
import type { Credential, CredentialUserId } from "../../domain/entities/credential.js";

/** In-memory `CredentialRepository` for testing use cases without a database. */
export class InMemoryCredentialRepository implements CredentialRepository {
  private readonly byUserId = new Map<CredentialUserId, Credential>();

  findByUserId(userId: CredentialUserId): Promise<Credential | undefined> {
    return Promise.resolve(this.byUserId.get(userId));
  }

  save(credential: Credential): Promise<void> {
    this.byUserId.set(credential.userId, credential);
    return Promise.resolve();
  }

  deleteByUserId(userId: CredentialUserId): Promise<void> {
    this.byUserId.delete(userId);
    return Promise.resolve();
  }

  async getStaleCredentialMetrics(currentHasher: {
    needsRehash(encodedHash: string): boolean;
  }): Promise<StaleCredentialMetrics> {
    const staleCreatedAts = Array.from(this.byUserId.values())
      .filter(({ passwordHash }) => currentHasher.needsRehash(passwordHash))
      .map(({ createdAt }) => createdAt)
      .sort((a, b) => a.getTime() - b.getTime());

    if (staleCreatedAts.length === 0) {
      return {
        count: 0,
        oldestCreatedAt: null,
        medianCreatedAt: null,
        p95CreatedAt: null,
      };
    }

    const count = staleCreatedAts.length;
    const oldestCreatedAt = staleCreatedAts[0];

    const medianIndex = Math.floor((count - 1) / 2);
    const medianCreatedAt = staleCreatedAts[medianIndex];

    const p95Index = Math.floor(0.95 * (count - 1));
    const p95CreatedAt = staleCreatedAts[p95Index];

    return {
      count,
      oldestCreatedAt,
      medianCreatedAt,
      p95CreatedAt,
    };
  }
}
