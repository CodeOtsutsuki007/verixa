import type { RevocationList } from "../../application/ports/revocation-list.js";

/**
 * A `RevocationList` backed by an in-memory `Map`, satisfying the exact same
 * port a real (Redis-backed) adapter will. Exists so `Logout`,
 * `LogoutEverywhere`, and `IssueSession`'s eviction path never need Redis in
 * their unit tests.
 */
export class InMemoryRevocationList implements RevocationList {
  private readonly expiresAtByTokenId = new Map<string, Date>();

  revoke(tokenId: string, expiresAt: Date): Promise<void> {
    this.expiresAtByTokenId.set(tokenId, expiresAt);
    return Promise.resolve();
  }

  isRevoked(tokenId: string): Promise<boolean> {
    return Promise.resolve(this.expiresAtByTokenId.has(tokenId));
  }
}
