/**
 * Revokes a user's sessions across every device.
 *
 * Implemented by the sessions package (Phase 05, Issue 092). Declared here as a
 * port so the recovery use case can demand "every session is gone" without
 * importing the sessions package — and so a test can assert the demand rather
 * than simulate a token store.
 */
export interface SessionRevoker {
  /** Revokes every active session for the user, returning how many were revoked. */
  revokeAllForUser(userId: string): Promise<number>;
}
