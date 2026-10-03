/**
 * Decides whether an actor is permitted to perform an MFA recovery.
 *
 * Recovery is the one MFA operation that can remove every factor from an
 * account, so it is never self-service: the caller must hold an elevated
 * privilege (an administrator, or a documented equivalent such as an
 * identity-re-verification challenge configured by the organization).
 *
 * This lives behind a port because the authorization question belongs to
 * Phase 07's RBAC, not to MFA; the MFA flow only needs a yes/no answer.
 */
export interface MfaRecoveryAuthorizer {
  /** Whether `actorId` may recover another user's MFA access. */
  canRecoverMfaAccess(actorId: string): Promise<boolean>;
}
