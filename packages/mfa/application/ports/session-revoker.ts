import type { Id } from "@verixa/shared-kernel";

/**
 * Port for revoking all active sessions belonging to a user.
 *
 * Provided as a port rather than a direct dependency on `@verixa/sessions`
 * to keep the `@verixa/mfa` package free of a hard session-layer dependency.
 * The adapter — wired up by the application host — delegates to `LogoutEverywhere`
 * from `@verixa/sessions`.
 *
 * Why a separate port rather than importing `LogoutEverywhere` directly?
 * `@verixa/mfa` should not know about `@verixa/sessions` — the dependency
 * would flow the wrong way. The recovery use case needs to revoke sessions,
 * but it should not understand how sessions work. A thin port describes the
 * capability needed; the host wires in whatever satisfies it.
 */
export interface SessionRevoker {
  revokeAllForUser(userId: Id<"UserId">): Promise<{ revokedCount: number }>;
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
