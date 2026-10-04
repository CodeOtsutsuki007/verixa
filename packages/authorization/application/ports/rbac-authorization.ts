/**
 * The outcome Phase 07's role/permission layer contributes for one
 * `(subject, action, resourceType)` check — the same three-state shape as
 * {@link import("../../domain/services/combining-algorithms.js").RuleOutcome},
 * for the same reason: a role check that simply has no opinion about this
 * action (`NOT_APPLICABLE`) must be distinguishable from one that actively
 * denies it, since {@link import("../services/authorization-service.js").AuthorizationService}
 * needs to fall through to ABAC evaluation only in the former case.
 */
export type RbacDecision = "PERMIT" | "DENY" | "NOT_APPLICABLE";

/**
 * The port `AuthorizationService` (Issue 152) uses to consult Phase 07's
 * role/permission grants — the RBAC half of the RBAC+ABAC composition this
 * package's name promises.
 *
 * Phase 07 (Issues 121–140) doesn't exist in this codebase yet, so nothing
 * currently implements this port for real; {@link NoRbacGrants} stands in
 * until it does (see that class's own doc comment for why that's correct
 * rather than a placeholder). Defining the port now, ahead of its real
 * implementation, is what lets `AuthorizationService` be written, tested,
 * and used by `AuthorizeAction` (Issue 153) today: once Phase 07 lands, a
 * `PrismaRbacAuthorizationPort` (or similar) implements this interface and
 * one line in the composition root swaps it in — nothing in
 * `AuthorizationService` or `AuthorizeAction` needs to change.
 */
export interface RbacAuthorizationPort {
  checkGrant(params: {
    subjectId: string;
    action: string;
    resourceType: string;
  }): Promise<RbacDecision>;
}

/**
 * An RBAC layer with no roles to consult.
 *
 * Correct until Phase 07 lands — there are no roles or permissions defined
 * anywhere in this codebase yet, so "no RBAC opinion on this request" is
 * the truthful answer, not a stand-in for one. This mirrors
 * `packages/credentials/application/ports/session-revoker.ts`'s
 * `NoSessionsRevoker`: the real call site (`AuthorizationService`) exists
 * and is exercised today, rather than commented out until its dependency
 * arrives.
 */
export class NoRbacGrants implements RbacAuthorizationPort {
  checkGrant(): Promise<RbacDecision> {
    return Promise.resolve("NOT_APPLICABLE");
  }
}
