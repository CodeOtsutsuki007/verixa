import type { ResourceRef, SubjectRef } from "../../domain/attribute-context.js";

/**
 * The coarse-grained RBAC floor (Phase 07, Issues 121–140), consumed by the
 * composition service rather than reimplemented by it.
 *
 * This port answers exactly one question — "does this subject hold a role that
 * grants this action on this resource type?" — and nothing else. Attribute
 * conditions, policy documents, and precedence live in the ABAC layer, so an
 * implementation of this port stays cheap enough to run on every request.
 */

/** The three answers a role check can give. `no-match` is not a denial. */
export type RoleDecisionKind = "grant" | "deny" | "no-match";

/** Outcome of a role/permission check, with the grants that produced it. */
export interface RoleDecision {
  readonly kind: RoleDecisionKind;
  /** Stable explanation, for logs and the audit trail. */
  readonly reason: string;
  /** Roles the subject holds that were considered. */
  readonly roles: readonly string[];
  /** Permissions the subject holds that were considered. */
  readonly permissions: readonly string[];
}

/** The RBAC half of an authorization question. */
export interface RoleCheckRequest {
  readonly subject: SubjectRef;
  readonly action: string;
  readonly resource: ResourceRef;
}

/** Port implemented by Phase 07's permission store (and by the cache in front of it). */
export interface RolePermissionGate {
  /**
   * Renders a role decision for the request.
   *
   * Contracts an implementation must honour:
   *
   * - **Total for expected outcomes.** "This subject has no matching role" is
   *   `no-match`, not an exception. Only an unreachable/permanently broken
   *   store may throw, and callers treat a throw as a denial.
   * - **No attribute judgements.** An implementation must not read policy
   *   attributes or condition values; a role check that starts evaluating
   *   attributes has moved decision-making out of the policy engine.
   * - **Deterministic.** The same request against the same store state returns
   *   the same decision, with no dependence on call order.
   */
  check(request: RoleCheckRequest): Promise<RoleDecision>;
}
