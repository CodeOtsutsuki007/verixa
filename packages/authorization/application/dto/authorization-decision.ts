import type { PolicyId } from "../../domain/entities/policy.js";

/**
 * The structured result `AuthorizeAction` (Issue 153) returns for a single
 * "can this subject do this action on this resource" check.
 *
 * `reason` is deliberately always populated, in every path (grant, deny, or
 * a resource-attribute resolution failure) — per Issue 153's acceptance
 * criteria, it must be sufficient for audit logging (Phase 10) on its own,
 * without whatever consumes it having to re-derive *why* from
 * `matchedPolicyIds` or re-run the check. See
 * `docs/guides/use-cases.md`'s PDP section for the full rationale and the
 * exact wording each path produces.
 */
export interface AuthorizationDecision {
  readonly granted: boolean;
  readonly reason: string;
  readonly matchedPolicyIds: readonly PolicyId[];
  readonly evaluatedAt: Date;
}
