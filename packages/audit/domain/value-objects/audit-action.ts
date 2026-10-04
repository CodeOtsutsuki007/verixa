/**
 * Audit action types.
 *
 * A closed set of action identifiers for auditable events across all contexts.
 * Each action represents a specific, security-relevant operation that warrants
 * recording in the audit trail.
 *
 * ## Naming convention
 *
 * Actions follow the pattern `<context>.<entity>.<verb>` (e.g.,
 * `identity.user.registered`, `credentials.password.reset_completed`). This
 * three-part structure makes the source and nature of an event immediately
 * apparent in query results and exports, and groups related actions together
 * when sorted lexicographically.
 *
 * ## Why a closed set
 *
 * Free-form action strings scatter equivalent events under different spellings
 * (`login_failed` vs. `LOGIN_FAILURE` vs. `user.login.failed`), making queries
 * unreliable and compliance reports incomplete. A typed enum catches typos at
 * compile time and ensures every query for "failed logins" finds them all.
 *
 * ## Extension strategy
 *
 * New actions are added here as new auditable operations are introduced. The
 * central registry is deliberate: it forces every new security-relevant
 * operation to declare itself explicitly, rather than silently not being
 * audited because someone forgot to add logging.
 */
export type AuditAction =
  // Identity context
  | "identity.user.registered"
  | "identity.user.suspended"
  | "identity.user.reactivated"
  | "identity.user.profile_updated"
  | "identity.organization.created"
  | "identity.organization.invitation_sent"
  // Credentials context
  | "credentials.user.registered_with_password"
  | "credentials.password.authentication_succeeded"
  | "credentials.password.authentication_failed"
  | "credentials.email.verification_requested"
  | "credentials.email.verification_completed"
  | "credentials.password.reset_requested"
  | "credentials.password.reset_completed"
  // Sessions context
  | "sessions.session.created"
  | "sessions.session.revoked"
  | "sessions.session.expired"
  // RBAC context
  | "rbac.role.assigned"
  | "rbac.role.revoked"
  | "rbac.permission.granted"
  | "rbac.permission.revoked"
  // Verification context
  | "verification.request.submitted"
  | "verification.evidence.submitted"
  | "verification.check.automated_completed"
  | "verification.review.claimed"
  | "verification.review.approved"
  | "verification.review.rejected"
  | "verification.review.more_info_requested"
  // Audit context (self-referential: auditing access to audit logs)
  | "audit.log.queried"
  | "audit.log.exported"
  | "audit.chain.verified"
  | "audit.chain.anchored";

/**
 * Type guard for valid audit actions.
 */
export function isAuditAction(value: string): value is AuditAction {
  const validActions: readonly string[] = [
    "identity.user.registered",
    "identity.user.suspended",
    "identity.user.reactivated",
    "identity.user.profile_updated",
    "identity.organization.created",
    "identity.organization.invitation_sent",
    "credentials.user.registered_with_password",
    "credentials.password.authentication_succeeded",
    "credentials.password.authentication_failed",
    "credentials.email.verification_requested",
    "credentials.email.verification_completed",
    "credentials.password.reset_requested",
    "credentials.password.reset_completed",
    "sessions.session.created",
    "sessions.session.revoked",
    "sessions.session.expired",
    "rbac.role.assigned",
    "rbac.role.revoked",
    "rbac.permission.granted",
    "rbac.permission.revoked",
    "verification.request.submitted",
    "verification.evidence.submitted",
    "verification.check.automated_completed",
    "verification.review.claimed",
    "verification.review.approved",
    "verification.review.rejected",
    "verification.review.more_info_requested",
    "audit.log.queried",
    "audit.log.exported",
    "audit.chain.verified",
    "audit.chain.anchored",
  ];

  return validActions.includes(value);
}
