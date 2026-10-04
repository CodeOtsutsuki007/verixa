import { DomainError, Result } from "@verixa/shared-kernel";

/**
 * The permissions that gate reading the audit log.
 *
 * Two, not one. Querying returns a bounded page an investigator reads on
 * screen; exporting hands over the whole filtered history in one go, for a
 * file that then leaves the system. The second is a bulk-disclosure
 * capability, and folding it into the first would mean anyone trusted to look
 * something up is also trusted to walk away with everything.
 *
 * Plain strings in the `context:action` shape Phase 07's RBAC permissions will
 * use, so the composition root can pass whatever that phase resolves for the
 * caller straight through, without a translation table.
 */
export const AUDIT_PERMISSIONS = {
  query: "audit:query",
  export: "audit:export",
} as const;

/** The two ways the audit log can be read. */
export type AuditReadOperation = keyof typeof AUDIT_PERMISSIONS;

/**
 * Who is asking to read the audit log.
 *
 * Built by the interface layer from an authenticated session — never from the
 * request body. `permissions` is whatever the caller has been granted *within
 * `organizationId`*; until Phase 07/12 wires real RBAC, the composition root
 * is responsible for populating it, and an empty set (the safe default) grants
 * nothing.
 */
export interface AuditReader {
  readonly actorId: string;
  readonly organizationId: string;
  readonly permissions: ReadonlySet<string>;
}

/** Why a read was refused. Internal: logged and audited, never sent to the caller. */
export type AuditAccessDenialReason = "missing_permission" | "cross_organization";

/**
 * A read of the audit log was refused.
 *
 * One message for every reason, the same way `AuthenticationError` has one
 * message for every login failure. A caller probing organization IDs should
 * not be able to tell "that organization is not yours" from "you lack the
 * permission" — the first answer confirms the ID is worth attacking with a
 * better-privileged account. `reason` carries the distinction for the audit
 * record and is deliberately left out of {@link toJSON}.
 */
export class AuditAccessDeniedError extends DomainError {
  readonly code = "AUDIT_ACCESS_DENIED";
  readonly httpStatusHint = 403;
  readonly reason: AuditAccessDenialReason;

  constructor(reason: AuditAccessDenialReason) {
    super("You are not permitted to read this audit log.");
    this.reason = reason;
  }
}

/**
 * Decides whether `reader` may perform `operation` on `organizationId`'s audit
 * log.
 *
 * ## Cross-organization access is refused, not filtered
 *
 * The tempting alternative is to ignore the requested organization and
 * silently scope the read to the caller's own. That returns a plausible,
 * empty-looking answer to a request that should never have been made, and it
 * hides the attempt: nothing distinguishes an operator who mistyped from one
 * probing other tenants. Refusing makes the attempt an event — which the use
 * cases then record.
 *
 * ## No override, yet
 *
 * There is no "platform operator may read every tenant" escape hatch. When one
 * is needed (Phase 16's admin tooling), it should arrive as its own explicit,
 * separately-granted permission, checked here, so that it shows up in review.
 * An implicit bypass — "admins skip this check" — is exactly the kind of rule
 * that ends up applying to more people than intended.
 */
export function authorizeAuditRead(
  reader: AuditReader,
  operation: AuditReadOperation,
  organizationId: string,
): Result<void, AuditAccessDeniedError> {
  if (reader.organizationId !== organizationId) {
    return Result.err(new AuditAccessDeniedError("cross_organization"));
  }

  const required = operation === "query" ? AUDIT_PERMISSIONS.query : AUDIT_PERMISSIONS.export;
  if (!reader.permissions.has(required)) {
    return Result.err(new AuditAccessDeniedError("missing_permission"));
  }

  return Result.ok(undefined);
}
