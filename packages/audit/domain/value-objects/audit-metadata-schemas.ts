import { z } from "zod";

import type { AuditAction } from "./audit-action.js";

/**
 * Metadata schema registry for audit events.
 *
 * Each action type has a corresponding Zod schema that validates its metadata
 * shape. This ensures that:
 * 1. Metadata is structured and queryable, not an opaque blob
 * 2. Required context fields are never missing
 * 3. Field types are consistent across all events of the same action
 *
 * ## Schema design principles
 *
 * - Keep metadata **minimal**: only facts directly related to the action itself.
 *   The actor, resource, timestamp, and organization are already first-class
 *   fields on `AuditEvent` — don't duplicate them in metadata.
 *
 * - **Never include secrets**: passwords, tokens, session secrets, API keys,
 *   or any PII beyond what's necessary to identify the affected resource.
 *
 * - Use **consistent field names** across schemas: `oldValue`/`newValue` for
 *   changes, `reason` for human-supplied rationale, `ipAddress` for source IP.
 *
 * - All fields are **optional** unless their absence would make the event
 *   meaningless. An incomplete event is better than no event; required fields
 *   are a build-time contract that can break at runtime if a caller forgets.
 *
 * ## Adding new schemas
 *
 * When a new action is added to `AuditAction`, add its schema here. An action
 * without a schema defaults to accepting any JSON object, which defeats the
 * purpose — the first time someone queries "every role assignment last month",
 * they'll discover half the events are missing `roleId` because it was never
 * required.
 */

// Base schemas for common metadata patterns
const baseMetadataSchema = z.object({}).strict();

const ipAddressSchema = z
  .object({
    ipAddress: z.string().ip().optional(),
    userAgent: z.string().optional(),
  })
  .strict();

const changeMetadataSchema = z
  .object({
    changes: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

const reasonMetadataSchema = z
  .object({
    reason: z.string().optional(),
  })
  .strict();

// Identity context schemas
const identityUserRegisteredSchema = baseMetadataSchema;

const identityUserSuspendedSchema = reasonMetadataSchema;

const identityUserReactivatedSchema = reasonMetadataSchema;

const identityUserProfileUpdatedSchema = changeMetadataSchema;

const identityOrganizationCreatedSchema = z
  .object({
    organizationName: z.string().optional(),
  })
  .strict();

const identityOrganizationInvitationSentSchema = z
  .object({
    inviteeEmail: z.string().email().optional(),
    roleId: z.string().optional(),
  })
  .strict();

// Credentials context schemas
const credentialsUserRegisteredWithPasswordSchema = baseMetadataSchema;

const credentialsPasswordAuthenticationSucceededSchema = ipAddressSchema;

const credentialsPasswordAuthenticationFailedSchema = ipAddressSchema.extend({
  failureReason: z.enum(["invalid_credentials", "account_locked", "other"]).optional(),
});

const credentialsEmailVerificationRequestedSchema = z
  .object({
    email: z.string().email().optional(),
  })
  .strict();

const credentialsEmailVerificationCompletedSchema = z
  .object({
    email: z.string().email().optional(),
  })
  .strict();

const credentialsPasswordResetRequestedSchema = z
  .object({
    email: z.string().email().optional(),
  })
  .strict()
  .merge(ipAddressSchema);

const credentialsPasswordResetCompletedSchema = ipAddressSchema;

// Sessions context schemas
const sessionsSessionCreatedSchema = ipAddressSchema;

const sessionsSessionRevokedSchema = reasonMetadataSchema;

const sessionsSessionExpiredSchema = baseMetadataSchema;

// RBAC context schemas
const rbacRoleAssignedSchema = z
  .object({
    roleId: z.string(),
    subjectId: z.string(),
  })
  .strict()
  .merge(reasonMetadataSchema);

const rbacRoleRevokedSchema = z
  .object({
    roleId: z.string(),
    subjectId: z.string(),
  })
  .strict()
  .merge(reasonMetadataSchema);

const rbacPermissionGrantedSchema = z
  .object({
    permission: z.string(),
    subjectId: z.string(),
  })
  .strict()
  .merge(reasonMetadataSchema);

const rbacPermissionRevokedSchema = z
  .object({
    permission: z.string(),
    subjectId: z.string(),
  })
  .strict()
  .merge(reasonMetadataSchema);

// Verification context schemas
const verificationRequestSubmittedSchema = z
  .object({
    verificationType: z.string().optional(),
  })
  .strict();

const verificationEvidenceSubmittedSchema = z
  .object({
    evidenceType: z.string().optional(),
    evidenceCount: z.number().optional(),
  })
  .strict();

const verificationCheckAutomatedCompletedSchema = z
  .object({
    providerName: z.string().optional(),
    outcome: z.enum(["passed", "failed", "inconclusive"]).optional(),
    confidenceScore: z.number().min(0).max(1).optional(),
  })
  .strict();

const verificationReviewClaimedSchema = z
  .object({
    reviewerId: z.string().optional(),
  })
  .strict();

const verificationReviewApprovedSchema = reasonMetadataSchema.extend({
  reviewerId: z.string().optional(),
});

const verificationReviewRejectedSchema = reasonMetadataSchema.extend({
  reviewerId: z.string().optional(),
});

const verificationReviewMoreInfoRequestedSchema = reasonMetadataSchema.extend({
  reviewerId: z.string().optional(),
});

// Audit context schemas
const auditLogQueriedSchema = z
  .object({
    filters: z.record(z.string(), z.unknown()).optional(),
    resultCount: z.number().optional(),
  })
  .strict();

const auditLogExportedSchema = z
  .object({
    format: z.enum(["csv", "json"]).optional(),
    recordCount: z.number().optional(),
  })
  .strict();

const auditChainVerifiedSchema = z
  .object({
    chainLength: z.number().optional(),
    isValid: z.boolean().optional(),
    firstBreak: z.number().optional(),
  })
  .strict();

const auditChainAnchoredSchema = z
  .object({
    anchorRef: z.string().optional(),
    recordCount: z.number().optional(),
  })
  .strict();

/**
 * The complete metadata schema registry.
 *
 * Maps each action to its validation schema. Actions not present in this map
 * accept any JSON object (permissive fallback), but every action **should**
 * have an explicit schema.
 */
export const AUDIT_METADATA_SCHEMAS: Partial<Record<AuditAction, z.ZodTypeAny>> = {
  // Identity
  "identity.user.registered": identityUserRegisteredSchema,
  "identity.user.suspended": identityUserSuspendedSchema,
  "identity.user.reactivated": identityUserReactivatedSchema,
  "identity.user.profile_updated": identityUserProfileUpdatedSchema,
  "identity.organization.created": identityOrganizationCreatedSchema,
  "identity.organization.invitation_sent": identityOrganizationInvitationSentSchema,
  // Credentials
  "credentials.user.registered_with_password": credentialsUserRegisteredWithPasswordSchema,
  "credentials.password.authentication_succeeded":
    credentialsPasswordAuthenticationSucceededSchema,
  "credentials.password.authentication_failed": credentialsPasswordAuthenticationFailedSchema,
  "credentials.email.verification_requested": credentialsEmailVerificationRequestedSchema,
  "credentials.email.verification_completed": credentialsEmailVerificationCompletedSchema,
  "credentials.password.reset_requested": credentialsPasswordResetRequestedSchema,
  "credentials.password.reset_completed": credentialsPasswordResetCompletedSchema,
  // Sessions
  "sessions.session.created": sessionsSessionCreatedSchema,
  "sessions.session.revoked": sessionsSessionRevokedSchema,
  "sessions.session.expired": sessionsSessionExpiredSchema,
  // RBAC
  "rbac.role.assigned": rbacRoleAssignedSchema,
  "rbac.role.revoked": rbacRoleRevokedSchema,
  "rbac.permission.granted": rbacPermissionGrantedSchema,
  "rbac.permission.revoked": rbacPermissionRevokedSchema,
  // Verification
  "verification.request.submitted": verificationRequestSubmittedSchema,
  "verification.evidence.submitted": verificationEvidenceSubmittedSchema,
  "verification.check.automated_completed": verificationCheckAutomatedCompletedSchema,
  "verification.review.claimed": verificationReviewClaimedSchema,
  "verification.review.approved": verificationReviewApprovedSchema,
  "verification.review.rejected": verificationReviewRejectedSchema,
  "verification.review.more_info_requested": verificationReviewMoreInfoRequestedSchema,
  // Audit
  "audit.log.queried": auditLogQueriedSchema,
  "audit.log.exported": auditLogExportedSchema,
  "audit.chain.verified": auditChainVerifiedSchema,
  "audit.chain.anchored": auditChainAnchoredSchema,
};

/**
 * Validates metadata against the schema for the given action.
 *
 * Returns the validated (and potentially transformed) metadata if valid, or
 * throws a ZodError if validation fails.
 *
 * Actions without a registered schema accept any object (permissive fallback).
 */
export function validateAuditMetadata(
  action: AuditAction,
  metadata: unknown,
): Record<string, unknown> {
  const schema = AUDIT_METADATA_SCHEMAS[action];

  if (schema === undefined) {
    // Permissive fallback: accept any object-shaped metadata for unregistered actions
    if (typeof metadata === "object" && metadata !== null && !Array.isArray(metadata)) {
      return metadata as Record<string, unknown>;
    }
    return {};
  }

  return schema.parse(metadata) as Record<string, unknown>;
}
