import {
  type VerificationDecision as VerificationDecisionValue,
  type VerificationRequestRow,
  type VerificationType as DbVerificationType,
} from "@verixa/database";
import { asId } from "@verixa/shared-kernel";

import { ReviewAssignment } from "../../domain/entities/review-assignment.js";
import { VerificationRequest } from "../../domain/entities/verification-request.js";
import {
  isVerificationStatus,
  VerificationStatus,
  type VerificationStatusValue,
} from "../../domain/value-objects/verification-status.js";
import {
  VerificationType,
  type VerificationTypeValue,
} from "../../domain/value-objects/verification-type.js";

/**
 * The single translation between the domain's `identity-document` and the
 * database's `identity_document`.
 *
 * Prisma enum member names cannot contain a hyphen, so it cannot match the
 * domain spelling exactly. Written as an explicit pair of tables rather than
 * a `.replace("-", "_")` so a future value that legitimately contains a
 * hyphen is a visible addition, not a silent mangling.
 *
 * `VerificationStatus` needs no equivalent: its values are already valid
 * Prisma member names, so they pass through untouched.
 */
const DOMAIN_TO_DB_TYPE: ReadonlyMap<VerificationTypeValue, DbVerificationType> = new Map([
  ["identity-document", "identity_document"],
  ["address", "address"],
  ["liveness", "liveness"],
]);

const DB_TO_DOMAIN_TYPE: ReadonlyMap<DbVerificationType, VerificationTypeValue> = new Map([
  ["identity_document", "identity-document"],
  ["address", "address"],
  ["liveness", "liveness"],
]);

/** Domain verification type to its database enum value. Exported for the adapter's query filters. */
export function toDbVerificationType(value: VerificationTypeValue): DbVerificationType {
  const mapped = DOMAIN_TO_DB_TYPE.get(value);
  if (mapped === undefined) {
    throw new Error(`No database enum value mapped for verification type "${value}".`);
  }
  return mapped;
}

/**
 * Translates between the `verification_requests` row shape and the
 * `VerificationRequest` aggregate. Everything Prisma-shaped stops here, for
 * the reasons `user-mapper.ts` sets out: letting generated types *be* the
 * domain model means a schema change becomes a domain change, and an
 * aggregate can be constructed that never passed a single invariant.
 */
export const VerificationRequestMapper = {
  toDomain(row: VerificationRequestRow): VerificationRequest {
    if (!isVerificationStatus(row.status)) {
      throw new Error(`verification_requests.id=${row.id} holds a status the domain rejects.`);
    }

    const requestId = asId<"VerificationRequestId">(row.id);

    // The three claim columns are written together and nulled together, so a
    // partially-populated claim means the row is corrupt — treat it as absent
    // rather than fabricating an assignment with a missing expiry.
    const assignment =
      row.assignedReviewerId !== null && row.assignedAt !== null && row.claimExpiresAt !== null
        ? ReviewAssignment.reconstitute({
            requestId,
            reviewerId: asId<"ReviewerId">(row.assignedReviewerId),
            assignedAt: row.assignedAt,
            claimExpiresAt: row.claimExpiresAt,
          })
        : undefined;

    const decision =
      row.decidedByReviewerId !== null && row.decidedAt !== null && row.decisionNote !== null
        ? {
            decidedBy: asId<"ReviewerId">(row.decidedByReviewerId),
            decidedAt: row.decidedAt,
            note: row.decisionNote,
          }
        : undefined;

    // `VerificationRequest.reconstitute` enforces that the decision and the
    // status agree, so an inconsistent row throws there rather than yielding
    // an aggregate whose `status` and `decision` tell different stories.
    return VerificationRequest.reconstitute({
      id: requestId,
      subjectUserId: asId<"VerificationSubjectId">(row.subjectUserId),
      organizationId: asId<"VerificationOrganizationId">(row.organizationId),
      type: VerificationType.reconstitute(fromDbVerificationType(row.type, row.id)),
      status: VerificationStatus.reconstitute(row.status),
      assignment,
      decision,
      needsMoreInfoNote: row.needsMoreInfoNote ?? undefined,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
  },

  /** Aggregate → row. Total and non-failing: a `VerificationRequest` is valid by construction. */
  toRow(request: VerificationRequest): VerificationRequestRow {
    return {
      id: request.id,
      subjectUserId: request.subjectUserId,
      organizationId: request.organizationId,
      type: toDbVerificationType(request.type.value),
      status: request.status.value,
      assignedReviewerId: request.assignment?.reviewerId ?? null,
      assignedAt: request.assignment?.assignedAt ?? null,
      claimExpiresAt: request.assignment?.claimExpiresAt ?? null,
      decidedByReviewerId: request.decision?.decidedBy ?? null,
      decidedAt: request.decision?.decidedAt ?? null,
      decision: decisionOf(request.status.value),
      decisionNote: request.decision?.note ?? null,
      needsMoreInfoNote: request.needsMoreInfoNote ?? null,
      createdAt: request.createdAt,
      updatedAt: request.updatedAt,
    };
  },
};

/**
 * The stored decision value is the terminal status itself, or NULL while the
 * request is undecided — so a row can never claim a decision it does not have
 * a status for.
 */
function fromDbVerificationType(value: DbVerificationType, id: string): VerificationTypeValue {
  const mapped = DB_TO_DOMAIN_TYPE.get(value);
  if (mapped === undefined) {
    throw new Error(`verification_requests.id=${id} holds a type the domain rejects: ${value}.`);
  }
  return mapped;
}

function decisionOf(status: VerificationStatusValue): VerificationDecisionValue | null {
  return status === "approved" || status === "rejected" ? status : null;
}
