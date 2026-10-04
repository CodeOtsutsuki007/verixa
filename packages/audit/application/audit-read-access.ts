import { DomainError, Result } from "@verixa/shared-kernel";

import {
  type AuditAccessDeniedError,
  type AuditReader,
  type AuditReadOperation,
  authorizeAuditRead,
} from "../domain/policies/audit-access-policy.js";

import type { AuditEventCriteria } from "./ports/audit-event-reader.js";
import type { RecordAuditEvent } from "./use-cases/record-audit-event.js";

/**
 * A read was authorized but could not be recorded, so it was not performed.
 *
 * 503 rather than 500: nothing about the request was wrong, and retrying once
 * the audit store is reachable again is the correct client behaviour.
 */
export class AuditReadNotRecordedError extends DomainError {
  readonly code = "AUDIT_READ_NOT_RECORDED";
  readonly httpStatusHint = 503;

  constructor() {
    super("The audit log is temporarily unavailable. Try again shortly.");
  }
}

export type AuditReadError = AuditAccessDeniedError | AuditReadNotRecordedError;

/**
 * The criteria as audit metadata. Only the fields actually supplied, and dates
 * as ISO strings — metadata is `Record<string, string>` so it canonicalizes
 * into the entry hash the same way on every platform.
 */
function describe(criteria: AuditEventCriteria): Record<string, string> {
  const metadata: Record<string, string> = { organizationId: criteria.organizationId };
  if (criteria.actorId !== undefined) metadata["filter.actorId"] = criteria.actorId;
  if (criteria.subjectId !== undefined) metadata["filter.subjectId"] = criteria.subjectId;
  if (criteria.from !== undefined) metadata["filter.from"] = criteria.from.toISOString();
  if (criteria.to !== undefined) metadata["filter.to"] = criteria.to.toISOString();
  return metadata;
}

/**
 * Authorizes a read of the audit log and records it, in that order, before a
 * single entry is returned.
 *
 * Shared by `QueryAuditEvents` and `ExportAuditEvents` so the two cannot drift
 * apart — an export path that skipped either step would be the one an
 * attacker used.
 *
 * ## Refusals are recorded too
 *
 * A denied read is written as `audit.access_denied`. The interesting event for
 * an investigator is rarely "an auditor read the log"; it is "someone kept
 * trying to read a log that was not theirs". That write is best-effort: the
 * caller is refused either way, so a failure to record the refusal changes
 * nothing about the outcome.
 *
 * ## Fail closed when the read cannot be recorded
 *
 * `RecordAuditEvent` swallows write failures, because it normally records an
 * operation that has *already happened* — failing a completed login would be
 * reporting a false negative. That reasoning does not apply here: nothing has
 * been disclosed yet, so refusing costs one retry and nothing else. The
 * alternative, serving the read and hoping the record catches up, would mean
 * the one reliable way to read the audit log unobserved is to break audit
 * writes first.
 */
export async function authorizeAndRecordAuditRead(
  recordAuditEvent: RecordAuditEvent,
  reader: AuditReader,
  operation: AuditReadOperation,
  criteria: AuditEventCriteria,
): Promise<Result<void, AuditReadError>> {
  const decision = authorizeAuditRead(reader, operation, criteria.organizationId);

  if (Result.isErr(decision)) {
    await recordAuditEvent.execute({
      action: "audit.access_denied",
      actorId: reader.actorId,
      subjectId: criteria.organizationId,
      metadata: {
        ...describe(criteria),
        operation,
        reason: decision.error.reason,
        actorOrganizationId: reader.organizationId,
      },
    });
    return decision;
  }

  const recorded = await recordAuditEvent.execute({
    action: operation === "query" ? "audit.queried" : "audit.exported",
    actorId: reader.actorId,
    subjectId: criteria.organizationId,
    metadata: describe(criteria),
  });

  if (recorded === undefined) {
    return Result.err(new AuditReadNotRecordedError());
  }

  return Result.ok(undefined);
}
