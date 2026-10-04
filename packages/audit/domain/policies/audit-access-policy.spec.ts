import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import {
  AUDIT_PERMISSIONS,
  AuditAccessDeniedError,
  type AuditReader,
  authorizeAuditRead,
} from "./audit-access-policy.js";

function reader(permissions: string[], organizationId = "org-a"): AuditReader {
  return { actorId: "auditor-1", organizationId, permissions: new Set(permissions) };
}

describe("authorizeAuditRead", () => {
  it("permits a query of the reader's own organization with audit:query", () => {
    const decision = authorizeAuditRead(reader([AUDIT_PERMISSIONS.query]), "query", "org-a");

    expect(Result.isOk(decision)).toBe(true);
  });

  it("permits an export of the reader's own organization with audit:export", () => {
    const decision = authorizeAuditRead(reader([AUDIT_PERMISSIONS.export]), "export", "org-a");

    expect(Result.isOk(decision)).toBe(true);
  });

  it("refuses a reader with no permissions at all", () => {
    const decision = authorizeAuditRead(reader([]), "query", "org-a");

    expect(Result.isErr(decision) && decision.error.reason).toBe("missing_permission");
  });

  it("does not let audit:query stand in for audit:export", () => {
    const decision = authorizeAuditRead(reader([AUDIT_PERMISSIONS.query]), "export", "org-a");

    expect(Result.isErr(decision) && decision.error.reason).toBe("missing_permission");
  });

  it("refuses another organization's log even when the reader holds every permission", () => {
    const everything = reader([AUDIT_PERMISSIONS.query, AUDIT_PERMISSIONS.export]);

    for (const operation of ["query", "export"] as const) {
      const decision = authorizeAuditRead(everything, operation, "org-b");
      expect(Result.isErr(decision) && decision.error.reason).toBe("cross_organization");
    }
  });

  it("gives the caller the same answer whatever the reason for refusal", () => {
    const crossOrg = new AuditAccessDeniedError("cross_organization");
    const noPermission = new AuditAccessDeniedError("missing_permission");

    // Serialized form is what reaches the wire; it must not reveal which rule
    // fired, or cross-organization probing becomes an ID-validity oracle.
    expect(JSON.stringify(crossOrg)).toBe(JSON.stringify(noPermission));
    expect(crossOrg.toJSON()).toEqual({
      code: "AUDIT_ACCESS_DENIED",
      message: "You are not permitted to read this audit log.",
      httpStatusHint: 403,
    });
  });
});
