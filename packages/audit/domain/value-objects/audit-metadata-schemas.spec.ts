import { describe, expect, it } from "vitest";

import type { AuditAction } from "./audit-action.js";
import { AUDIT_METADATA_SCHEMAS, validateAuditMetadata } from "./audit-metadata-schemas.js";

describe("validateAuditMetadata", () => {
  it("passes metadata through unchanged when it satisfies the action's schema", () => {
    const metadata = validateAuditMetadata("sessions.session.created", {
      ipAddress: "203.0.113.7",
    });

    expect(metadata).toEqual({ ipAddress: "203.0.113.7" });
  });

  it("rejects a field the schema did not declare", () => {
    // `.strict()` is what makes the registry mean anything: an unregistered key
    // is usually a typo in a producer, and accepting it silently is how a
    // required field ends up missing from half of last month's events.
    expect(() =>
      validateAuditMetadata("sessions.session.created", { unexpected: "value" }),
    ).toThrow();
  });

  it("rejects a malformed value for a declared field", () => {
    expect(() =>
      validateAuditMetadata("sessions.session.created", { ipAddress: "not-an-ip" }),
    ).toThrow();
  });

  describe("the permissive fallback for an action with no schema", () => {
    // Every action in the union has a schema today. These tests pin the
    // behaviour that takes over the first time one is added to `AuditAction`
    // and forgotten here, which is the gap the registry's own doc comment
    // warns about — it is worth stating in a test that the fallback accepts
    // anything, so the next person does not discover it in production.
    const unregistered = "identity.device.enrolled" as AuditAction;

    it("accepts any object-shaped metadata", () => {
      expect(AUDIT_METADATA_SCHEMAS[unregistered]).toBeUndefined();
      expect(validateAuditMetadata(unregistered, { anything: 1 })).toEqual({ anything: 1 });
    });

    it("substitutes an empty object for metadata that is not an object at all", () => {
      expect(validateAuditMetadata(unregistered, "a string")).toEqual({});
      expect(validateAuditMetadata(unregistered, null)).toEqual({});
      expect(validateAuditMetadata(unregistered, ["a", "b"])).toEqual({});
    });
  });
});
