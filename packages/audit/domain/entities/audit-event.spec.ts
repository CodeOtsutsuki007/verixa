import { describe, expect, it } from "vitest";

import { AuditEvent } from "./audit-event.js";

describe("AuditEvent", () => {
  describe("create", () => {
    it("creates an audit event with all required fields", () => {
      const event = AuditEvent.create({
        actorId: "user-123",
        action: "identity.user.registered",
        resourceType: "user",
        resourceId: "user-456",
        organizationId: "org-789",
      });

      expect(event.id).toBeDefined();
      expect(event.actorId).toBe("user-123");
      expect(event.action).toBe("identity.user.registered");
      expect(event.resourceType).toBe("user");
      expect(event.resourceId).toBe("user-456");
      expect(event.organizationId).toBe("org-789");
      expect(event.timestamp).toBeInstanceOf(Date);
      expect(event.metadata).toEqual({});
    });

    it("accepts undefined actorId for system actions", () => {
      const event = AuditEvent.create({
        actorId: undefined,
        action: "sessions.session.expired",
        resourceType: "session",
        resourceId: "session-123",
        organizationId: "org-789",
      });

      expect(event.actorId).toBeUndefined();
    });

    it("accepts valid metadata that conforms to action schema", () => {
      const event = AuditEvent.create({
        actorId: "user-123",
        action: "credentials.password.authentication_succeeded",
        resourceType: "user",
        resourceId: "user-456",
        organizationId: "org-789",
        metadata: {
          ipAddress: "192.168.1.1",
          userAgent: "Mozilla/5.0",
        },
      });

      expect(event.metadata).toEqual({
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla/5.0",
      });
    });

    it("uses provided timestamp instead of defaulting to now", () => {
      const customTimestamp = new Date("2024-01-15T10:30:00Z");

      const event = AuditEvent.create({
        actorId: "user-123",
        action: "identity.user.registered",
        resourceType: "user",
        resourceId: "user-456",
        organizationId: "org-789",
        timestamp: customTimestamp,
      });

      expect(event.timestamp).toEqual(customTimestamp);
    });

    it("throws when action is not a valid AuditAction", () => {
      expect(() =>
        AuditEvent.create({
          actorId: "user-123",
          action: "invalid.action.type",
          resourceType: "user",
          resourceId: "user-456",
          organizationId: "org-789",
        }),
      ).toThrow(/Invalid audit action/);
    });

    it("throws when metadata does not conform to action schema", () => {
      expect(() =>
        AuditEvent.create({
          actorId: "user-123",
          action: "rbac.role.assigned",
          resourceType: "user",
          resourceId: "user-456",
          organizationId: "org-789",
          metadata: {
            // Missing required 'roleId' and 'subjectId' fields
            someInvalidField: "value",
          },
        }),
      ).toThrow();
    });

    it("accepts metadata with optional fields omitted", () => {
      const event = AuditEvent.create({
        actorId: "user-123",
        action: "credentials.password.authentication_succeeded",
        resourceType: "user",
        resourceId: "user-456",
        organizationId: "org-789",
        metadata: {
          // ipAddress and userAgent are optional
        },
      });

      expect(event.metadata).toEqual({});
    });

    it("validates metadata IP address format", () => {
      expect(() =>
        AuditEvent.create({
          actorId: "user-123",
          action: "credentials.password.authentication_succeeded",
          resourceType: "user",
          resourceId: "user-456",
          organizationId: "org-789",
          metadata: {
            ipAddress: "not-a-valid-ip",
          },
        }),
      ).toThrow();
    });

    it("creates events with complex metadata schemas", () => {
      const event = AuditEvent.create({
        actorId: "reviewer-123",
        action: "verification.review.approved",
        resourceType: "verification_request",
        resourceId: "vr-456",
        organizationId: "org-789",
        metadata: {
          reviewerId: "reviewer-123",
          reason: "All documents verified successfully",
        },
      });

      expect(event.metadata).toEqual({
        reviewerId: "reviewer-123",
        reason: "All documents verified successfully",
      });
    });
  });

  describe("immutability", () => {
    it("does not expose setters for any field", () => {
      const event = AuditEvent.create({
        actorId: "user-123",
        action: "identity.user.registered",
        resourceType: "user",
        resourceId: "user-456",
        organizationId: "org-789",
      });

      // TypeScript compilation would fail if setters existed, but we can verify at runtime
      const eventAsAny = event as any;
      expect(typeof eventAsAny.setActorId).toBe("undefined");
      expect(typeof eventAsAny.setAction).toBe("undefined");
      expect(typeof eventAsAny.setMetadata).toBe("undefined");
    });

    it("freezes metadata to prevent mutation", () => {
      const event = AuditEvent.create({
        actorId: "user-123",
        action: "identity.user.registered",
        resourceType: "user",
        resourceId: "user-456",
        organizationId: "org-789",
        metadata: { key: "value" },
      });

      expect(() => {
        (event.metadata as any).key = "modified";
      }).toThrow();
    });

    it("prevents adding new properties to frozen metadata", () => {
      const event = AuditEvent.create({
        actorId: "user-123",
        action: "identity.user.registered",
        resourceType: "user",
        resourceId: "user-456",
        organizationId: "org-789",
        metadata: {},
      });

      expect(() => {
        (event.metadata as any).newKey = "value";
      }).toThrow();
    });
  });

  describe("reconstitute", () => {
    it("rebuilds an event from stored data without validation", () => {
      const storedProps = {
        id: "evt_test123" as any,
        actorId: "user-123",
        action: "identity.user.registered" as const,
        resourceType: "user" as const,
        resourceId: "user-456",
        timestamp: new Date("2024-01-15T10:30:00Z"),
        metadata: { someField: "value" },
        organizationId: "org-789",
      };

      const event = AuditEvent.reconstitute(storedProps);

      expect(event.id).toBe(storedProps.id);
      expect(event.actorId).toBe(storedProps.actorId);
      expect(event.action).toBe(storedProps.action);
      expect(event.resourceType).toBe(storedProps.resourceType);
      expect(event.resourceId).toBe(storedProps.resourceId);
      expect(event.timestamp).toEqual(storedProps.timestamp);
      expect(event.metadata).toEqual(storedProps.metadata);
      expect(event.organizationId).toBe(storedProps.organizationId);
    });

    it("does not validate metadata when reconstituting", () => {
      // This would fail validation in create(), but reconstitute trusts stored data
      const storedProps = {
        id: "evt_test123" as any,
        actorId: "user-123",
        action: "rbac.role.assigned" as const,
        resourceType: "user" as const,
        resourceId: "user-456",
        timestamp: new Date(),
        metadata: { invalidField: "this would be rejected by validation" },
        organizationId: "org-789",
      };

      // Should not throw
      const event = AuditEvent.reconstitute(storedProps);
      expect(event).toBeDefined();
    });
  });

  describe("withMetadata", () => {
    it("creates a copy with replaced metadata", () => {
      const original = AuditEvent.create({
        actorId: "user-123",
        action: "identity.user.registered",
        resourceType: "user",
        resourceId: "user-456",
        organizationId: "org-789",
        metadata: { original: "value" },
      });

      const modified = original.withMetadata({ replaced: "newValue" });

      expect(modified.metadata).toEqual({ replaced: "newValue" });
      expect(original.metadata).toEqual({ original: "value" }); // Original unchanged
      expect(modified.id).toBe(original.id); // Same ID
      expect(modified.action).toBe(original.action); // Same action
    });
  });

  describe("tenant scoping", () => {
    it("includes organizationId on every event", () => {
      const event = AuditEvent.create({
        actorId: "user-123",
        action: "identity.user.registered",
        resourceType: "user",
        resourceId: "user-456",
        organizationId: "org-specific",
      });

      expect(event.organizationId).toBe("org-specific");
    });

    it("allows different organizations to have events for the same resource", () => {
      const event1 = AuditEvent.create({
        actorId: "user-123",
        action: "identity.user.registered",
        resourceType: "user",
        resourceId: "user-456",
        organizationId: "org-1",
      });

      const event2 = AuditEvent.create({
        actorId: "user-789",
        action: "identity.user.registered",
        resourceType: "user",
        resourceId: "user-456",
        organizationId: "org-2",
      });

      expect(event1.organizationId).toBe("org-1");
      expect(event2.organizationId).toBe("org-2");
      expect(event1.resourceId).toBe(event2.resourceId);
    });
  });
});
