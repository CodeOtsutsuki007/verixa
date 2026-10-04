import { asId, Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import {
  type OrgId,
  type RoleId,
  type UserId,
  UserRoleAssignment,
} from "./user-role-assignment.js";

const USER_A = asId<"UserId">("11111111-1111-4111-8111-111111111111");
const ADMIN_USER = asId<"UserId">("22222222-2222-4222-8222-222222222222");
const ROLE_ADMIN = asId<"RoleId">("33333333-3333-4333-8333-333333333333");
const ORG_1 = asId<"OrganizationId">("44444444-4444-4444-8444-444444444444");

describe("UserRoleAssignment", () => {
  describe("create", () => {
    it("creates a valid scoped role assignment", () => {
      const assignedAt = new Date("2026-01-01T00:00:00.000Z");
      const expiresAt = new Date("2026-01-02T00:00:00.000Z");

      const result = UserRoleAssignment.create({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: ORG_1,
        assignedBy: ADMIN_USER,
        assignedAt,
        expiresAt,
      });

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        const assignment = result.value;
        expect(assignment.id).toBeDefined();
        expect(assignment.userId).toBe(USER_A);
        expect(assignment.roleId).toBe(ROLE_ADMIN);
        expect(assignment.orgId).toBe(ORG_1);
        expect(assignment.assignedBy).toBe(ADMIN_USER);
        expect(assignment.assignedAt).toEqual(assignedAt);
        expect(assignment.expiresAt).toEqual(expiresAt);
        expect(assignment.isScoped()).toBe(true);
        expect(assignment.isGlobal()).toBe(false);
      }
    });

    it("creates a valid global role assignment with orgId: null", () => {
      const result = UserRoleAssignment.create({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: null,
        assignedBy: ADMIN_USER,
      });

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        const assignment = result.value;
        expect(assignment.orgId).toBeNull();
        expect(assignment.isGlobal()).toBe(true);
        expect(assignment.isScoped()).toBe(false);
        expect(assignment.expiresAt).toBeUndefined();
      }
    });

    it("preserves custom id when supplied in params", () => {
      const customId = asId<"UserRoleAssignmentId">("55555555-5555-4555-8555-555555555555");
      const result = UserRoleAssignment.create({
        id: customId,
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: null,
        assignedBy: ADMIN_USER,
      });

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.id).toBe(customId);
      }
    });

    it("convenience factory assignScoped creates a scoped assignment", () => {
      const result = UserRoleAssignment.assignScoped({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: ORG_1,
        assignedBy: ADMIN_USER,
      });

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.isScoped()).toBe(true);
        expect(result.value.orgId).toBe(ORG_1);
      }
    });

    it("convenience factory assignGlobal creates a global assignment", () => {
      const result = UserRoleAssignment.assignGlobal({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        assignedBy: ADMIN_USER,
      });

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.isGlobal()).toBe(true);
        expect(result.value.orgId).toBeNull();
      }
    });

    it("reconstitutes an assignment from trusted props", () => {
      const now = new Date();
      const assignmentId = asId<"UserRoleAssignmentId">("66666666-6666-4666-8666-666666666666");
      const assignment = UserRoleAssignment.reconstitute({
        id: assignmentId,
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: ORG_1,
        assignedAt: now,
        assignedBy: ADMIN_USER,
      });

      expect(assignment.id).toBe(assignmentId);
      expect(assignment.userId).toBe(USER_A);
      expect(assignment.roleId).toBe(ROLE_ADMIN);
      expect(assignment.orgId).toBe(ORG_1);
      expect(assignment.isScoped()).toBe(true);
    });
  });

  describe("scope validation and ambiguity rejection", () => {
    it("rejects undefined orgId as ambiguous scope", () => {
      const result = UserRoleAssignment.create({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: undefined as unknown as OrgId,
        assignedBy: ADMIN_USER,
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.fieldErrors.orgId).toContain("ambiguous_scope");
      }
    });

    it("rejects empty string orgId", () => {
      const result = UserRoleAssignment.create({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: "" as OrgId,
        assignedBy: ADMIN_USER,
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.fieldErrors.orgId).toContain("invalid_scope");
      }
    });

    it("rejects whitespace-only orgId", () => {
      const result = UserRoleAssignment.create({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: "   " as OrgId,
        assignedBy: ADMIN_USER,
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.fieldErrors.orgId).toContain("invalid_scope");
      }
    });
  });

  describe("required fields validation", () => {
    it("rejects empty userId", () => {
      const result = UserRoleAssignment.create({
        userId: "" as UserId,
        roleId: ROLE_ADMIN,
        orgId: null,
        assignedBy: ADMIN_USER,
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.fieldErrors.userId).toContain("required");
      }
    });

    it("rejects empty roleId", () => {
      const result = UserRoleAssignment.create({
        userId: USER_A,
        roleId: "" as RoleId,
        orgId: null,
        assignedBy: ADMIN_USER,
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.fieldErrors.roleId).toContain("required");
      }
    });

    it("rejects empty assignedBy", () => {
      const result = UserRoleAssignment.create({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: null,
        assignedBy: "" as UserId,
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.fieldErrors.assignedBy).toContain("required");
      }
    });
  });

  describe("dates and expiry behavior", () => {
    it("rejects invalid assignedAt Date", () => {
      const result = UserRoleAssignment.create({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: null,
        assignedBy: ADMIN_USER,
        assignedAt: new Date("not-a-valid-date"),
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.fieldErrors.assignedAt).toContain("invalid_date");
      }
    });

    it("rejects invalid expiresAt Date", () => {
      const result = UserRoleAssignment.create({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: null,
        assignedBy: ADMIN_USER,
        expiresAt: new Date("not-a-valid-date"),
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.fieldErrors.expiresAt).toContain("invalid_date");
      }
    });

    it("rejects expiresAt that is earlier than assignedAt", () => {
      const assignedAt = new Date("2026-06-01T12:00:00.000Z");
      const expiresAt = new Date("2026-06-01T11:59:59.000Z");

      const result = UserRoleAssignment.create({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: null,
        assignedBy: ADMIN_USER,
        assignedAt,
        expiresAt,
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.fieldErrors.expiresAt).toContain("must_be_after_assigned_at");
      }
    });

    it("rejects expiresAt that is equal to assignedAt", () => {
      const moment = new Date("2026-06-01T12:00:00.000Z");

      const result = UserRoleAssignment.create({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: null,
        assignedBy: ADMIN_USER,
        assignedAt: moment,
        expiresAt: moment,
      });

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.fieldErrors.expiresAt).toContain("must_be_after_assigned_at");
      }
    });

    it("isExpired returns false when assignment has no expiresAt", () => {
      const result = UserRoleAssignment.create({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: null,
        assignedBy: ADMIN_USER,
      });

      if (!Result.isOk(result)) throw new Error("setup failed");
      const assignment = result.value;

      expect(assignment.isExpired()).toBe(false);
      expect(assignment.isExpired(new Date("2099-01-01T00:00:00.000Z"))).toBe(false);
    });

    it("isExpired evaluates correctly against a reference time", () => {
      const assignedAt = new Date("2026-01-01T00:00:00.000Z");
      const expiresAt = new Date("2026-01-01T12:00:00.000Z");

      const result = UserRoleAssignment.create({
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: ORG_1,
        assignedBy: ADMIN_USER,
        assignedAt,
        expiresAt,
      });

      if (!Result.isOk(result)) throw new Error("setup failed");
      const assignment = result.value;

      // Before expiry
      expect(assignment.isExpired(new Date("2026-01-01T11:59:59.999Z"))).toBe(false);

      // Exactly at expiry
      expect(assignment.isExpired(new Date("2026-01-01T12:00:00.000Z"))).toBe(true);

      // Past expiry
      expect(assignment.isExpired(new Date("2026-01-01T12:00:00.001Z"))).toBe(true);
    });

    it("isExpired defaults to current time if reference date is omitted", () => {
      const pastExpiry = new Date(Date.now() - 10_000);
      const pastAssigned = new Date(Date.now() - 20_000);

      const assignment = UserRoleAssignment.reconstitute({
        id: asId<"UserRoleAssignmentId">("77777777-7777-4777-8777-777777777777"),
        userId: USER_A,
        roleId: ROLE_ADMIN,
        orgId: ORG_1,
        assignedAt: pastAssigned,
        assignedBy: ADMIN_USER,
        expiresAt: pastExpiry,
      });

      expect(assignment.isExpired()).toBe(true);
    });
  });
});
