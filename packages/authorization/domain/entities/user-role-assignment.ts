import { createId, type Id, Result, ValidationError } from "@verixa/shared-kernel";

export type UserRoleAssignmentId = Id<"UserRoleAssignmentId">;
export type UserId = Id<"UserId">;
export type RoleId = Id<"RoleId">;
export type OrgId = Id<"OrganizationId">;

export interface UserRoleAssignmentProps {
  readonly id: UserRoleAssignmentId;
  readonly userId: UserId;
  readonly roleId: RoleId;
  /** The organization ID scoping this assignment, or `null` for a global (system-wide) role. */
  readonly orgId: OrgId | null;
  readonly assignedAt: Date;
  readonly assignedBy: UserId;
  readonly expiresAt?: Date | undefined;
}

export interface CreateUserRoleAssignmentParams {
  readonly id?: UserRoleAssignmentId;
  readonly userId: UserId;
  readonly roleId: RoleId;
  /**
   * The organization scoping this role assignment, or `null` for a global (system-wide) role.
   *
   * Must be explicitly:
   * - `null` for a global role assignment, or
   * - A non-empty, non-whitespace `OrgId` string for an organization-scoped assignment.
   *
   * An ambiguous state (such as `undefined`, an empty string `""`, or whitespace-only) is rejected.
   */
  readonly orgId: OrgId | null;
  readonly assignedBy: UserId;
  readonly assignedAt?: Date;
  readonly expiresAt?: Date | undefined;
}

/**
 * An explicit join entity linking a {@link UserId} to a {@link RoleId}, scoped
 * to an organization via `orgId` (or `null` for global roles), with audit
 * attribution (`assignedBy`, `assignedAt`) and optional time-bound elevation
 * (`expiresAt`).
 *
 * ## Why role assignment is its own entity
 *
 * Modeling role assignment as a distinct entity — rather than an array of roles
 * embedded on `User` or a property of `OrganizationMembership` — provides two
 * crucial architecture benefits:
 *
 * 1. **Decoupled Bounded Contexts:** Identity (`packages/identity`) owns user
 *    credentials, lifecycle, and organization membership. Authorization
 *    (`packages/authorization`) owns permissions, roles, and assignments. Keeping
 *    them separate avoids polluting identity models with authorization policies and
 *    allows independent schema and access pattern evolution.
 *
 * 2. **Multi-Tenant Scoping and Temporal Elevation:** A single user can hold different
 *    roles in different organizations (e.g., `admin` in Org A and `viewer` in Org B),
 *    as well as system-wide global roles (`super-admin`). Modeling assignments as
 *    first-class records also naturally accommodates temporary, time-bound access
 *    elevations via `expiresAt` without mutating role definitions or user profiles.
 */
export class UserRoleAssignment {
  readonly id: UserRoleAssignmentId;
  readonly userId: UserId;
  readonly roleId: RoleId;
  readonly orgId: OrgId | null;
  readonly assignedAt: Date;
  readonly assignedBy: UserId;
  readonly expiresAt: Date | undefined;

  private constructor(props: UserRoleAssignmentProps) {
    this.id = props.id;
    this.userId = props.userId;
    this.roleId = props.roleId;
    this.orgId = props.orgId;
    this.assignedAt = props.assignedAt;
    this.assignedBy = props.assignedBy;
    this.expiresAt = props.expiresAt;
  }

  /**
   * Creates a new `UserRoleAssignment` after validating all invariants.
   *
   * Returns a `ValidationError` if:
   * - `userId`, `roleId`, or `assignedBy` is empty or invalid.
   * - `orgId` is ambiguous (`undefined`, empty string, or whitespace-only).
   * - `assignedAt` or `expiresAt` is an invalid Date.
   * - `expiresAt` is earlier than or equal to `assignedAt`.
   */
  static create(
    params: CreateUserRoleAssignmentParams,
  ): Result<UserRoleAssignment, ValidationError> {
    if (!params.userId || typeof params.userId !== "string" || params.userId.trim() === "") {
      return Result.err(
        new ValidationError("userId must be a non-empty string.", {
          userId: ["required"],
        }),
      );
    }

    if (!params.roleId || typeof params.roleId !== "string" || params.roleId.trim() === "") {
      return Result.err(
        new ValidationError("roleId must be a non-empty string.", {
          roleId: ["required"],
        }),
      );
    }

    if (
      !params.assignedBy ||
      typeof params.assignedBy !== "string" ||
      params.assignedBy.trim() === ""
    ) {
      return Result.err(
        new ValidationError("assignedBy must be a non-empty string.", {
          assignedBy: ["required"],
        }),
      );
    }

    // Invariant: Scope must be unambiguous. Either explicitly `null` (global)
    // or a non-empty, non-whitespace string (scoped).
    if (params.orgId === undefined || params.orgId === null) {
      if (params.orgId === undefined) {
        return Result.err(
          new ValidationError(
            "orgId must be explicitly provided: pass an OrgId for scoped roles or null for global roles.",
            { orgId: ["ambiguous_scope"] },
          ),
        );
      }
    } else {
      if (typeof params.orgId !== "string" || params.orgId.trim() === "") {
        return Result.err(
          new ValidationError(
            "orgId must be a valid non-empty string when scoped, or null for global roles.",
            { orgId: ["invalid_scope"] },
          ),
        );
      }
    }

    const assignedAt = params.assignedAt ?? new Date();
    if (!(assignedAt instanceof Date) || isNaN(assignedAt.getTime())) {
      return Result.err(
        new ValidationError("assignedAt must be a valid Date.", {
          assignedAt: ["invalid_date"],
        }),
      );
    }

    let expiresAt: Date | undefined;
    if (params.expiresAt !== undefined && params.expiresAt !== null) {
      if (!(params.expiresAt instanceof Date) || isNaN(params.expiresAt.getTime())) {
        return Result.err(
          new ValidationError("expiresAt must be a valid Date.", {
            expiresAt: ["invalid_date"],
          }),
        );
      }
      if (params.expiresAt.getTime() <= assignedAt.getTime()) {
        return Result.err(
          new ValidationError("expiresAt must be strictly after assignedAt.", {
            expiresAt: ["must_be_after_assigned_at"],
          }),
        );
      }
      expiresAt = params.expiresAt;
    }

    const id = params.id ?? createId<"UserRoleAssignmentId">();

    return Result.ok(
      new UserRoleAssignment({
        id,
        userId: params.userId,
        roleId: params.roleId,
        orgId: params.orgId,
        assignedAt,
        assignedBy: params.assignedBy,
        expiresAt,
      }),
    );
  }

  /**
   * Convenience factory to create an organization-scoped role assignment.
   */
  static assignScoped(
    params: Omit<CreateUserRoleAssignmentParams, "orgId"> & { readonly orgId: OrgId },
  ): Result<UserRoleAssignment, ValidationError> {
    return UserRoleAssignment.create(params);
  }

  /**
   * Convenience factory to create a global (system-wide) role assignment (`orgId: null`).
   */
  static assignGlobal(
    params: Omit<CreateUserRoleAssignmentParams, "orgId">,
  ): Result<UserRoleAssignment, ValidationError> {
    return UserRoleAssignment.create({ ...params, orgId: null });
  }

  /**
   * Reconstitutes an already-persisted assignment from trusted storage data.
   * Skips domain validation by design.
   */
  static reconstitute(props: UserRoleAssignmentProps): UserRoleAssignment {
    return new UserRoleAssignment(props);
  }

  /**
   * Returns true if this assignment applies globally across all organizations.
   */
  isGlobal(): boolean {
    return this.orgId === null;
  }

  /**
   * Returns true if this assignment is scoped to a specific organization.
   */
  isScoped(): boolean {
    return this.orgId !== null;
  }

  /**
   * Evaluates whether this role assignment has expired relative to a reference time.
   *
   * Assignments without an `expiresAt` timestamp never expire (returns `false`).
   * For time-bound assignments, returns `true` once `now >= expiresAt`.
   *
   * @param now Reference time to evaluate expiry against (defaults to the current system time).
   */
  isExpired(now: Date = new Date()): boolean {
    if (this.expiresAt === undefined) {
      return false;
    }
    return now.getTime() >= this.expiresAt.getTime();
  }
}
