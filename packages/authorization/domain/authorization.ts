import { randomUUID } from "node:crypto";

export type PermissionKey = `${string}:${string}`;

export class AuthorizationError extends Error {
  constructor(public readonly code: "NOT_FOUND" | "FORBIDDEN" | "CONFLICT" | "INVALID") {
    super(code);
    this.name = "AuthorizationError";
  }
}

export class Permission {
  readonly id: string;
  readonly key: PermissionKey;

  constructor(
    key: string,
    readonly description: string,
    id = randomUUID(),
  ) {
    if (!/^[a-z][a-z0-9-]*:[a-z][a-z0-9-*]*$/.test(key)) {
      throw new AuthorizationError("INVALID");
    }
    this.key = key as PermissionKey;
    this.id = id;
  }
}

export interface RoleRecord {
  id: string;
  name: string;
  description: string;
  isSystemRole: boolean;
  permissions: string[];
}

export interface RoleAssignment {
  id: string;
  userId: string;
  roleId: string;
  organizationId: string;
  assignedAt: Date;
  assignedBy: string | null;
  expiresAt: Date | null;
}

export class Role {
  constructor(readonly record: RoleRecord) {}

  hasPermission(key: string): boolean {
    const resource = key.split(":")[0];
    return (
      this.record.permissions.includes("*:*") ||
      this.record.permissions.includes(key) ||
      this.record.permissions.includes(`${resource}:*`)
    );
  }
}
