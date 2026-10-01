import type { RoleAssignment, RoleRecord } from "../domain/authorization.js";

export interface AuthorizationRepository {
  listRoles(organizationId?: string | null): Promise<RoleRecord[]>;
  getRole(id: string): Promise<RoleRecord | undefined>;
  createRole(input: Omit<RoleRecord, "id" | "permissions">): Promise<RoleRecord>;
  updateRole(id: string, input: { name?: string; description?: string }): Promise<RoleRecord>;
  deleteRole(id: string): Promise<void>;
  listPermissions(): Promise<{ id: string; key: string; description: string }[]>;
  grantPermission(roleId: string, key: string): Promise<RoleRecord>;
  revokePermission(roleId: string, key: string): Promise<RoleRecord>;
  listAssignments(userId: string, organizationId?: string | null): Promise<RoleAssignment[]>;
  assignRole(input: Omit<RoleAssignment, "id" | "assignedAt">): Promise<RoleAssignment>;
  revokeAssignment(id: string): Promise<void>;
  hasPermission(userId: string, organizationId: string | null, key: string): Promise<boolean>;
}
