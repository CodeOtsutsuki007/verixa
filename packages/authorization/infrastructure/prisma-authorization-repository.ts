import { randomUUID } from "node:crypto";

import type { PrismaClient } from "@verixa/database";

import type { AuthorizationRepository } from "../application/authorization-repository.js";
import {
  AuthorizationError,
  Role,
  type RoleAssignment,
  type RoleRecord,
} from "../domain/authorization.js";

type RoleWithPermissions = {
  id: string;
  name: string;
  description: string;
  isSystemRole: boolean;
  organizationId: string | null;
  permissions: { permission: { key: string } }[];
};

export class PrismaAuthorizationRepository implements AuthorizationRepository {
  constructor(private readonly prisma: PrismaClient) {}

  private map(row: RoleWithPermissions): RoleRecord {
    return {
      id: row.id,
      name: row.name,
      description: row.description,
      isSystemRole: row.isSystemRole,
      organizationId: row.organizationId,
      permissions: row.permissions.map((permission) => permission.permission.key),
    };
  }

  async listRoles(organizationId?: string | null): Promise<RoleRecord[]> {
    const rows = await this.prisma.role.findMany({
      where: organizationId === undefined ? {} : { organizationId: organizationId ?? null },
      include: { permissions: { include: { permission: true } } },
      orderBy: { name: "asc" },
    });
    return rows.map((row) => this.map(row));
  }

  async getRole(id: string): Promise<RoleRecord | undefined> {
    const row = await this.prisma.role.findUnique({
      where: { id },
      include: { permissions: { include: { permission: true } } },
    });
    return row === null ? undefined : this.map(row);
  }

  async createRole(input: Omit<RoleRecord, "id" | "permissions">): Promise<RoleRecord> {
    const now = new Date();
    const row = await this.prisma.role.create({
      data: {
        id: randomUUID(),
        name: input.name,
        description: input.description,
        isSystemRole: input.isSystemRole,
        organizationId: input.organizationId,
        createdAt: now,
        updatedAt: now,
      },
      include: { permissions: { include: { permission: true } } },
    });
    return this.map(row);
  }

  async updateRole(
    id: string,
    input: { name?: string; description?: string },
  ): Promise<RoleRecord> {
    const row = await this.prisma.role.update({
      where: { id },
      data: { ...input, updatedAt: new Date() },
      include: { permissions: { include: { permission: true } } },
    });
    return this.map(row);
  }

  async deleteRole(id: string): Promise<void> {
    const role = await this.prisma.role.findUnique({
      where: { id },
      select: { isSystemRole: true },
    });
    if (role === null) throw new AuthorizationError("NOT_FOUND");
    if (role.isSystemRole) throw new AuthorizationError("FORBIDDEN");
    await this.prisma.role.delete({ where: { id } });
  }

  async listPermissions(): Promise<{ id: string; key: string; description: string }[]> {
    return this.prisma.permission.findMany({
      select: { id: true, key: true, description: true },
      orderBy: { key: "asc" },
    });
  }

  async grantPermission(roleId: string, key: string): Promise<RoleRecord> {
    const permission = await this.prisma.permission.findUnique({ where: { key } });
    if (permission === null) throw new AuthorizationError("NOT_FOUND");
    const role = await this.prisma.role.findUnique({
      where: { id: roleId },
      select: { isSystemRole: true },
    });
    if (role === null) throw new AuthorizationError("NOT_FOUND");
    if (key === "*:*" && !role.isSystemRole) throw new AuthorizationError("FORBIDDEN");
    await this.prisma.rolePermission.upsert({
      where: { roleId_permissionId: { roleId, permissionId: permission.id } },
      create: { roleId, permissionId: permission.id },
      update: {},
    });
    return (await this.getRole(roleId))!;
  }

  async revokePermission(roleId: string, key: string): Promise<RoleRecord> {
    const permission = await this.prisma.permission.findUnique({ where: { key } });
    if (permission === null) throw new AuthorizationError("NOT_FOUND");
    const role = await this.prisma.role.findUnique({
      where: { id: roleId },
      select: { isSystemRole: true },
    });
    if (role === null) throw new AuthorizationError("NOT_FOUND");
    if (role.isSystemRole) throw new AuthorizationError("FORBIDDEN");
    await this.prisma.rolePermission.deleteMany({ where: { roleId, permissionId: permission.id } });
    return (await this.getRole(roleId))!;
  }

  async listAssignments(userId: string, organizationId?: string | null): Promise<RoleAssignment[]> {
    const rows = await this.prisma.userRoleAssignment.findMany({
      where: {
        userId,
        ...(organizationId === undefined ? {} : { organizationId: organizationId ?? null }),
      },
      orderBy: { assignedAt: "desc" },
    });
    return rows;
  }

  async assignRole(input: Omit<RoleAssignment, "id" | "assignedAt">): Promise<RoleAssignment> {
    const role = await this.prisma.role.findUnique({ where: { id: input.roleId } });
    if (role === null) throw new AuthorizationError("NOT_FOUND");
    const existing = await this.prisma.userRoleAssignment.findFirst({
      where: {
        userId: input.userId,
        roleId: input.roleId,
        organizationId: input.organizationId ?? null,
        OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
      },
    });
    if (existing !== null) return existing;
    return this.prisma.userRoleAssignment.create({
      data: { id: randomUUID(), ...input, assignedAt: new Date() },
    });
  }

  async revokeAssignment(id: string): Promise<void> {
    await this.prisma.userRoleAssignment.delete({ where: { id } });
  }

  async hasPermission(
    userId: string,
    organizationId: string | null,
    key: string,
  ): Promise<boolean> {
    const rows = await this.prisma.userRoleAssignment.findMany({
      where: {
        userId,
        OR: [{ organizationId }, { organizationId: null }],
        AND: [{ OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }] }],
      },
      include: { role: { include: { permissions: { include: { permission: true } } } } },
    });
    return rows.some((row) =>
      new Role({
        id: row.role.id,
        name: row.role.name,
        description: row.role.description,
        isSystemRole: row.role.isSystemRole,
        organizationId: row.role.organizationId,
        permissions: row.role.permissions.map((permission) => permission.permission.key),
      }).hasPermission(key),
    );
  }
}
