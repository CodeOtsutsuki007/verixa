import type { PrismaClient } from "@verixa/database";
import { Result } from "@verixa/shared-kernel";
import type { RoleRepository } from "../../application/ports/role-repository.js";
import { Role, type RoleId } from "../../domain/entities/role.js";
import { Permission } from "../../domain/value-objects/permission.js";
import { mapPrismaError } from "@verixa/identity/infrastructure/persistence/error-mapper.js";

export class PrismaRoleRepository implements RoleRepository {
  constructor(private readonly prisma: PrismaClient)
   {}

  async save(role: Role): Promise<void> {
    try {
      const permissionKeys = Array.from(role.permissions).map((p) => p.key);
      await this.prisma.role.upsert({
        where: { id: role.id },
        create: {
          id: role.id,
          orgId: role.orgId ?? null,
          name: role.name,
          description: role.description ?? null,
          isSystemRole: role.isSystemRole,
          permissions: {
            connect: permissionKeys.map((key) => ({ key })),
          },
        },
        update: {
          name: role.name,
          description: role.description ?? null,
          isSystemRole: role.isSystemRole,
          permissions: {
            set: permissionKeys.map((key) => ({ key })),
          },
        },
      });
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async findById(id: RoleId): Promise<Role | undefined> {
    try {
      const record = await this.prisma.role.findUnique({
        where: { id },
        include: { permissions: true },
      });
      if (!record) {
        return undefined;
      }
      const permissions = new Set<Permission>();
      for (const pRecord of record.permissions) {
        const pResult = Permission.create(pRecord.key);
        if (Result.isOk(pResult)) {
          permissions.add(pResult.value);
        }
      }
      const roleResult = Role.create({
        id: record.id as RoleId,
        orgId: record.orgId ?? undefined,
        name: record.name,
        description: record.description ?? undefined,
        isSystemRole: record.isSystemRole,
        permissions,
      });
      if (!Result.isOk(roleResult)) {
        return undefined;
      }
      return roleResult.value;
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async findByName(name: string, orgId?: string): Promise<Role | undefined> {
    try {
      const record = await this.prisma.role.findFirst({
        where: {
          name,
          orgId: orgId ?? null,
        },
        include: { permissions: true },
      });
      if (!record) {
        return undefined;
      }
      const permissions = new Set<Permission>();
      for (const pRecord of record.permissions) {
        const pResult = Permission.create(pRecord.key);
        if (Result.isOk(pResult)) {
          permissions.add(pResult.value);
        }
      }
      const roleResult = Role.create({
        id: record.id as RoleId,
        orgId: record.orgId ?? undefined,
        name: record.name,
        description: record.description ?? undefined,
        isSystemRole: record.isSystemRole,
        permissions,
      });
      if (!Result.isOk(roleResult)) {
        return undefined;
      }
      return roleResult.value;
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async findAllForOrg(orgId?: string): Promise<Role[]> {
    try {
      const records = await this.prisma.role.findMany({
        where: {
          orgId: orgId ?? null,
        },
        include: { permissions: true },
      });
      const roles: Role[] = [];
      for (const record of records) {
        const permissions = new Set<Permission>();
        for (const pRecord of record.permissions) {
          const pResult = Permission.create(pRecord.key);
          if (Result.isOk(pResult)) {
            permissions.add(pResult.value);
          }
        }
        const roleResult = Role.create({
          id: record.id as RoleId,
          orgId: record.orgId ?? undefined,
          name: record.name,
          description: record.description ?? undefined,
          isSystemRole: record.isSystemRole,
          permissions,
        });
        if (Result.isOk(roleResult)) {
          roles.push(roleResult.value);
        }
      }
      return roles;
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async delete(id: RoleId): Promise<void> {
    try {
      await this.prisma.role.delete({
        where: { id },
      });
    } catch (error) {
      throw mapPrismaError(error);
    }
  }
}
