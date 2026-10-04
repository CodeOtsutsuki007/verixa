import type { PrismaClient } from "@verixa/database";
import { Result } from "@verixa/shared-kernel";
import type { PermissionRepository } from "../../application/ports/permission-repository.js";
import { Permission } from "../../domain/value-objects/permission.js";
import { mapPrismaError } from "@verixa/identity/infrastructure/persistence/error-mapper.js";

export class PrismaPermissionRepository implements PermissionRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async save(permission: Permission): Promise<void> {
    try {
      await this.prisma.permission.upsert({
        where: { key: permission.key },
        create: {
          key: permission.key,
          resource: permission.resource,
          action: permission.action,
        },
        update: {
          resource: permission.resource,
          action: permission.action,
        },
      });
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async findByKey(key: string): Promise<Permission | undefined> {
    try {
      const record = await this.prisma.permission.findUnique({
        where: { key },
      });
      if (!record) {
        return undefined;
      }
      const result = Permission.create(record.key);
      if (!Result.isOk(result)) {
        return undefined;
      }
      return result.value;
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async findAll(): Promise<Permission[]> {
    try {
      const records = await this.prisma.permission.findMany();
      const permissions: Permission[] = [];
      for (const record of records) {
        const result = Permission.create(record.key);
        if (Result.isOk(result)) {
          permissions.push(result.value);
        }
      }
      return permissions;
    } catch (error) {
      throw mapPrismaError(error);
    }
  }
}
