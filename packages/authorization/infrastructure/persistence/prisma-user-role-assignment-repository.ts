import type { PrismaClient } from "@verixa/database";
import type { UserRoleAssignmentRepository } from "../../application/ports/user-role-assignment-repository.js";
import { UserRoleAssignment, type UserRoleAssignmentId } from "../../domain/entities/user-role-assignment.js";
import type { RoleId } from "../../domain/entities/role.js";
import { mapPrismaError } from "@verixa/identity/infrastructure/persistence/error-mapper.js";

export class PrismaUserRoleAssignmentRepository implements UserRoleAssignmentRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async save(assignment: UserRoleAssignment): Promise<void> {
    try {
      await this.prisma.userRoleAssignment.upsert({
        where: { id: assignment.id },
        create: {
          id: assignment.id,
          userId: assignment.userId,
          roleId: assignment.roleId,
          orgId: assignment.orgId ?? null,
          assignedAt: assignment.assignedAt,
          assignedBy: assignment.assignedBy ?? null,
          expiresAt: assignment.expiresAt ?? null,
        },
        update: {
          userId: assignment.userId,
          roleId: assignment.roleId,
          orgId: assignment.orgId ?? null,
          assignedAt: assignment.assignedAt,
          assignedBy: assignment.assignedBy ?? null,
          expiresAt: assignment.expiresAt ?? null,
        },
      });
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async findById(id: UserRoleAssignmentId): Promise<UserRoleAssignment | undefined> {
    try {
      const record = await this.prisma.userRoleAssignment.findUnique({
        where: { id },
      });
      if (!record) {
        return undefined;
      }
      return UserRoleAssignment.create({
        id: record.id as UserRoleAssignmentId,
        userId: record.userId,
        roleId: record.roleId as RoleId,
        orgId: record.orgId ?? undefined,
        assignedAt: record.assignedAt,
        assignedBy: record.assignedBy ?? undefined,
        expiresAt: record.expiresAt ?? undefined,
      });
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async findAllForUser(userId: string, orgId?: string): Promise<UserRoleAssignment[]> {
    try {
      const records = await this.prisma.userRoleAssignment.findMany({
        where: {
          userId,
          orgId: orgId ?? null,
        },
      });
      return records.map((record) =>
        UserRoleAssignment.create({
          id: record.id as UserRoleAssignmentId,
          userId: record.userId,
          roleId: record.roleId as RoleId,
          orgId: record.orgId ?? undefined,
          assignedAt: record.assignedAt,
          assignedBy: record.assignedBy ?? undefined,
          expiresAt: record.expiresAt ?? undefined,
        })
      );
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async findAllForRole(roleId: RoleId): Promise<UserRoleAssignment[]> {
    try {
      const records = await this.prisma.userRoleAssignment.findMany({
        where: {
          roleId,
        },
      });
      return records.map((record) =>
        UserRoleAssignment.create({
          id: record.id as UserRoleAssignmentId,
          userId: record.userId,
          roleId: record.roleId as RoleId,
          orgId: record.orgId ?? undefined,
          assignedAt: record.assignedAt,
          assignedBy: record.assignedBy ?? undefined,
          expiresAt: record.expiresAt ?? undefined,
        })
      );
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async delete(id: UserRoleAssignmentId): Promise<void> {
    try {
      await this.prisma.userRoleAssignment.delete({
        where: { id },
      });
    } catch (error) {
      throw mapPrismaError(error);
    }
  }
}
