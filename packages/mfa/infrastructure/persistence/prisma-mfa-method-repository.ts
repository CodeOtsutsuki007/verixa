import type { PrismaClient } from "@verixa/database";
import type { MfaMethodRepository } from "../../application/ports/mfa-method-repository.js";
import type { MfaMethod, MfaMethodId, UserId } from "../../domain/entities/mfa-method.js";
import { withMappedErrors } from "./error-mapper.js";
import { MfaMethodMapper } from "./mfa-method-mapper.js";

export class PrismaMfaMethodRepository implements MfaMethodRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async save(method: MfaMethod): Promise<void> {
    const row = MfaMethodMapper.toRow(method);
    const { id, ...withoutId } = row;

    await withMappedErrors("MfaMethod", () =>
      this.prisma.mfaMethod.upsert({
        where: { id },
        create: row as any,
        update: withoutId as any,
      })
    );
  }

  async findById(id: MfaMethodId): Promise<MfaMethod | undefined> {
    const row = await this.prisma.mfaMethod.findUnique({ where: { id } });
    return row ? MfaMethodMapper.toDomain(row) : undefined;
  }

  async findActiveByUserId(userId: UserId): Promise<MfaMethod[]> {
    const rows = await this.prisma.mfaMethod.findMany({
      where: { userId, status: "active" },
    });
    return rows.map(row => MfaMethodMapper.toDomain(row));
  }

  async findPendingByUserId(userId: UserId): Promise<MfaMethod[]> {
    const rows = await this.prisma.mfaMethod.findMany({
      where: { userId, status: "pending" },
    });
    return rows.map(row => MfaMethodMapper.toDomain(row));
  }

  async findAllByUserId(userId: UserId): Promise<MfaMethod[]> {
    const rows = await this.prisma.mfaMethod.findMany({ where: { userId } });
    return rows.map(row => MfaMethodMapper.toDomain(row));
  }

  async delete(id: MfaMethodId): Promise<void> {
    await withMappedErrors("MfaMethod", async () => {
      await this.prisma.mfaMethod.delete({ where: { id } });
    });
  }
}
