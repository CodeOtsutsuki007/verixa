import type { PrismaClient } from "@verixa/database";

import type { PolicyRepository } from "../../application/ports/policy-repository.js";
import type { Policy, PolicyId } from "../../domain/entities/policy.js";

import { withMappedErrors } from "./error-mapper.js";
import { PolicyMapper } from "./policy-mapper.js";

/** Prisma adapter for the append-only `PolicyRepository` port. */
export class PrismaPolicyRepository implements PolicyRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async save(policy: Policy): Promise<void> {
    // createMany + skipDuplicates is an atomic insert-if-absent for the
    // composite (id, version) key. An upsert would rewrite an old revision.
    await withMappedErrors("Policy", () =>
      this.prisma.policy
        .createMany({
          data: [PolicyMapper.toRow(policy)],
          skipDuplicates: true,
        })
        .then(() => undefined),
    );
  }

  async findById(id: PolicyId): Promise<Policy | undefined> {
    const row = await this.prisma.policy.findFirst({
      where: { id },
      orderBy: { version: "desc" },
    });
    return row === null ? undefined : PolicyMapper.toDomain(row);
  }

  async findApplicableTo(resourceType: string, action: string): Promise<Policy[]> {
    // First narrow by indexed selector fields, then select only the greatest
    // version for each policy id. Filtering status after selecting the latest
    // version ensures a newer archived revision does not expose an older one.
    const latest = await this.prisma.policy.groupBy({
      by: ["id"],
      where: { resourceType, actions: { has: action } },
      _max: { version: true },
    });
    const latestVersions = latest.flatMap(({ id, _max }) =>
      _max.version === null ? [] : [{ id, version: _max.version }],
    );
    if (latestVersions.length === 0) return [];

    const rows = await this.prisma.policy.findMany({
      where: {
        OR: latestVersions,
        status: "published",
      },
      orderBy: { id: "asc" },
    });
    return rows.map((row) => PolicyMapper.toDomain(row));
  }

  async listVersionsFor(policyId: PolicyId): Promise<Policy[]> {
    const rows = await this.prisma.policy.findMany({
      where: { id: policyId },
      orderBy: { version: "asc" },
    });
    return rows.map((row) => PolicyMapper.toDomain(row));
  }
}
