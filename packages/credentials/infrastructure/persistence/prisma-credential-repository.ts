import type { CredentialRow, PrismaClient } from "@verixa/database";
import { asId } from "@verixa/shared-kernel";

import type {
  CredentialRepository,
  StaleCredentialMetrics,
} from "../../application/ports/credential-repository.js";
import { Credential, type CredentialUserId } from "../../domain/entities/credential.js";

/**
 * What goes *into* the database.
 *
 * Distinct from `CredentialRow` only in `passwordHistory`: Prisma types that
 * column as `JsonValue` on the way out, because a Json column can hold
 * anything, but an insert needs a concrete value. The read and write
 * directions genuinely differ, and collapsing them would mean casting.
 */
type CredentialRowInput = Omit<CredentialRow, "passwordHistory"> & {
  passwordHistory: string[];
};

/** Reads the Json `password_history` column back as the string list the domain expects. */
function toPasswordHistory(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** Row ↔ aggregate translation for `Credential`. */
export const CredentialMapper = {
  toDomain(row: CredentialRow): Credential {
    return Credential.reconstitute({
      id: asId<"CredentialId">(row.id),
      userId: asId<"UserId">(row.userId),
      passwordHash: row.passwordHash,
      failedAttempts: row.failedAttempts,
      // Null in the column, `undefined` in the domain. The database has one
      // absent value and TypeScript has two; mapping them at the boundary is
      // what stops `null` leaking inward and forcing every call site to
      // handle both.
      lockedUntil: row.lockedUntil ?? undefined,
      // `passwordHistory` is a Json column, so Prisma types it as JsonValue:
      // the shape is a convention this code maintains, not one Postgres
      // enforces. Coerced defensively rather than cast, so a hand-edited row
      // degrades to an empty history instead of crashing a login.
      passwordHistory: toPasswordHistory(row.passwordHistory),
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
  },

  toRow(credential: Credential): CredentialRowInput {
    return {
      id: credential.id,
      userId: credential.userId,
      passwordHash: credential.passwordHash,
      failedAttempts: credential.failedAttempts,
      lockedUntil: credential.lockedUntil ?? null,
      passwordHistory: credential.passwordHistory,
      createdAt: credential.createdAt,
      updatedAt: credential.updatedAt,
    };
  },
};

/**
 * Prisma-backed `CredentialRepository`.
 *
 * Takes its client as a constructor argument, like every other repository
 * here, so it can be handed a transaction client and enlisted in someone
 * else's unit of work — which `RegisterUserWithPassword` depends on.
 */
export class PrismaCredentialRepository implements CredentialRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findByUserId(userId: CredentialUserId): Promise<Credential | undefined> {
    const row = await this.prisma.credential.findUnique({ where: { userId } });
    return row === null ? undefined : CredentialMapper.toDomain(row);
  }

  async save(credential: Credential): Promise<void> {
    const row = CredentialMapper.toRow(credential);
    const { id, ...withoutId } = row;
    await this.prisma.credential.upsert({
      where: { id },
      create: row,
      update: withoutId,
    });
  }

  async deleteByUserId(userId: CredentialUserId): Promise<void> {
    // `deleteMany`, not `delete`: deleting a credential that isn't there is a
    // no-op, not an error. `delete` would throw P2025 and make every caller
    // handle "already gone" as a failure, when it is the desired end state.
    await this.prisma.credential.deleteMany({ where: { userId } });
  }

  async getStaleCredentialMetrics(currentHasher: {
    needsRehash(encodedHash: string): boolean;
  }): Promise<StaleCredentialMetrics> {
    // Fetch all credentials to evaluate staleness. The needsRehash check must
    // happen in application code because it examines the parsed parameters —
    // Prisma cannot express "extract parameters from a PHC string and compare
    // to defaults". A raw SQL query would require duplicating the parameter
    // logic here.
    const allCredentials = await this.prisma.credential.findMany({
      select: { passwordHash: true, createdAt: true },
    });

    const staleCreatedAts = allCredentials
      .filter(({ passwordHash }) => currentHasher.needsRehash(passwordHash))
      .map(({ createdAt }) => createdAt)
      .sort((a, b) => a.getTime() - b.getTime());

    if (staleCreatedAts.length === 0) {
      return {
        count: 0,
        oldestCreatedAt: null,
        medianCreatedAt: null,
        p95CreatedAt: null,
      };
    }

    const count = staleCreatedAts.length;
    const oldestCreatedAt = staleCreatedAts[0];

    // Median is the middle value (50th percentile).
    const medianIndex = Math.floor((count - 1) / 2);
    const medianCreatedAt = staleCreatedAts[medianIndex];

    // 95th percentile: the value at position floor(0.95 * (n - 1)).
    // For n=100, that's position 94 (the 95th item, 0-indexed).
    const p95Index = Math.floor(0.95 * (count - 1));
    const p95CreatedAt = staleCreatedAts[p95Index];

    // Indexing an array yields `T | undefined` under
    // noUncheckedIndexedAccess; the metric contract uses `null` for absent.
    return {
      count,
      oldestCreatedAt: oldestCreatedAt ?? null,
      medianCreatedAt: medianCreatedAt ?? null,
      p95CreatedAt: p95CreatedAt ?? null,
    };
  }
}
