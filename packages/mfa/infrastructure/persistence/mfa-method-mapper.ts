import { MfaMethodRow as PrismaMfaMethodRow } from "@verixa/database";
import { MfaMethod, type MfaMethodId, type UserId, type MfaMethodType, type MfaMethodStatus } from "../../domain/entities/mfa-method.js";
import { encrypt, decrypt } from "../crypto/encryption.js";

export class MfaMethodMapper {
  static toDomain(row: PrismaMfaMethodRow): MfaMethod {
    const secret = row.secret ? decrypt(row.secret) : null;
    return MfaMethod.load({
      id: row.id as MfaMethodId,
      userId: row.userId as UserId,
      type: row.type as MfaMethodType,
      status: row.status as MfaMethodStatus,
      secret,
      lastUsedAt: row.lastUsedAt,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      // Lockout/replay state is domain-only for now: the `mfa_methods` table
      // has no columns for it yet, so it is reset on rehydration rather than
      // silently lost in the middle of a session. A follow-up migration will
      // persist these when the rate-limiting guarantees are needed across
      // requests (see docs/security/mfa-design.md).
      failedAttempts: 0,
      lockedUntil: null,
      lastUsedStep: null,
    });
  }

  static toRow(method: MfaMethod): Omit<PrismaMfaMethodRow, "user"> {
    const secret = method.secret ? encrypt(method.secret) : null;
    return {
      id: method.id,
      userId: method.userId,
      type: method.type as any,
      status: method.status as any,
      secret,
      lastUsedAt: method.lastUsedAt,
      createdAt: method.createdAt,
      updatedAt: method.updatedAt,
    };
  }
}
