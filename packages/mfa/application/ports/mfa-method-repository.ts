import type { Id } from "@verixa/shared-kernel";

import type { MfaMethod, MfaMethodId } from "../../domain/entities/mfa-method.js";

export interface MfaMethodRepository {
  save(method: MfaMethod): Promise<void>;
  findById(id: MfaMethodId): Promise<MfaMethod | null>;
  findByUserId(userId: Id<"UserId">): Promise<MfaMethod[]>;
import type { MfaMethod, MfaMethodId } from "../../domain/entities/mfa-method.js";
import type { MfaMethod, MfaMethodId, UserId } from "../../domain/entities/mfa-method.js";

/**
 * Port for accessing and persisting `MfaMethod` aggregates.
 *
 * Implementations handle encryption-at-rest for TOTP secrets transparently —
 * a secret must never be persisted in plaintext. The domain stays ignorant of
 * this storage-level concern.
 */
export interface MfaMethodRepository {
  /** Idempotently saves a method: updates an existing row or creates a new one. */
  save(method: MfaMethod): Promise<void>;

  /** Returns the method with the given id, or `undefined` if none exists. */
  findById(id: MfaMethodId): Promise<MfaMethod | undefined>;

  /** Returns every `active` method for a user, excluding `pending`/`disabled`. */
  findActiveByUserId(userId: UserId): Promise<MfaMethod[]>;

  /** Returns every `pending` method for a user (e.g. awaiting enrollment confirmation). */
  findPendingByUserId(userId: UserId): Promise<MfaMethod[]>;

  /** Returns every method for a user regardless of status (used by recovery). */
  findAllByUserId(userId: UserId): Promise<MfaMethod[]>;

  /** Physically deletes a method. Abandoned enrollments may be hard-deleted. */
  delete(id: MfaMethodId): Promise<void>;
}
