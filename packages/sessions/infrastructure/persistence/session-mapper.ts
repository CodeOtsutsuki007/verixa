import type { SessionRow } from "@verixa/database";
import { asId } from "@verixa/shared-kernel";

import { Session, type SessionId, type UserId } from "../../domain/entities/session.js";
import { SessionExpiryPolicy } from "../../domain/value-objects/session-expiry-policy.js";

/**
 * Translates between the `sessions` row shape and the `Session` aggregate.
 *
 * This file is the entire reason `@verixa/database` never appears in the
 * domain or application layers: everything Prisma-shaped stops here. Without
 * an explicit mapper, the natural shortcut is to let Prisma's generated types
 * *be* the domain model — which works until the schema needs to change for a
 * database reason and every layer changes with it, or until something
 * constructs a "Session" that never passed a single domain invariant.
 *
 * The mapping is deliberately manual rather than a generic object-to-object
 * mapper. It's more code, and it's the code that would otherwise silently do
 * the wrong thing: reconstructing the `SessionExpiryPolicy` requires knowing
 * both that it exists and what its constructor signature is, and a generic
 * mapper that just assigned properties would produce a structurally-valid,
 * semantically-broken aggregate.
 */
export const SessionMapper = {
  /**
   * Row → aggregate.
   *
   * Uses `Session.reconstitute`, not `Session.create`: this data was already
   * valid when it was written, so re-running creation rules would be both
   * redundant and wrong (creation assigns a new id and an initial expiry;
   * loading must preserve what's stored).
   *
   * The `expiryPolicy` cannot be read from the database (it's a runtime
   * configuration, not persisted data). Callers must provide it. This is
   * intentional: the policy belongs to the session's creation context
   * (e.g., "this user's refresh tokens use a 7-day absolute policy"), and
   * reconstructing a session from the database doesn't recreate that context.
   * A use case that loads a session and needs to touch it must supply the
   * policy it wants to use.
   *
   * The policy is supplied by callers, which mirrors the user repository's
   * pattern: value objects are rebuilt through their factories, and a failure
   * there is treated as a programmer/data-integrity error rather than a
   * `Result` — by construction nothing invalid should ever have been written,
   * so a failure means the database disagrees with the domain and continuing
   * would silently propagate corruption. Throwing is the correct response.
   */
  toDomain(row: SessionRow, expiryPolicy: SessionExpiryPolicy): Session {
    return Session.reconstitute({
      id: asId<"SessionId">(row.id),
      userId: asId<"UserId">(row.userId),
      createdAt: row.createdAt,
      lastSeenAt: row.lastSeenAt,
      expiresAt: row.expiresAt,
      revokedAt: row.revokedAt ?? undefined,
      status: row.status,
      expiryPolicy,
    });
  },

  /**
   * Aggregate → row. Total and non-failing: a `Session` is valid by construction.
   *
   * Note: the `expiryPolicy` itself is not persisted. Only its effects
   * (the `expiresAt` timestamp, the `status` and `revokedAt` fields) are.
   * The policy is a runtime configuration that the application layer supplies
   * when it loads and needs to manipulate a session.
   */
  toRow(session: Session): SessionRow {
    return {
      id: session.id,
      userId: session.userId,
      createdAt: session.createdAt,
      lastSeenAt: session.lastSeenAt,
      expiresAt: session.expiresAt,
      revokedAt: session.revokedAt ?? null,
      status: session.status,
    };
  },
};
