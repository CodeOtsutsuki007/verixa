import type { PrismaClient } from "@verixa/database";

import type { SessionRepository } from "../../application/ports/session-repository.js";
import type { Session, SessionId, UserId } from "../../domain/entities/session.js";
import { SessionExpiryPolicy } from "../../domain/value-objects/session-expiry-policy.js";

import { withMappedErrors } from "./error-mapper.js";
import { SessionMapper } from "./session-mapper.js";

/**
 * Prisma-backed `SessionRepository`. Satisfies exactly the same port — and the
 * same behavioral contract (`session-repository.contract.ts`) — as
 * `InMemorySessionRepository`, which is what makes them substitutable rather
 * than merely similar.
 *
 * Takes a `PrismaClient` rather than constructing one. That's what lets a
 * caller hand it a transaction client instead (`prisma.$transaction(tx =>
 * ...)`), which later issues depend on for multi-aggregate atomicity — a
 * repository that owned its own connection could never participate in
 * someone else's transaction.
 *
 * ### Expiry policy
 *
 * Sessions are stored with the result of their expiry policy applied
 * (`expiresAt`, the timestamp), but the policy itself is a runtime
 * configuration supplied by the use case or caller. This repository does not
 * store policies — it only looks at the fields they produce. When a session is
 * loaded and needs to be touched (to extend the expiry, if using a sliding
 * policy), the caller supplies the policy to `toDomain()` or to `touch()`.
 */
export class PrismaSessionRepository implements SessionRepository {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly defaultExpiryPolicy: SessionExpiryPolicy,
  ) {}

  async save(session: Session): Promise<void> {
    const row = SessionMapper.toRow(session);

    await withMappedErrors("Session", () =>
      this.prisma.session.upsert({
        where: { id: row.id },
        create: row,
        update: row,
      }),
    );
  }

  async findById(sessionId: SessionId): Promise<Session | undefined> {
    const row = await this.prisma.session.findUnique({
      where: { id: sessionId },
    });
    return row === null ? undefined : SessionMapper.toDomain(row, this.defaultExpiryPolicy);
  }

  async findActiveByUserId(userId: UserId): Promise<Session[]> {
    const now = new Date();

    const rows = await this.prisma.session.findMany({
      where: {
        userId,
        status: "active",
        expiresAt: {
          gt: now,
        },
      },
    });

    return rows.map((row) => SessionMapper.toDomain(row, this.defaultExpiryPolicy));
  }

  async revoke(sessionId: SessionId): Promise<void> {
    // Idempotent: only revoke if not already revoked. Load the session first
    // to preserve its original revokedAt if it's already revoked.
    const existing = await this.prisma.session.findUnique({
      where: { id: sessionId },
    });

    if (existing && existing.status !== "revoked") {
      await withMappedErrors("Session", () =>
        this.prisma.session.update({
          where: { id: sessionId },
          data: {
            status: "revoked",
            revokedAt: new Date(),
          },
        }),
      );
    }
  }

  async revokeAllForUser(userId: UserId): Promise<void> {
    await withMappedErrors("Session", () =>
      this.prisma.session.updateMany({
        where: {
          userId,
          status: "active", // Only revoke non-revoked sessions (idempotent)
        },
        data: {
          status: "revoked",
          revokedAt: new Date(),
        },
      }),
    );
  }
}
