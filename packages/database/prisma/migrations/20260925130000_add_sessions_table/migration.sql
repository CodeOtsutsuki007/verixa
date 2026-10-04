-- Sessions table for Phase 05 (Issue 083). Stores authenticated user sessions,
-- tracking their lifecycle from creation through expiry or explicit revocation.
--
-- Indexed on (userId, expiresAt) for the primary query pattern: "active sessions
-- per user" lookups (used by "list devices", session limits, "log out everywhere").
-- Secondary index on expiresAt for background expiry sweeps.

CREATE TYPE "session_status" AS ENUM ('active', 'revoked');

CREATE TABLE "sessions" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "revoked_at" TIMESTAMPTZ(3),
    "status" "session_status" NOT NULL,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE
);

-- Fast lookup for "active sessions per user" queries.
-- Sorted on both columns means range queries like
--   WHERE userId = ? AND status = 'active' AND expiresAt > now()
-- use this index without a secondary sort.
CREATE INDEX "sessions_user_id_expires_at_idx" ON "sessions" ("user_id", "expires_at");

-- Supports background expiry sweep.
CREATE INDEX "sessions_expires_at_idx" ON "sessions" ("expires_at");
