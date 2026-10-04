-- Brings two tables back in line with schema.prisma.
--
-- Both were drift reported by `prisma migrate diff`: the schema described
-- something replaying the migrations would never produce.

-- `password_history` was created as JSON but the schema maps it to `Json`,
-- which Prisma emits as JSONB.
--
-- The difference is not cosmetic. JSON stores the original text and reparses
-- on every read; JSONB stores a decomposed binary form, which is what makes
-- containment operators and GIN indexes available. Code written against the
-- schema would assume the latter.
ALTER TABLE "credentials"
    ALTER COLUMN "password_history" TYPE JSONB USING "password_history"::JSONB;

-- `sessions.user_id` already had a foreign key, declared inline when the
-- table was created, but without ON UPDATE CASCADE -- which is what the drift
-- report was pointing at, not a missing constraint.
--
-- Dropped and recreated rather than altered, because Postgres has no ALTER
-- for a constraint's referential actions.
ALTER TABLE "sessions" DROP CONSTRAINT IF EXISTS "sessions_user_id_fkey";

ALTER TABLE "sessions"
    ADD CONSTRAINT "sessions_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
