-- Versioned ABAC policy records (Phase 08, Issue 150).
--
-- A version is never updated in place. The composite key gives every
-- (policy id, version) pair one durable row and prevents accidental edits
-- from replacing an earlier published revision.
CREATE TYPE "policy_status" AS ENUM ('draft', 'published', 'archived');

CREATE TABLE "policies" (
    "id" UUID NOT NULL,
    "version" INTEGER NOT NULL,
    "name" TEXT NOT NULL,
    "resource_type" TEXT NOT NULL,
    "actions" TEXT[] NOT NULL,
    "rules" JSONB NOT NULL,
    "dsl_source" TEXT,
    "status" "policy_status" NOT NULL DEFAULT 'published',
    "created_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "policies_pkey" PRIMARY KEY ("id", "version"),
    CONSTRAINT "policies_version_positive" CHECK ("version" > 0)
);

-- Target lookups narrow first by resource and active status, then inspect the
-- latest version per policy. The actions array gets a GIN index so a single
-- requested action does not scan every policy for that resource type.
CREATE INDEX "policies_resource_type_id_version_idx"
    ON "policies" ("resource_type", "id", "version" DESC);

CREATE INDEX "policies_actions_gin_idx"
    ON "policies" USING GIN ("actions");
