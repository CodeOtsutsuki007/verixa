-- KYC-style verification requests and their reviewer assignments (Phase 09,
-- Issues 161-175). One table, because the reviewer claim and the terminal
-- decision are state *on* the request, not separate aggregates: a request
-- always has at most one active claim, and the claim is meaningless detached
-- from the request it targets.
--
-- A note on scope: evidence (Issue 165/168) is deliberately NOT a table here
-- yet. These four issues cover the provider port, the default manual-review
-- provider, and the claim/decide use cases; evidence persistence and its
-- storage adapter belong to Issues 166 and 168.

-- The domain's unions, mirrored. Prisma enum member names cannot contain a
-- hyphen, so the domain's `identity-document` is stored as `identity_document`;
-- the single translation lives in the verification persistence mapper.
CREATE TYPE "verification_type" AS ENUM ('identity_document', 'address', 'liveness');

CREATE TYPE "verification_status" AS ENUM (
    'pending_evidence',
    'submitted',
    'in_review',
    'needs_more_info',
    'approved',
    'rejected'
);

CREATE TYPE "verification_decision" AS ENUM ('approved', 'rejected');

CREATE TABLE "verification_requests" (
    "id" UUID NOT NULL,

    "subject_user_id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,

    "type" "verification_type" NOT NULL,
    "status" "verification_status" NOT NULL,

    -- The reviewer currently holding a time-bounded claim. Plain UUIDs with no
    -- foreign key: whether the caller is a reviewer at all is Phase 07's RBAC
    -- concern, and a bare UUID means the record survives that reviewer's
    -- deletion, matching the audit log's actor/subject columns.
    "assigned_reviewer_id" UUID,
    "assigned_at" TIMESTAMPTZ(3),

    -- A lease, not a lock. The queue skips a row whose claim has expired, so a
    -- reviewer whose session dies releases the case without a scheduled job to
    -- notice.
    "claim_expires_at" TIMESTAMPTZ(3),

    "decided_by_reviewer_id" UUID,
    "decided_at" TIMESTAMPTZ(3),
    "decision" "verification_decision",

    -- The mandatory rationale recorded with a decision (Issue 175). On the row
    -- rather than in a separate decisions table so that reading a decided
    -- request answers "by whom, when, and why" in one query.
    "decision_note" TEXT,

    -- What the reviewer asked for while the request is `needs_more_info`
    -- (Issue 176).
    "needs_more_info_note" TEXT,

    "created_at" TIMESTAMPTZ(3) NOT NULL,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "verification_requests_pkey" PRIMARY KEY ("id")
);

-- "This subject's verification history."
CREATE INDEX "verification_requests_subject_user_id_idx"
    ON "verification_requests" ("subject_user_id");

-- The reviewer queue's ordering key. Composite so that
-- `WHERE status = 'in_review' ORDER BY created_at` — the claim query — is
-- served by the index rather than a filter-then-sort over the whole table.
CREATE INDEX "verification_requests_status_created_at_idx"
    ON "verification_requests" ("status", "created_at");

-- Tenant-scoped listings.
CREATE INDEX "verification_requests_organization_id_idx"
    ON "verification_requests" ("organization_id");

-- "Does this reviewer hold a live claim?" — the one-at-a-time policy check.
CREATE INDEX "verification_requests_assigned_reviewer_id_claim_expires_at_idx"
    ON "verification_requests" ("assigned_reviewer_id", "claim_expires_at");

-- Cascade: a verification request is meaningless once its subject or tenant is
-- gone, and retaining PII-adjacent rows after erasure would keep exactly the
-- data that needed to go.
ALTER TABLE "verification_requests"
    ADD CONSTRAINT "verification_requests_subject_user_id_fkey"
    FOREIGN KEY ("subject_user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "verification_requests"
    ADD CONSTRAINT "verification_requests_organization_id_fkey"
    FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Row-Level Security, following the pattern established for the other
-- tenant-scoped tables (Issue 052, ADR-0002). A request carries
-- PII-adjacent metadata, so it must never be readable across an org boundary
-- — not even by another tenant's reviewer working the same queue.
--
-- ENABLE alone exempts the table owner, and the owner is who the application
-- connects as in most setups, so FORCE is what makes the policy real for the
-- only role that matters. A Postgres SUPERUSER still bypasses RLS, which is
-- why the application must connect as a non-superuser and set the tenant via
-- `withTenantContext` (see docs/security/multi-tenancy.md).
ALTER TABLE "verification_requests" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "verification_requests" FORCE ROW LEVEL SECURITY;

CREATE POLICY "tenant_isolation" ON "verification_requests"
    USING ("organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
    WITH CHECK ("organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
