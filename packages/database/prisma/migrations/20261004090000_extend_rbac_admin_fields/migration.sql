-- Add the fields required by the admin API to the RBAC tables already
-- introduced by 20261003000000_add_rbac_and_mfa_tables.
ALTER TABLE "roles"
  ADD COLUMN "is_system_role" BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE "user_role_assignments"
  ADD COLUMN "assigned_by" UUID,
  ADD COLUMN "expires_at" TIMESTAMPTZ(3);
