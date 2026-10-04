-- Password history and reuse prevention (Issue 072).
--
-- Stores hashes of the last N passwords per credential, checked on password
-- change and reset flows to prevent trivial "change and change back" bypasses.
--
-- Stored as a JSON array of hashes ordered most-recent-first:
-- ["$argon2id$...$", "$argon2id$...$", ...]
--
-- Capped at PasswordHistoryPolicy.depth (default 5) entries. NIST SP 800-63B
-- endorses reuse prevention even as it deprioritizes forced rotation.
-- N=5 balances security vs. friction.

ALTER TABLE "credentials"
    ADD COLUMN "password_history" JSON NOT NULL DEFAULT '[]';

-- Type annotation: an array of strings (password hashes).
-- Prisma's migration generator does not preserve comments on JSON columns,
-- so this is documented here and in the Prisma schema.
