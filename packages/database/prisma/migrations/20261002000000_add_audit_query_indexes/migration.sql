-- Composite indexes for the filtered audit query paths (Issue 188).
--
-- Every read through PrismaAuditLogRepository.findWithFilters (Issue 187)
-- filters on at most one equality column and then walks the log in
-- `sequence` order for keyset pagination. The indexes below lead with the
-- equality column and include `sequence` second, so the planner can satisfy
-- both the filter and the ordering from one index instead of filtering and
-- then sorting.
--
-- The roadmap for this issue named (organizationId, timestamp),
-- (actorId, timestamp) and (resourceType, resourceId, timestamp). Two of
-- those columns do not exist on this table -- they belong to the Phase 10
-- AuditEvent model, which is not persisted yet -- and the query orders by
-- `sequence`, not `timestamp`, so a time-led index would still need a sort.
-- These match the query paths that actually exist. See
-- docs/performance/audit-query-benchmarks.md.
--
-- The single-column indexes these replace are redundant: a B-tree on
-- (a, b) already answers `WHERE a = ?`, so keeping both only adds write cost
-- to the append-only path.

DROP INDEX "audit_log_entries_occurred_at_idx";
DROP INDEX "audit_log_entries_actor_id_idx";
DROP INDEX "audit_log_entries_subject_id_idx";

CREATE INDEX "audit_log_entries_actor_id_sequence_idx" ON "audit_log_entries" ("actor_id", "sequence");
CREATE INDEX "audit_log_entries_subject_id_sequence_idx" ON "audit_log_entries" ("subject_id", "sequence");
CREATE INDEX "audit_log_entries_action_sequence_idx" ON "audit_log_entries" ("action", "sequence");
CREATE INDEX "audit_log_entries_occurred_at_sequence_idx" ON "audit_log_entries" ("occurred_at", "sequence");
