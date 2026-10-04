import { describe } from "vitest";

import { auditLogRepositoryContract } from "../testing/contracts/audit-log-repository.contract.js";
import { InMemoryAuditLogRepository } from "../testing/in-memory-audit-repositories.js";

/**
 * The in-memory fake is what nearly every test in the monorepo records audit
 * events against, so "the fake honours the append protocol like the real
 * adapter" is load-bearing rather than nice to have. The same suite runs
 * against `PrismaAuditLogRepository` in `prisma-audit-repositories.spec.ts`,
 * which is the only thing keeping the two honest about behaving identically.
 */
describe("InMemoryAuditLogRepository", () => {
  auditLogRepositoryContract(() => new InMemoryAuditLogRepository());
});
