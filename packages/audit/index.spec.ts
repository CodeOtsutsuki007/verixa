import { fileURLToPath } from "node:url";

import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

import * as audit from "./index.js";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));

describe("@verixa/audit public API", () => {
  it("records and verifies a chain using nothing but the public surface", async () => {
    const repository = new audit.InMemoryAuditLogRepository();
    const record = new audit.RecordAuditEvent(repository);

    await record.execute({ action: "user.registered", subjectId: "user-1" });
    await record.execute({ action: "user.login_succeeded", actorId: "user-1" });

    expect(await repository.count()).toBe(2);
    expect(audit.verifyChain(repository.all())).toBeUndefined();
  });

  it("does not expose the hash chain's internals", () => {
    // Runtime values, checked by name: a type-only export leaves nothing at
    // runtime, so these would only be present if someone re-exported the
    // value — the thing this surface exists to prevent.
    expect(audit).not.toHaveProperty("GENESIS_HASH");
    expect(audit).not.toHaveProperty("AuditLogEntry");
    expect(audit).not.toHaveProperty("AuditLogEntryMapper");
  });
});

/**
 * Runs the repository's real ESLint configuration, so what is verified is the
 * rule contributors actually hit — not a copy of it that could drift.
 *
 * Linted as the text of files that exist on disk, because the configuration is
 * type-aware and the TypeScript project service only knows files that belong
 * to a project.
 */
describe("deep-import boundary rule for @verixa/audit", () => {
  const eslint = new ESLint({ cwd: repositoryRoot });

  async function boundaryViolations(code: string, filePath: string): Promise<string[]> {
    const [result] = await eslint.lintText(code, { filePath: `${repositoryRoot}${filePath}` });
    return (result?.messages ?? [])
      .filter((message) => message.ruleId === "no-restricted-imports")
      .map((message) => message.message);
  }

  it("rejects a deep import from another package", async () => {
    const violations = await boundaryViolations(
      'export { AuditLogEntry } from "@verixa/audit/domain/entities/audit-log-entry.js";\n',
      "apps/api/src/composition-root.ts",
    );

    expect(violations).toHaveLength(1);
    expect(violations[0]).toContain("`@verixa/audit`");
  });

  it("allows importing from the package root", async () => {
    const violations = await boundaryViolations(
      'export { RecordAuditEvent } from "@verixa/audit";\n',
      "apps/api/src/composition-root.ts",
    );

    expect(violations).toEqual([]);
  });

  it("does not apply inside the audit package itself", async () => {
    const violations = await boundaryViolations(
      'export { GENESIS_HASH } from "@verixa/audit/domain/entities/audit-log-entry.js";\n',
      "packages/audit/index.ts",
    );

    expect(violations).toEqual([]);
  });
}, 120_000);
