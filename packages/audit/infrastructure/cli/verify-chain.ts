#!/usr/bin/env node
import { randomUUID } from "node:crypto";

import { Keypair } from "@stellar/stellar-sdk";
import { PrismaClient } from "@verixa/database";
import { Result } from "@verixa/shared-kernel";
import { StellarHashAnchor } from "@verixa/stellar-anchor";

import type { AnchorVerifierPort } from "../../application/ports/audit-log-repository.js";
import { VerifyAuditChain } from "../../application/use-cases/verify-audit-chain.js";
import {
  PrismaAnchorRecordRepository,
  PrismaAuditLogRepository,
} from "../persistence/prisma-audit-repositories.js";

/**
 * Verifies the audit log's hash chain against a real database.
 *
 *     pnpm audit:verify-chain
 *
 * The point of this tool is that it can be run by someone who does not trust
 * the database — an operator after a suspected incident, an auditor, whoever.
 * It reads the rows, re-derives every hash from the content, and reports the
 * first place the two disagree. Trusting the stored digest would prove
 * nothing: whoever can edit a row can edit its hash too.
 *
 * Exit status is the machine-readable answer — 0 intact, 1 broken or the check
 * could not run — so it works as a scheduled job or a deploy gate without
 * anyone parsing prose.
 */

const USAGE = `
Usage:
  verify-chain [options]

Options:
  --from <sequence>        First entry to verify (default: 1, the whole chain)
  --to <sequence>          Last entry to verify (default: the chain head)
  --organization <id>      Report how many verified entries belong to this organization
  --batch-size <n>         Entries per query, 1-5000 (default: 500)
  --check-anchors          Confirm anchored ranges against the public ledger
  --limit-anchors <n>      Receipts to consult with --check-anchors (default: 20)

Environment:
  DATABASE_URL             Postgres connection string. Required.
  STELLAR_NETWORK          "testnet" (default) or "public". Only for --check-anchors.

Checking anchors needs no secret key: it only reads public ledger data, which is
what makes it independently checkable by someone with no access to this system.
`.trim();

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function parseNumber(flag: string, value: string | undefined): number {
  if (value === undefined) fail(`Missing value for ${flag}.\n\n${USAGE}`);

  const parsed = Number(value);
  if (!Number.isInteger(parsed)) fail(`${flag} expects an integer, received "${value}".`);
  return parsed;
}

interface CliOptions {
  readonly checkAnchors: boolean;
  readonly fromSequence?: number;
  readonly toSequence?: number;
  readonly organizationId?: string;
  readonly batchSize?: number;
  readonly maxAnchorChecks?: number;
}

function parseArgs(argv: readonly string[]): CliOptions {
  const options: { -readonly [K in keyof CliOptions]: CliOptions[K] } = { checkAnchors: false };

  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];

    switch (flag) {
      case "--from":
        options.fromSequence = parseNumber("--from", value);
        index += 1;
        break;
      case "--to":
        options.toSequence = parseNumber("--to", value);
        index += 1;
        break;
      case "--organization":
        if (value === undefined) fail("Missing value for --organization.");
        options.organizationId = value;
        index += 1;
        break;
      case "--batch-size":
        options.batchSize = parseNumber("--batch-size", value);
        index += 1;
        break;
      case "--limit-anchors":
        options.maxAnchorChecks = parseNumber("--limit-anchors", value);
        index += 1;
        break;
      case "--check-anchors":
        options.checkAnchors = true;
        break;
      default:
        fail(`Unknown option "${String(flag)}".\n\n${USAGE}`);
    }
  }

  return options;
}

function describe(value: boolean | undefined): string {
  if (value === undefined) return "unchecked";
  return value ? "matches" : "MISMATCH";
}

/**
 * A receipt disagreeing with either side is a failure even when the chain
 * verified: a locally consistent log that no longer matches what was published
 * to a public ledger is precisely the tampering this exists to catch.
 *
 * `undefined` — the sequence sat outside the verified range — is not a failure,
 * since nothing was recomputed to compare against.
 */
function anchorsAgree(checks: readonly { matchesDatabaseChain: boolean | undefined }[]): boolean {
  return checks.every((check) => check.matchesDatabaseChain !== false);
}

function buildVerifier(): AnchorVerifierPort {
  const network = process.env["STELLAR_NETWORK"] === "public" ? "public" : "testnet";

  // A throwaway keypair. `verify` reads public ledger data and signs nothing,
  // so verification asks for no credentials — the same reasoning as the
  // anchoring CLI's verify path, and the reason an external auditor can run
  // this check without being handed anything.
  return new StellarHashAnchor({ secretKey: Keypair.random().secret(), network });
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));

  const databaseUrl = process.env["DATABASE_URL"];
  if (databaseUrl === undefined || databaseUrl === "") {
    fail("DATABASE_URL must be set to verify the audit chain.");
  }

  const prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });

  const verify = new VerifyAuditChain(
    new PrismaAuditLogRepository(prisma.auditLogEntry),
    options.checkAnchors
      ? new PrismaAnchorRecordRepository(prisma.anchorRecord, randomUUID)
      : undefined,
    options.checkAnchors ? buildVerifier() : undefined,
  );

  const result = await verify.execute({
    ...(options.fromSequence === undefined ? {} : { fromSequence: options.fromSequence }),
    ...(options.toSequence === undefined ? {} : { toSequence: options.toSequence }),
    ...(options.organizationId === undefined ? {} : { organizationId: options.organizationId }),
    ...(options.batchSize === undefined ? {} : { batchSize: options.batchSize }),
    ...(options.maxAnchorChecks === undefined ? {} : { maxAnchorChecks: options.maxAnchorChecks }),
    checkAnchors: options.checkAnchors,
  });

  await prisma.$disconnect();

  if (Result.isErr(result)) fail(`Verification could not run: ${result.error.message}`);

  const value = result.value;
  const lines = [
    `chain verification: ${value.valid ? "INTACT" : "BROKEN"}`,
    `  range:     ${String(value.fromSequence)}-${String(value.toSequence ?? "empty")}`,
    `  entries:   ${String(value.checkedEntries)} checked`,
  ];

  if (value.organizationId !== undefined) {
    lines.push(
      `  org:       ${value.organizationId} (${String(value.organizationEntryCount)} entries in range)`,
    );
  }
  if (value.headHash !== undefined) lines.push(`  head hash: ${value.headHash}`);
  if (value.seededFromWindowStart) {
    lines.push("  note:      started mid-chain; breaks earlier in the log are outside this run");
  }
  if (value.firstBreak !== undefined) {
    lines.push(
      `  first break at sequence ${String(value.firstBreak.sequence)}: ${value.firstBreak.reason}`,
    );
  }

  for (const check of value.anchorChecks) {
    lines.push(
      `  anchor @${String(check.sequence)} (${check.network} ${check.anchorRef}): ` +
        `database ${describe(check.matchesDatabaseChain)}, ledger ${describe(check.matchesLedger)}` +
        (check.ledgerError === undefined ? "" : ` — ${check.ledgerError}`),
    );
  }
  if (value.anchorsSkipped) {
    lines.push("  anchors:   --check-anchors requested but no ledger is configured");
  }

  for (const line of lines) process.stdout.write(`${line}\n`);

  process.exit(value.valid && anchorsAgree(value.anchorChecks) ? 0 : 1);
}

main().catch((error: unknown) => {
  fail(error instanceof Error ? error.message : String(error));
});
