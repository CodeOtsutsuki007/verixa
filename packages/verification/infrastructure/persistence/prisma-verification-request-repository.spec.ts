import { randomUUID } from "node:crypto";
import { createConnection } from "node:net";

import { PrismaClient } from "@verixa/database";
import { asId, Result } from "@verixa/shared-kernel";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { VerificationRequest } from "../../domain/entities/verification-request.js";
import { VerificationType } from "../../domain/value-objects/verification-type.js";
import {
  verificationRequestRepositoryContract,
  type VerificationRequestContractContext,
} from "../testing/contracts/verification-request-repository.contract.js";

import { PrismaVerificationRequestRepository } from "./prisma-verification-request-repository.js";

/**
 * Database-backed tests skip when no Postgres is reachable, so a fresh clone
 * without Docker still gets a green `pnpm test`; `TEST_DATABASE_URL` points at
 * one that is already running. Mirrors `@verixa/mfa`'s harness.
 */
async function databaseUrl(): Promise<string | undefined> {
  const configured = process.env["TEST_DATABASE_URL"];
  if (configured === undefined) return undefined;

  const url = new URL(configured);
  const reachable = await new Promise<boolean>((resolve) => {
    const socket = createConnection({ host: url.hostname, port: Number(url.port || 5432) });
    const finish = (result: boolean): void => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(result);
    };
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.setTimeout(2_000, () => finish(false));
  });

  return reachable ? configured : undefined;
}

const database = await databaseUrl();

describe.skipIf(database === undefined)(
  "PrismaVerificationRequestRepository (real Postgres)",
  () => {
    let prisma: PrismaClient;

    beforeAll(async () => {
      prisma = new PrismaClient({ datasources: { db: { url: database as string } } });
      await prisma.$connect();
    }, 60_000);

    afterAll(async () => {
      await prisma.$disconnect();
    }, 60_000);

    afterEach(async () => {
      // Contracts assume they start from an empty store. Order matters:
      // verification_requests cascade from both, but organizations.owner_id is
      // ON DELETE RESTRICT, so organizations must go before their users.
      await prisma.verificationRequest.deleteMany({});
      await prisma.organization.deleteMany({});
      await prisma.user.deleteMany({});
    });

    async function createContext(): Promise<VerificationRequestContractContext> {
      const now = new Date();
      const subjectUserId = randomUUID();
      const otherSubjectUserId = randomUUID();

      await prisma.user.createMany({
        data: [subjectUserId, otherSubjectUserId].map((id) => ({
          id,
          email: `verification-${id}@example.com`,
          displayName: "Verification Test Subject",
          status: "active" as const,
          createdAt: now,
          updatedAt: now,
        })),
      });

      const organizationId = randomUUID();
      await prisma.organization.create({
        data: {
          id: organizationId,
          name: "Verification Test Org",
          slug: `verification-${organizationId}`,
          ownerId: subjectUserId,
          status: "active",
          createdAt: now,
          updatedAt: now,
        },
      });

      return {
        subjectUserId: subjectUserId as VerificationRequestContractContext["subjectUserId"],
        otherSubjectUserId:
          otherSubjectUserId as VerificationRequestContractContext["otherSubjectUserId"],
        organizationId: organizationId as VerificationRequestContractContext["organizationId"],
      };
    }

    function inReview(context: VerificationRequestContractContext): VerificationRequest {
      const created = VerificationRequest.request({
        subjectUserId: context.subjectUserId,
        organizationId: context.organizationId,
        type: VerificationType.reconstitute("identity-document"),
      });
      const submitted = created.submit();
      if (Result.isErr(submitted)) throw new Error("fixture setup failed");
      const reviewing = submitted.value.startReview();
      if (Result.isErr(reviewing)) throw new Error("fixture setup failed");
      return reviewing.value;
    }

    verificationRequestRepositoryContract(
      () => new PrismaVerificationRequestRepository(prisma),
      createContext,
    );

    describe("race safety the fake can only simulate", () => {
      it("hands a single case to exactly one of two concurrent reviewers", async () => {
        const repository = new PrismaVerificationRequestRepository(prisma);
        const context = await createContext();
        await repository.save(inReview(context));

        const now = new Date();
        const [first, second] = await Promise.all([
          repository.claimNextInReview({
            reviewerId: asId<"ReviewerId">(randomUUID()),
            now,
            claimTtlMs: 60_000,
            oneAtATime: true,
          }),
          repository.claimNextInReview({
            reviewerId: asId<"ReviewerId">(randomUUID()),
            now,
            claimTtlMs: 60_000,
            oneAtATime: true,
          }),
        ]);

        // This is the assertion `FOR UPDATE SKIP LOCKED` exists for. Without the
        // lock, both transactions read the same unclaimed row and both commit a
        // claim — and the loser's claim silently overwrites the winner's.
        const claimed = [first, second].filter((outcome) => outcome.kind === "claimed");
        expect(claimed).toHaveLength(1);
      });
    });
  },
);
