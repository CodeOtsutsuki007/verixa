import { buildContainer, type Container } from "@verixa/api/composition-root";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createTestPrismaClient, databaseAvailability } from "./helpers/database.js";
import { createHttpTestClient, type HttpTestClient } from "./helpers/http-client.js";

const available = await databaseAvailability();

describe.skipIf(!available)("Verification and Review Queue HTTP API", () => {
  const prisma = createTestPrismaClient();
  let container: Container;
  let client: HttpTestClient;

  beforeAll(async () => {
    container = buildContainer(prisma);
    client = await createHttpTestClient(container);
  }, 60_000);

  afterAll(async () => {
    await client.close();
    await prisma.$disconnect();
  }, 60_000);

  it("submits verification request successfully", async () => {
    const response = await client.request.post("/verification").send({
      subjectUserId: "user_123",
      orgId: "org_123",
      verificationType: "identity-document",
    });
    expect(response.status).toBe(201);
    expect(response.body).toMatchObject({
      status: "pending_evidence",
    });
  });

  it("rejects non-reviewer caller on queue with 403", async () => {
    const response = await client.request.get("/verification/review-queue");
    expect(response.status).toBe(403);
  });

  it("allows reviewer caller on queue", async () => {
    const response = await client.request
      .get("/verification/review-queue")
      .set("Authorization", "Bearer reviewer-token");
    expect(response.status).toBe(200);
    expect(Array.isArray(response.body)).toBe(true);
  });

  it("allows reviewer to make a decision", async () => {
    const response = await client.request
      .post("/verification/review-queue/req_123/decision")
      .set("Authorization", "Bearer reviewer-token")
      .send({ decision: "approve" });
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      status: "approved",
    });
  });
});
