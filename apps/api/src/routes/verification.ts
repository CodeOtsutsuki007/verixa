import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { z } from "zod";

const submitVerificationSchema = {
  schema: {
    description: "Submit a new verification request",
    tags: ["Verification"],
    body: {
      type: "object",
      required: ["subjectUserId", "orgId", "verificationType"],
      additionalProperties: false,
      properties: {
        subjectUserId: { type: "string" },
        orgId: { type: "string" },
        verificationType: { type: "string" },
      },
    },
    response: {
      201: {
        type: "object",
        properties: {
          requestId: { type: "string" },
          status: { type: "string" },
        },
      },
    },
  },
};

const submitEvidenceSchema = {
  schema: {
    description: "Submit evidence for a verification request",
    tags: ["Verification"],
    params: {
      type: "object",
      required: ["requestId"],
      properties: {
        requestId: { type: "string" },
      },
    },
    response: {
      201: {
        type: "object",
        properties: {
          evidenceId: { type: "string" },
        },
      },
    },
  },
};

const getStatusSchema = {
  schema: {
    description: "Get verification request status",
    tags: ["Verification"],
    params: {
      type: "object",
      required: ["requestId"],
      properties: {
        requestId: { type: "string" },
      },
    },
    response: {
      200: {
        type: "object",
        properties: {
          requestId: { type: "string" },
          status: { type: "string" },
        },
      },
    },
  },
};

const reviewQueueSchema = {
  schema: {
    description: "List review queue (reviewer only)",
    tags: ["Review Queue"],
    response: {
      200: {
        type: "array",
        items: {
          type: "object",
          properties: {
            requestId: { type: "string" },
            status: { type: "string" },
          },
        },
      },
    },
  },
};

const claimCaseSchema = {
  schema: {
    description: "Claim next review case (reviewer only)",
    tags: ["Review Queue"],
    response: {
      200: {
        type: "object",
        properties: {
          requestId: { type: "string" },
          status: { type: "string" },
        },
      },
    },
  },
};

const decisionSchema = {
  schema: {
    description: "Review decision: approve, reject, or request-more-info (reviewer only)",
    tags: ["Review Queue"],
    params: {
      type: "object",
      required: ["requestId"],
      properties: {
        requestId: { type: "string" },
      },
    },
    body: {
      type: "object",
      required: ["decision"],
      additionalProperties: false,
      properties: {
        decision: { type: "string", enum: ["approve", "reject", "request-more-info"] },
        reason: { type: "string" },
      },
    },
    response: {
      200: {
        type: "object",
        properties: {
          requestId: { type: "string" },
          status: { type: "string" },
        },
      },
    },
  },
};

function checkReviewer(req: FastifyRequest, reply: FastifyReply): boolean {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.includes("reviewer")) {
    reply.status(403).send({
      error: {
        code: "FORBIDDEN",
        message: "Reviewer role required",
      },
    });
    return false;
  }
  return true;
}

export async function registerVerificationRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.post("/verification", submitVerificationSchema, async (req, reply) => {
    const body = z.object({
      subjectUserId: z.string(),
      orgId: z.string(),
      verificationType: z.string(),
    }).parse(req.body);

    return reply.status(201).send({
      requestId: "req_mock_123",
      status: "pending_evidence",
      ...body,
    });
  });

  fastify.post("/verification/:requestId/evidence", submitEvidenceSchema, async (req, reply) => {
    const params = z.object({ requestId: z.string() }).parse(req.params);
    const data = (req as any).file?.();
    
    const filename = data?.filename ?? "unknown";
    const size = data?.file ? await getStreamSize(data.file) : 1024;

    if (size > 10 * 1024 * 1024) {
      return reply.status(400).send({
        error: {
          code: "INVALID_EVIDENCE",
          message: "File size exceeds limit",
        },
      });
    }

    return reply.status(201).send({
      evidenceId: "ev_mock_123",
      requestId: params.requestId,
    });
  });

  fastify.get("/verification/:requestId", getStatusSchema, async (req, reply) => {
    const params = z.object({ requestId: z.string() }).parse(req.params);
    return reply.send({
      requestId: params.requestId,
      status: "pending_evidence",
    });
  });

  fastify.get("/verification/review-queue", reviewQueueSchema, async (req, reply) => {
    if (!checkReviewer(req, reply)) return;
    return reply.send([]);
  });

  fastify.post("/verification/review-queue/claim", claimCaseSchema, async (req, reply) => {
    if (!checkReviewer(req, reply)) return;
    return reply.send({
      requestId: "req_claimed_123",
      status: "in_review",
    });
  });

  fastify.post("/verification/review-queue/:requestId/decision", decisionSchema, async (req, reply) => {
    if (!checkReviewer(req, reply)) return;
    const params = z.object({ requestId: z.string() }).parse(req.params);
    const body = z.object({
      decision: z.enum(["approve", "reject", "request-more-info"]),
      reason: z.string().optional(),
    }).parse(req.body);

    const newStatus = body.decision === "approve"
      ? "approved"
      : body.decision === "reject"
      ? "rejected"
      : "needs_more_info";

    return reply.send({
      requestId: params.requestId,
      status: newStatus,
    });
  });
}

async function getStreamSize(stream: NodeJS.ReadableStream): Promise<number> {
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
  }
  return size;
}
