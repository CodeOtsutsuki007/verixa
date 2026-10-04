import { asId, Result } from "@verixa/shared-kernel";
import Fastify from "fastify";
import supertest from "supertest";
import { beforeEach, describe, expect, it } from "vitest";

import { PermissionChecker } from "../../application/services/permission-checker.js";
import { Role } from "../../domain/entities/role.js";
import { UserRoleAssignment } from "../../domain/entities/user-role-assignment.js";
import { InMemoryRoleRepository } from "../../infrastructure/fakes/in-memory-role-repository.js";
import { InMemoryUserRoleAssignmentRepository } from "../../infrastructure/fakes/in-memory-user-role-assignment-repository.js";

import {
  type AuthenticatedPrincipal,
  requireAllPermissions,
  requireAnyPermission,
  requirePermission,
} from "./require-permission.js";

declare module "fastify" {
  interface FastifyRequest {
    principal?: AuthenticatedPrincipal;
  }
}

interface ForbiddenErrorBody {
  error: {
    code: string;
    message: string;
  };
}

describe("requirePermission Fastify route guards", () => {
  let roleRepository: InMemoryRoleRepository;
  let userRoleAssignmentRepository: InMemoryUserRoleAssignmentRepository;
  let checker: PermissionChecker;

  const userAlice = asId<"UserId">("usr_alice");
  const userBob = asId<"UserId">("usr_bob");
  const orgAlpha = asId<"OrgId">("org_alpha");
  const orgBeta = asId<"OrgId">("org_beta");

  beforeEach(async () => {
    roleRepository = new InMemoryRoleRepository();
    userRoleAssignmentRepository = new InMemoryUserRoleAssignmentRepository();
    checker = new PermissionChecker(userRoleAssignmentRepository, roleRepository);

    // Create roles
    const editorRole = Role.create({
      name: "editor",
      orgId: orgAlpha,
      permissions: ["articles:read", "articles:write"],
    });
    if (!Result.isOk(editorRole)) throw new Error("setup error");
    await roleRepository.save(editorRole.value);

    const billingRole = Role.create({
      name: "billing-manager",
      orgId: orgAlpha,
      permissions: ["billing:manage"],
    });
    if (!Result.isOk(billingRole)) throw new Error("setup error");
    await roleRepository.save(billingRole.value);

    // Assign Alice editor role in orgAlpha
    const aliceAssignment = UserRoleAssignment.create({
      userId: userAlice,
      roleId: editorRole.value.id,
      orgId: orgAlpha,
      assignedBy: userAlice,
    });
    if (!Result.isOk(aliceAssignment)) throw new Error("setup error");
    await userRoleAssignmentRepository.save(aliceAssignment.value);
  });

  function createApp(attachPrincipal?: AuthenticatedPrincipal) {
    const app = Fastify();

    // Mock authentication middleware populating request.principal
    app.addHook(
      "preHandler",
      (request: Fastify.FastifyRequest, _reply: Fastify.FastifyReply, done: () => void) => {
        if (attachPrincipal) {
          request.principal = attachPrincipal;
        }
        done();
      },
    );

    app.get("/articles", { preHandler: [requirePermission(checker, "articles:read")] }, () => {
      return { data: "articles-list" };
    });

    app.post("/articles", { preHandler: [requirePermission(checker, "articles:write")] }, () => {
      return { created: true };
    });

    app.get(
      "/dashboard",
      {
        preHandler: [requireAnyPermission(checker, ["articles:read", "billing:manage"])],
      },
      () => {
        return { dashboard: "ok" };
      },
    );

    app.get(
      "/admin/full",
      {
        preHandler: [requireAllPermissions(checker, ["articles:write", "billing:manage"])],
      },
      () => {
        return { admin: "ok" };
      },
    );

    return app;
  }

  it("allows authorized requests to proceed to the handler", async () => {
    const app = createApp({ userId: userAlice, orgId: orgAlpha });
    await app.ready();

    const res = await supertest(app.server).get("/articles");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ data: "articles-list" });

    await app.close();
  });

  it("rejects unauthorized requests with 403 without leaking permission name", async () => {
    const app = createApp({ userId: userAlice, orgId: orgAlpha });
    await app.ready();

    // Alice does not have billing:manage
    const res = await supertest(app.server).get("/admin/full");
    expect(res.status).toBe(403);
    expect(res.body).toEqual({
      error: {
        code: "FORBIDDEN",
        message: "You do not have permission to perform this action.",
      },
    });

    // Ensure no leakage in error message
    expect(JSON.stringify(res.body)).not.toContain("billing:manage");
    expect(JSON.stringify(res.body)).not.toContain("articles:write");

    await app.close();
  });

  it("rejects requests from users with wrong org scope", async () => {
    // Alice in orgBeta
    const app = createApp({ userId: userAlice, orgId: orgBeta });
    await app.ready();

    const res = await supertest(app.server).get("/articles");
    expect(res.status).toBe(403);
    const body = res.body as ForbiddenErrorBody;
    expect(body.error.code).toBe("FORBIDDEN");

    await app.close();
  });

  it("rejects unauthenticated requests where principal is missing", async () => {
    const app = createApp(undefined);
    await app.ready();

    const res = await supertest(app.server).get("/articles");
    expect(res.status).toBe(403);
    const body = res.body as ForbiddenErrorBody;
    expect(body.error.code).toBe("FORBIDDEN");

    await app.close();
  });

  it("handles requireAnyPermission correctly", async () => {
    const app = createApp({ userId: userAlice, orgId: orgAlpha });
    await app.ready();

    const res = await supertest(app.server).get("/dashboard");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ dashboard: "ok" });

    await app.close();
  });

  it("rejects requireAnyPermission if user has none of the permissions", async () => {
    const app = createApp({ userId: userBob, orgId: orgAlpha });
    await app.ready();

    const res = await supertest(app.server).get("/dashboard");
    expect(res.status).toBe(403);

    await app.close();
  });
});
