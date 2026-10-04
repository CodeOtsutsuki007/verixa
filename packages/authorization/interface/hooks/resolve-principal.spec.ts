import { asId } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Permission } from "../../domain/value-objects/permission.js";
import type {
  AuthenticatedPrincipal,
  RequestWithPrincipal,
} from "../guards/require-permission.js";
import {
  requireAllPermissions,
  requireAnyPermission,
  requirePermission,
} from "../guards/require-permission.js";

import { createResolvePrincipalHook, type PermissionResolverLike } from "./resolve-principal.js";

describe("createResolvePrincipalHook", () => {
  let mockChecker: PermissionResolverLike;
  let resolveEffectivePermissionsSpy: ReturnType<typeof vi.fn>;

  const userId = asId<"UserId">("user_123");
  const orgId = asId<"OrgId">("org_456");

  beforeEach(() => {
    resolveEffectivePermissionsSpy = vi
      .fn()
      .mockResolvedValue(new Set([Permission.from("users:read"), Permission.from("orgs:*")]));
    mockChecker = {
      resolveEffectivePermissions: resolveEffectivePermissionsSpy,
    };
  });

  it("populates request.principal.permissions exactly once per request", async () => {
    const hook = createResolvePrincipalHook(mockChecker);
    const principal: AuthenticatedPrincipal = {
      userId,
      orgId,
    };
    const request: RequestWithPrincipal = {
      principal,
    };

    // First execution: populates permissions
    await hook(request);
    expect(resolveEffectivePermissionsSpy).toHaveBeenCalledTimes(1);
    expect(resolveEffectivePermissionsSpy).toHaveBeenCalledWith(userId, orgId);
    expect(principal.permissions).toBeInstanceOf(Set);
    expect(principal.permissions?.has("users:read")).toBe(true);
    expect(principal.permissions?.has("orgs:*")).toBe(true);

    // Second execution on same request: uses cached memoized Set
    await hook(request);
    expect(resolveEffectivePermissionsSpy).toHaveBeenCalledTimes(1);
  });

  it("does not throw or populate permissions on unauthenticated requests", async () => {
    const hook = createResolvePrincipalHook(mockChecker);
    const emptyRequest = {};

    await expect(hook(emptyRequest)).resolves.not.toThrow();
    expect(resolveEffectivePermissionsSpy).not.toHaveBeenCalled();

    const requestWithEmptyPrincipal = { principal: undefined };
    await expect(hook(requestWithEmptyPrincipal)).resolves.not.toThrow();
    expect(resolveEffectivePermissionsSpy).not.toHaveBeenCalled();
  });

  it("respects custom orgIdResolver", async () => {
    const customOrgId = asId<"OrgId">("org_custom");
    const hook = createResolvePrincipalHook(mockChecker, {
      orgIdResolver: () => customOrgId,
    });
    const request = {
      principal: {
        userId,
        orgId,
      },
    };

    await hook(request);
    expect(resolveEffectivePermissionsSpy).toHaveBeenCalledWith(userId, customOrgId);
  });

  it("integrates seamlessly with requirePermission guard using cached permissions", async () => {
    const hook = createResolvePrincipalHook(mockChecker);
    const dummyChecker = {
      hasPermission: vi.fn(),
      hasAnyPermission: vi.fn(),
      hasAllPermissions: vi.fn(),
    };

    const guard = requirePermission(dummyChecker, "users:read");
    const wildcardGuard = requirePermission(dummyChecker, "orgs:write");
    const deniedGuard = requirePermission(dummyChecker, "secrets:read");

    const request = {
      principal: {
        userId,
        orgId,
      },
    };

    const reply = {
      status: vi.fn().mockReturnThis(),
      send: vi.fn(),
    };

    // Run resolution hook
    await hook(request);
    expect(resolveEffectivePermissionsSpy).toHaveBeenCalledTimes(1);

    // Run first guard
    await guard(request, reply);
    expect(reply.status).not.toHaveBeenCalled();
    expect(dummyChecker.hasPermission).not.toHaveBeenCalled(); // Cached!

    // Run wildcard guard
    await wildcardGuard(request, reply);
    expect(reply.status).not.toHaveBeenCalled();
    expect(dummyChecker.hasPermission).not.toHaveBeenCalled(); // Cached!

    // Run denied guard
    await deniedGuard(request, reply);
    expect(reply.status).toHaveBeenCalledWith(403);
    expect(dummyChecker.hasPermission).not.toHaveBeenCalled();
  });

  it("integrates with requireAnyPermission and requireAllPermissions using cached permissions", async () => {
    const hook = createResolvePrincipalHook(mockChecker);
    const dummyChecker = {
      hasPermission: vi.fn(),
      hasAnyPermission: vi.fn(),
      hasAllPermissions: vi.fn(),
    };

    const anyGuard = requireAnyPermission(dummyChecker, ["users:read", "billing:read"]);
    const allGuard = requireAllPermissions(dummyChecker, ["users:read", "orgs:delete"]);

    const request = {
      principal: {
        userId,
        orgId,
      },
    };

    const reply = {
      status: vi.fn().mockReturnThis(),
      send: vi.fn(),
    };

    await hook(request);

    await anyGuard(request, reply);
    expect(reply.status).not.toHaveBeenCalled();

    await allGuard(request, reply);
    expect(reply.status).not.toHaveBeenCalled();

    expect(dummyChecker.hasAnyPermission).not.toHaveBeenCalled();
    expect(dummyChecker.hasAllPermissions).not.toHaveBeenCalled();
  });
});
