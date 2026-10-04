import type { OrgId } from "../../domain/entities/role.js";
import type { UserId } from "../../domain/entities/user-role-assignment.js";
import type { Permission } from "../../domain/value-objects/permission.js";

/**
 * Represents the authenticated principal attached to an incoming HTTP request.
 */
export interface AuthenticatedPrincipal {
  readonly userId: UserId;
  readonly orgId?: OrgId | null | undefined;
}

/**
 * Minimal request interface required by permission guards.
 */
export interface RequestWithPrincipal {
  readonly principal?: AuthenticatedPrincipal | undefined;
  readonly params?: unknown;
  readonly query?: unknown;
  readonly headers?: unknown;
}

/**
 * Minimal reply interface required by permission guards.
 */
export interface GuardReply {
  status(code: number): GuardReply;
  send(payload: unknown): GuardReply | Promise<unknown>;
}

export type PermissionCheckerLike = {
  hasPermission(
    userId: UserId,
    orgId: OrgId | null,
    permission: Permission | string,
  ): Promise<boolean>;
  hasAnyPermission(
    userId: UserId,
    orgId: OrgId | null,
    permissions: Iterable<Permission | string>,
  ): Promise<boolean>;
  hasAllPermissions(
    userId: UserId,
    orgId: OrgId | null,
    permissions: Iterable<Permission | string>,
  ): Promise<boolean>;
};

export type OrgIdResolver = (request: RequestWithPrincipal) => OrgId | null;

const DEFAULT_FORBIDDEN_BODY = {
  error: {
    code: "FORBIDDEN",
    message: "You do not have permission to perform this action.",
  },
} as const;

/**
 * Returns a Fastify `preHandler` hook enforcing that the authenticated principal
 * possesses the specified permission.
 *
 * Responds with `403 Forbidden` on denial without leaking required permission names.
 */
export function requirePermission(
  checker: PermissionCheckerLike,
  permission: Permission | string,
  orgIdResolver?: OrgIdResolver,
) {
  return async function permissionGuard(request: RequestWithPrincipal, reply: GuardReply) {
    const principal = request.principal;
    if (!principal || !principal.userId) {
      // Unauthenticated or unpopulated principal
      await reply.status(403).send(DEFAULT_FORBIDDEN_BODY);
      return;
    }

    const orgId = orgIdResolver ? orgIdResolver(request) : (principal.orgId ?? null);

    const allowed = await checker.hasPermission(principal.userId, orgId, permission);
    if (!allowed) {
      await reply.status(403).send(DEFAULT_FORBIDDEN_BODY);
      return;
    }
  };
}

/**
 * Returns a Fastify `preHandler` hook enforcing that the authenticated principal
 * possesses at least one of the candidate permissions.
 */
export function requireAnyPermission(
  checker: PermissionCheckerLike,
  permissions: Iterable<Permission | string>,
  orgIdResolver?: OrgIdResolver,
) {
  return async function anyPermissionGuard(request: RequestWithPrincipal, reply: GuardReply) {
    const principal = request.principal;
    if (!principal || !principal.userId) {
      await reply.status(403).send(DEFAULT_FORBIDDEN_BODY);
      return;
    }

    const orgId = orgIdResolver ? orgIdResolver(request) : (principal.orgId ?? null);

    const allowed = await checker.hasAnyPermission(principal.userId, orgId, permissions);
    if (!allowed) {
      await reply.status(403).send(DEFAULT_FORBIDDEN_BODY);
      return;
    }
  };
}

/**
 * Returns a Fastify `preHandler` hook enforcing that the authenticated principal
 * possesses all of the specified permissions.
 */
export function requireAllPermissions(
  checker: PermissionCheckerLike,
  permissions: Iterable<Permission | string>,
  orgIdResolver?: OrgIdResolver,
) {
  return async function allPermissionsGuard(request: RequestWithPrincipal, reply: GuardReply) {
    const principal = request.principal;
    if (!principal || !principal.userId) {
      await reply.status(403).send(DEFAULT_FORBIDDEN_BODY);
      return;
    }

    const orgId = orgIdResolver ? orgIdResolver(request) : (principal.orgId ?? null);

    const allowed = await checker.hasAllPermissions(principal.userId, orgId, permissions);
    if (!allowed) {
      await reply.status(403).send(DEFAULT_FORBIDDEN_BODY);
      return;
    }
  };
}
