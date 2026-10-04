import { randomUUID } from "node:crypto";

import type { PrismaClient } from "@prisma/client";

export const DEFAULT_PERMISSIONS = [
  ["users:read", "View users"],
  ["users:write", "Create and update users"],
  ["roles:read", "View roles and permissions"],
  ["roles:write", "Create and manage roles"],
  ["orgs:read", "View organizations"],
  ["orgs:write", "Manage organizations"],
  ["*:*", "Unrestricted platform administration"],
] as const;

export const DEFAULT_ROLES = [
  { name: "super-admin", description: "Platform administrator", permissions: ["*:*"] },
  {
    name: "org-owner",
    description: "Organization owner",
    permissions: [
      "users:read",
      "users:write",
      "roles:read",
      "roles:write",
      "orgs:read",
      "orgs:write",
    ],
  },
  { name: "member", description: "Organization member", permissions: ["users:read", "orgs:read"] },
  {
    name: "viewer",
    description: "Read-only organization viewer",
    permissions: ["users:read", "orgs:read", "roles:read"],
  },
] as const;

/** Idempotently installs the platform catalog and protected global roles. */
export async function seedDefaultRoles(prisma: PrismaClient): Promise<void> {
  const now = new Date("2026-01-01T00:00:00.000Z");
  const permissions = new Map<string, string>();
  for (const [key, description] of DEFAULT_PERMISSIONS) {
    const permission = await prisma.permission.upsert({
      where: { key },
      create: { id: randomUUID(), key, description, createdAt: now },
      update: { description },
    });
    permissions.set(key, permission.id);
  }
  for (const definition of DEFAULT_ROLES) {
    const role = await prisma.role.upsert({
      where: { name: definition.name },
      create: {
        id: randomUUID(),
        name: definition.name,
        description: definition.description,
        isSystemRole: true,
        createdAt: now,
        updatedAt: now,
      },
      update: { description: definition.description, isSystemRole: true, updatedAt: now },
    });
    for (const key of definition.permissions) {
      const permissionId = permissions.get(key);
      if (permissionId === undefined) throw new Error(`Missing seeded permission ${key}`);
      await prisma.rolePermission.upsert({
        where: { roleId_permissionId: { roleId: role.id, permissionId } },
        create: { roleId: role.id, permissionId },
        update: {},
      });
    }
  }
}
