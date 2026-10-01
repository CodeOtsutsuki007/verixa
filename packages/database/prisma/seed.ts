import { randomUUID } from "node:crypto";

import { PrismaClient } from "@prisma/client";

const DEFAULT_PERMISSIONS = [
  ["users:read", "View users"],
  ["users:write", "Create and update users"],
  ["roles:read", "View roles and permissions"],
  ["roles:write", "Create and manage roles"],
  ["orgs:read", "View organizations"],
  ["orgs:write", "Manage organizations"],
  ["*:*", "Unrestricted platform administration"],
] as const;
const DEFAULT_ROLES = [
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

async function seedDefaultRoles(prisma: PrismaClient): Promise<void> {
  const now = new Date("2026-01-01T00:00:00.000Z");
  const permissionIds = new Map<string, string>();
  for (const [key, description] of DEFAULT_PERMISSIONS) {
    const row = await prisma.permission.upsert({
      where: { key },
      create: { id: randomUUID(), key, description, createdAt: now },
      update: { description },
    });
    permissionIds.set(key, row.id);
  }
  for (const definition of DEFAULT_ROLES) {
    const existing = await prisma.role.findFirst({
      where: { organizationId: null, name: definition.name },
    });
    const role =
      existing === null
        ? await prisma.role.create({
            data: {
              id: randomUUID(),
              name: definition.name,
              description: definition.description,
              isSystemRole: true,
              organizationId: null,
              createdAt: now,
              updatedAt: now,
            },
          })
        : await prisma.role.update({
            where: { id: existing.id },
            data: { description: definition.description, isSystemRole: true, updatedAt: now },
          });
    for (const key of definition.permissions) {
      const permissionId = permissionIds.get(key);
      if (permissionId === undefined) throw new Error(`Missing seeded permission ${key}`);
      await prisma.rolePermission.upsert({
        where: { roleId_permissionId: { roleId: role.id, permissionId } },
        create: { roleId: role.id, permissionId },
        update: {},
      });
    }
  }
}

/**
 * Deterministic development fixtures.
 *
 * Run with `pnpm db:seed`. Safe to run repeatedly: every record is upserted
 * against a fixed id, so a second run updates rather than duplicating. That
 * property is not a nicety — a seed you're afraid to re-run becomes a seed
 * nobody runs, and the fixtures drift out of sync with the schema until they
 * no longer work at all.
 *
 * ## This data is for local development only
 *
 * Every value here is obviously, deliberately fake: `@example.com` addresses
 * (an IANA-reserved domain that can never receive mail), names that read as
 * placeholders, and no secrets of any kind.
 *
 * That last part matters more than it looks. Seed files are copied,
 * committed, pasted into issues, and screenshotted in tutorials — so anything
 * in one should be worthless if disclosed. The failure mode isn't a leaked
 * seed password; it's that a realistic-looking one teaches the wrong habit
 * and eventually gets pasted somewhere real, or that a deployment
 * accidentally seeds a staging box with credentials someone then relies on.
 * Nothing here should ever be usable as a credential.
 *
 * There are no passwords yet because credentials arrive in Phase 04. When
 * they do, seeded accounts must use passwords that are clearly fake and
 * documented as unusable outside local development — never something that
 * looks like a real one.
 */

const prisma = new PrismaClient();

/**
 * Fixed ids, not random ones.
 *
 * Deterministic ids are what make the seed idempotent, and they also make
 * fixtures referenceable: a contributor debugging locally can point at
 * `00000000-0000-4000-8000-000000000001` and know exactly which user that is,
 * across resets and across machines. Random ids would change every run and be
 * useless in a bug report.
 *
 * The `4` and `8` in the third and fourth groups keep these valid UUIDv4s, so
 * anything that validates the format still accepts them.
 */
const IDS = {
  alice: "00000000-0000-4000-8000-000000000001",
  bob: "00000000-0000-4000-8000-000000000002",
  carol: "00000000-0000-4000-8000-000000000003",
  acme: "00000000-0000-4000-8000-00000000000a",
  globex: "00000000-0000-4000-8000-00000000000b",
  aliceAcme: "00000000-0000-4000-8000-000000000101",
  bobAcme: "00000000-0000-4000-8000-000000000102",
  bobGlobex: "00000000-0000-4000-8000-000000000103",
  carolGlobex: "00000000-0000-4000-8000-000000000104",
} as const;

// A fixed timestamp, for the same reason as fixed ids: a seed that writes
// `new Date()` produces a different database on every run, which makes
// "did my change affect this?" harder to answer than it needs to be.
const SEEDED_AT = new Date("2026-01-01T00:00:00.000Z");

async function seed(): Promise<void> {
  const users = [
    {
      id: IDS.alice,
      email: "alice@example.com",
      displayName: "Alice Ashworth",
      givenName: "Alice",
      familyName: "Ashworth",
      status: "active" as const,
    },
    {
      id: IDS.bob,
      email: "bob@example.com",
      displayName: "Bob Barker",
      givenName: "Bob",
      familyName: "Barker",
      status: "active" as const,
    },
    // Deliberately still pending: exercising a non-active status locally
    // catches "we only ever tested the happy path" bugs before review does.
    {
      id: IDS.carol,
      email: "carol@example.com",
      displayName: "Carol Chen",
      givenName: null,
      familyName: null,
      status: "pending" as const,
    },
  ];

  for (const user of users) {
    const { id, ...fields } = user;
    await prisma.user.upsert({
      where: { id },
      create: { id, ...fields, createdAt: SEEDED_AT, updatedAt: SEEDED_AT },
      update: { ...fields, updatedAt: SEEDED_AT },
    });
  }

  const organizations = [
    { id: IDS.acme, name: "Acme Inc", slug: "acme", ownerId: IDS.alice, status: "active" as const },
    {
      id: IDS.globex,
      name: "Globex Corporation",
      slug: "globex",
      ownerId: IDS.bob,
      status: "active" as const,
    },
  ];

  for (const organization of organizations) {
    const { id, ...fields } = organization;
    await prisma.organization.upsert({
      where: { id },
      create: { id, ...fields, createdAt: SEEDED_AT, updatedAt: SEEDED_AT },
      update: { ...fields, updatedAt: SEEDED_AT },
    });
  }

  // Bob belongs to both organizations on purpose. A user spanning tenants is
  // the case that breaks naive multi-tenancy assumptions, and ADR-0002 chose
  // row-level isolation partly because it handles this without contortion —
  // so the seed should make it the default thing a contributor sees, not an
  // edge case they have to construct by hand.
  const memberships = [
    { id: IDS.aliceAcme, userId: IDS.alice, organizationId: IDS.acme, status: "active" as const },
    { id: IDS.bobAcme, userId: IDS.bob, organizationId: IDS.acme, status: "active" as const },
    { id: IDS.bobGlobex, userId: IDS.bob, organizationId: IDS.globex, status: "active" as const },
    // A revoked membership, so the partial unique index and the "revoked
    // doesn't block rejoining" rule are both visible in real data.
    {
      id: IDS.carolGlobex,
      userId: IDS.carol,
      organizationId: IDS.globex,
      status: "revoked" as const,
    },
  ];

  for (const membership of memberships) {
    const { id, ...fields } = membership;
    await prisma.organizationMembership.upsert({
      where: { id },
      create: { id, ...fields, joinedAt: SEEDED_AT },
      update: fields,
    });
  }

  await seedDefaultRoles(prisma);

  // Invitations are deliberately not seeded. An invitation is only meaningful
  // alongside the raw token that was mailed to its recipient, and that token
  // is unrecoverable by design (see docs/security/token-storage.md) — a
  // seeded invitation would be a row nobody can ever accept. Worse, seeding a
  // *known* token would put a working bearer credential in version control,
  // which is exactly what that document says never to do.

  console.log(
    `Seeded ${String(users.length)} users, ${String(organizations.length)} organizations, ` +
      `${String(memberships.length)} memberships and the default authorization catalog.`,
  );
}

seed()
  .catch((error: unknown) => {
    console.error("Seeding failed:", error);
    process.exitCode = 1;
  })
  .finally(() => {
    void prisma.$disconnect();
  });
