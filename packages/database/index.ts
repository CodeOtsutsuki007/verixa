// Re-exports the generated Prisma client as this package's public surface, so
// consumers import `@verixa/database` rather than `@prisma/client` directly.
// That indirection is what lets the ORM choice stay an infrastructure detail:
// only this package and the repository adapters that implement Phase 02's
// ports ever see Prisma types, and the domain/application layers never do.
//
// The client is generated, not committed — it's platform-specific (it ships a
// compiled query-engine binary for the machine that generated it), so
// `pnpm db:generate` must run after a fresh clone and any time the schema
// changes. See docs/guides/database.md.
// Loaded through createRequire rather than a static `export ... from`.
//
// The generated Prisma client is CommonJS, and Node's ESM loader can only
// statically analyse named exports from CJS when they are assigned in a form
// its lexer recognises. Prisma builds its exports dynamically, so the lexer
// finds nothing and `export { PrismaClient } from "@prisma/client"` throws at
// import time with "Named export not found".
//
// This never surfaced in tests — Vitest transforms modules rather than using
// Node's ESM loader — nor in `pnpm build`, since it is purely a runtime
// resolution concern. It appeared the moment a real `node dist/server.js`
// imported this package, which is why wiring the composition root into the
// server was worth doing on its own.
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const prismaRuntime = require("@prisma/client") as typeof import("@prisma/client");

export const {
  InvitationStatus,
  MembershipStatus,
  OrganizationStatus,
  Prisma,
  PrismaClient,
  SessionStatus,
  UserStatus,
} = prismaRuntime;

// The destructuring above binds values only, and several of these names are
// needed in type position too — `PrismaClient` as a constructor parameter on
// every repository adapter, the enums as the `status` field of four domain
// entities. A `const` and a `type` may share a name (they live in separate
// declaration spaces), so each is declared twice rather than re-exported;
// `export type { PrismaClient } from "@prisma/client"` would collide with the
// value binding instead of complementing it.
export type PrismaClient = InstanceType<typeof prismaRuntime.PrismaClient>;
export type InvitationStatus =
  (typeof prismaRuntime.InvitationStatus)[keyof typeof prismaRuntime.InvitationStatus];
export type MembershipStatus =
  (typeof prismaRuntime.MembershipStatus)[keyof typeof prismaRuntime.MembershipStatus];
export type OrganizationStatus =
  (typeof prismaRuntime.OrganizationStatus)[keyof typeof prismaRuntime.OrganizationStatus];
export type SessionStatus = (typeof prismaRuntime.SessionStatus)[keyof typeof prismaRuntime.SessionStatus];
export type UserStatus = (typeof prismaRuntime.UserStatus)[keyof typeof prismaRuntime.UserStatus];

// Surfaced directly rather than left behind `Prisma.` — adapters need to
// recognise it to translate constraint violations into domain errors, and a
// `const Prisma` carries no namespace meaning for the type position. Lifting
// it here also suits this package's purpose better: callers should not be
// reaching through a Prisma namespace to name an error they must handle.
export const PrismaClientKnownRequestError = prismaRuntime.Prisma.PrismaClientKnownRequestError;
export type PrismaClientKnownRequestError = InstanceType<
  typeof prismaRuntime.Prisma.PrismaClientKnownRequestError
>;

// Row types for the models defined in prisma/schema.prisma. Repository
// adapters (Issue 046 onward) map between these and the domain entities;
// nothing outside an adapter should ever hold one.
export type {
  Credential as CredentialRow,
  Invitation as InvitationRow,
  Organization as OrganizationRow,
  OrganizationMembership as OrganizationMembershipRow,
  Session as SessionRow,
  User as UserRow,
  MfaMethod as MfaMethodRow,
} from "@prisma/client";
