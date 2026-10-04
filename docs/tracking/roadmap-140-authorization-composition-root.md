# Tracking: [140] Composition-root wiring, coverage gate & public API surface for packages/authorization

## Status

**Blocked** — the Phase 07 package this issue closes out does not exist on `master` yet.

- Issue: https://github.com/Kyvera-Labs/verixa/issues/77
- Phase: 07 — Authorization: RBAC, roadmap issue 140
- Verified at: `138d1e0` (`master`)

This is a tracking note, not an implementation. It records why the issue is
blocked and what will unblock it, so progress is visible without opening a PR
against interfaces that do not exist.

## Blocking dependencies

All still open at the time of writing:

- #66 — roadmap 129: Prisma-backed repositories (Role, Permission, UserRoleAssignment)
- #71 — roadmap 134: `PermissionChecker` application service
- #73 — roadmap 136: Fastify `requirePermission` preHandler route guard
- #74 — roadmap 137: request-scoped principal resolution & per-request caching
- #76 — roadmap 139: Admin role-management REST API

The package itself (`packages/authorization`) is being built across a large
number of unmerged PRs (for example #227, #232, #234–236, #242–251, #255–259,
#266, #273). None are merged into `master`.

## Why this is blocked

The deliverable is to *register* existing implementations — the Phase 07 use
cases, `PermissionChecker`, and the Prisma repositories — in
`apps/api/src/composition-root.ts`, and to curate `packages/authorization/index.ts`.
None of those implementations exist on `master`, so there is nothing to wire and
nothing to re-export. `apps/api/src/composition-root.ts` currently has no
authorization entries to extend, and `packages/authorization` is absent entirely.

The issue's own guidance applies: "If any of those are still open, check with a
maintainer on this issue before starting — you may be able to proceed against
the interface alone, or it may be worth waiting." There is no interface on
`master` to proceed against.

## What unblocks it

`packages/authorization` landing on `master` with the Phase 07 use cases,
`PermissionChecker`, and the Prisma repositories (#66, #71, #73, #74, #76).

## Plan once unblocked

1. Register the authorization repositories, use cases, and `PermissionChecker`
   in `apps/api/src/composition-root.ts`, following the existing identity and
   sessions wiring.
2. Apply the 037/076/097 coverage-gate pattern to
   `packages/authorization/vitest.config.ts`.
3. Curate `packages/authorization/index.ts` per the 038/078/099 boundary pattern
   so matching/resolution internals stay unexported, and update the boundary
   rules in `eslint.config.mjs` accordingly.
