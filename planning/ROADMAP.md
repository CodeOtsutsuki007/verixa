# Verixa — Development Roadmap

> **Contributors:** work is tracked as GitHub Issues, which are generated
> from the phase files in `planning/issues/`. If an issue you want to work on
> isn't open yet, say so — the specification already exists here and opening
> it is a two-minute job.
>
> Every issue carries its own acceptance criteria, dependencies, required
> tests and required documentation *before* anyone starts, so "done" is
> agreed up front rather than negotiated in review.

500 sequential issues, grouped into 25 phases of 20 issues each. Issues are
sequential and mostly dependency-ordered within a phase; cross-phase dependencies
are called out explicitly in each issue.

Full issue detail lives in `planning/issues/phase-XX-<slug>.md`.

| Phase | Range | Title | Summary |
|---|---|---|---|
| 01 | 001–020 | Foundation & Tooling | Monorepo scaffold, TS/lint/format config, CI skeleton, Docker base, config loading, base error/Result types |
| 02 | 021–040 | Domain Modeling — Identity Core | User/Organization entities, value objects (Email, UserId), domain events, identity repository port |
| 03 | 041–060 | Database & Persistence | Postgres setup, Prisma schema, migrations, repository implementations, Testcontainers integration tests |
| 04 | 061–080 | Auth — Credentials & Passwords | Password hashing (argon2), password policy, registration, login, password reset, email verification, lockout |
| 05 | 081–100 | Auth — Sessions & Tokens | Session entity, JWT access/refresh tokens, token rotation, revocation lists (Redis), logout, "logout everywhere" |
| 06 | 101–120 | Multi-Factor Authentication | TOTP enrollment/verification, backup codes, WebAuthn/passkey registration & assertion, MFA enforcement policy |
| 07 | 121–140 | Authorization — RBAC | Role/Permission entities, role assignment, permission checks, route guards, seed roles, admin role management API |
| 08 | 141–160 | Authorization — ABAC / Policy Engine | Policy DSL, policy evaluation engine, resource-attribute conditions, policy testing tools, RBAC+ABAC composition |
| 09 | 161–180 | Identity Verification | Verification request workflow, evidence submission, reviewer queue, verification status state machine, provider adapter interface |
| 10 | 181–200 (+190A–190D) | Audit Logging | Append-only audit event store, event schema, emitters across contexts, query/export API, tamper-evidence (hash chaining + optional Stellar external anchoring, ADR-0003) |
| 11 | 201–220 | Security Hardening | Threat modeling docs, CSRF/CORS, security headers, secrets management, dependency scanning, brute-force protection, pen-test checklist |
| 12 | 221–240 | API Layer — REST | OpenAPI-first route definitions, request validation, error response contract, pagination, versioning strategy, API key auth for machine clients |
| 13 | 241–260 | API Layer — GraphQL & Gateway | GraphQL schema for governance/admin use cases, resolvers over existing use cases, gateway auth context, query complexity limits |
| 14 | 261–280 | Notifications & Messaging | Notification domain events, email adapter, SMS adapter, webhook dispatch, templating, delivery retry/backoff, preference center |
| 15 | 281–300 | Rate Limiting & Abuse Prevention | Token-bucket limiter, per-route policy, IP/account-based limits, CAPTCHA hook, anomaly flags, abuse audit trail |
| 16 | 301–320 | Admin & Governance | Org management, policy management UI-facing API, compliance workflows, data retention rules, admin audit views |
| 17 | 321–340 | Developer Tooling & SDKs | TypeScript SDK client, CLI for local dev/admin tasks, seed/fixture scripts, Postman/OpenAPI export, plugin/extension points |
| 18 | 341–360 | Observability | Structured logging, correlation IDs, metrics endpoint, tracing hooks, health/readiness checks, dashboards-as-code |
| 19 | 361–380 | CI/CD & DevOps Automation | GitHub Actions pipelines (lint/test/build), release automation (semantic-release), dependency update automation, preview environments |
| 20 | 381–400 | Docker & Deployment Infra | Multi-stage Dockerfiles, docker-compose for local dev, production deployment guide, environment config matrix, migrations-on-deploy |
| 21 | 401–420 | Testing Infrastructure | Unit test conventions, integration test harness, e2e test suite, contract tests, coverage gates, mutation testing exploration |
| 22 | 421–440 | Documentation & Education | README overhaul, docs site structure, architecture guides, "build your own auth" tutorial series, contributor onboarding docs |
| 23 | 441–460 | Performance & Scalability | Query optimization, caching strategy, load testing, connection pooling, horizontal scale readiness, index review |
| 24 | 461–480 | Compliance & Data Privacy | GDPR-style data export/delete, data classification, consent tracking, retention policies, privacy-by-design review |
| 25 | 481–500 | Community, Governance & v1.0 Launch | CONTRIBUTING/CODE_OF_CONDUCT, issue/PR templates, RFC process, changelog automation, v1.0 readiness checklist, launch materials |

## Sequencing Notes

- Phases 01–03 are hard prerequisites for everything else (tooling, domain
  primitives, persistence).
- Phases 04–08 (auth/authz) are the critical path for a usable MVP and should
  land before phases 09–16 in most contribution orders, though verification (09)
  and audit (10) can proceed in parallel once phase 03 is done.
- Phases 17–24 are largely independent of each other and can be parallelized
  across contributors once their phase-level dependencies are met.
- Phase 25 (launch) depends on a stable, tested subset of all prior phases, not
  literally every issue — a v1.0 scope cut will be made explicitly when that
  phase is reached.

## Status

- [x] Issue 001 — Initialize monorepo workspace & base tooling (implemented)
- [x] Issue 002 — Configure ESLint + Prettier across the workspace (implemented)
- [x] Issue 003 — Root TypeScript strict-mode configuration (implemented)
- [x] Issue 004 — Shared kernel package: Result/Either type (implemented)
- [x] Issue 005 — Shared kernel: typed identifiers (branded types) (implemented)
- [x] Issue 006 — Domain error hierarchy (implemented)
- [x] Issue 007 — Typed configuration loader (implemented; also reverted Issue 003's source `paths` alias in favor of standard package resolution — see docs/guides/typescript-conventions.md)
- [x] Issue 008 — Structured logger setup (pino) (implemented)
- [x] Issue 009 — Git hooks: pre-commit lint/format/typecheck (implemented)
- [x] Issue 010 — Conventional Commits enforcement (implemented)
- [x] Issue 011 — CI skeleton: lint/typecheck/test workflow (implemented)
- [x] Issue 012 — Base Dockerfile for apps/api (implemented)
- [x] Issue 013 — docker-compose for local development (implemented)
- [x] Issue 014 — Vitest test runner configuration (implemented)
- [x] Issue 015 — Supertest HTTP integration test harness (implemented; also fixed CI ordering — build must run before lint too, not just before typecheck/test, since package.json `exports` subpaths have no missing-file fallback)
- [x] Issue 016 — EditorConfig & VS Code workspace recommendations (implemented)
- [x] Issue 017 — CODEOWNERS and PR/issue templates (implemented)
- [x] Issue 018 — Root README v1 (project overview) (implemented; license badge added)
- [x] Issue 019 — LICENSE and NOTICE (implemented; NOTICE + per-package `license` fields + SPDX guidance)
- [x] Issue 020 — Architecture Decision Record (ADR) process (implemented)
- [x] Issue 021 — `Email` value object (implemented)
- [x] Issue 022 — `DisplayName` and `PersonName` value objects (implemented)
- [x] Issue 023 — `User` entity (implemented)
- [x] Issue 024 — `Organization` entity (implemented)
- [x] Issue 025 — `OrganizationMembership` entity (implemented)
- [x] Issue 026 — Domain event base type & dispatcher interface (implemented)
- [x] Issue 027 — `UserRegistered` and `UserStatusChanged` domain events (implemented)
- [x] Issue 028 — `UserRepository` port (implemented)
- [x] Issue 029 — `OrganizationRepository`/`OrganizationMembershipRepository` ports (implemented)
- [x] Issue 030 — Use case: `RegisterUser` (implemented)
- [x] Issue 031 — In-memory fake repositories + reusable contract test suite (implemented)
- [x] Issue 032 — Use case: `UpdateUserProfile` (implemented)
- [x] Issue 033 — Use cases: `SuspendUser` / `ReactivateUser` (implemented)
- [x] Issue 034 — Use case: `CreateOrganization` (implemented)
- [x] Issue 035 — Use case: `InviteUserToOrganization` (domain skeleton) (implemented)
- [x] Issue 036 — Domain validation error aggregation utility (implemented)
- [x] Issue 037 — Identity context unit test coverage gate (implemented)
- [x] Issue 038 — `packages/identity` public API surface (`index.ts`) (implemented)
- [x] Issue 039 — ADR: Identity/Organization multi-tenancy model (implemented; numbered ADR-0002 to match actual sequence — see below)
- [x] Issue 040 — Identity context educational walkthrough (implemented)
- [x] Issue 041 — Provision PostgreSQL for local/dev/test (implemented; verified structurally + via CI, no local Docker in this environment)
- [x] Issue 042 — Initialize Prisma schema & migration workflow (implemented as `packages/database` rather than a root `prisma/` dir — pnpm's strict resolution requires the generated client to live in a package its consumers depend on; no migration files yet since there are no models until Issue 043)
- [x] Issue 190A (pulled forward, out of sequence) — Stellar external audit-anchoring adapter. `packages/stellar-anchor`: `HashAnchor` port, `StellarHashAnchor` (MEMO_HASH commitment + Horizon verification), `InMemoryHashAnchor` fake doubling as the anchoring-disabled option, shared behavioral contract both pass, and an anchor/verify CLI. 7 tests green against the live Stellar testnet. Built ahead of its Phase 10 consumer deliberately — the mechanism is independently useful and worth proving against a real ledger before an audit subsystem depends on it. The scheduled chain-tip anchoring job and `VerifyAuditChain` integration remain in Phase 10.
- [x] Issue 043 — `users` table & Prisma model (implemented; `citext` email with a case-insensitive unique index, `user_status` enum mirroring the domain union, `timestamptz` timestamps, domain-assigned UUID id with no `@default`. Migration SQL generated offline via `prisma migrate diff --from-empty` since this environment has no local Postgres; verified against a real database in CI. Also fixed a pre-existing defect from Issue 041: database-backed tests now skip gracefully when no Postgres is reachable — `pnpm test` was failing on a fresh clone without Docker — with `REQUIRE_DATABASE_TESTS=1` in CI so the skip can't silently hide missing coverage. Known gap: `given_name`/`family_name` are independently nullable, permitting a DB state `PersonName` can't represent; needs a CHECK constraint Prisma can't express, deferred until it can be verified against a live database.)
- [x] Issue 044 — `organizations` & `organization_memberships` tables (implemented; citext slug, explicit FK policies — RESTRICT on `organizations.owner_id` so erasing an owner can't destroy an org, CASCADE on memberships. Active-membership uniqueness is a **partial** unique index, hand-written into the migration since Prisma can't express a WHERE on `@@unique`; that object is unmanaged by Prisma, noted in docs.)
- [x] Issue 045 — `invitations` table (implemented; token stored as SHA-256 hash only. Required a domain change: `Invitation.create()` now returns `IssuedInvitation` — the raw token alongside the entity rather than on it — so the raw value exists exactly once and cannot be persisted by accident. Added `matchesToken` with timing-safe comparison. New doc: docs/security/token-storage.md.)
- [x] Issue 046 — Prisma-backed `UserRepository` (implemented; explicit hand-written mapper keeps Prisma types out of the domain, passes the Issue 031 contract suite against real Postgres.)
- [x] Issue 047 — Testcontainers integration test setup (implemented as a two-strategy harness: reuse `TEST_DATABASE_URL` when reachable, else start an ephemeral container. A dedicated CI job runs *without* `TEST_DATABASE_URL` to prove the Testcontainers path actually works rather than shipping untested.)
- [x] Issue 048 — Prisma-backed `OrganizationRepository`/`OrganizationMembershipRepository` (implemented; introduced a `UnitOfWork` port so `CreateOrganization` writes both aggregates in one transaction. `CreateOrganization` now takes the unit of work instead of two repositories. Rollback verified against real Postgres.)
- [x] Issue 049 — `InvitationRepository` implementation (implemented; hashes the raw token in the adapter — the only layer that knows the stored form — and filters expiry in SQL rather than in memory.)
- [x] Issue 050 — Composition root (implemented; `apps/api/src/composition-root.ts` is the single place that knows concrete implementations exist. Integration test drives `RegisterUser`, `UpdateUserProfile`, and `CreateOrganization` end to end against real Postgres.)
- [x] Issue 051 — Database seeding script (implemented; `pnpm db:seed`, idempotent via fixed-id upserts. Deliberately seeds no invitations — a seeded token would be a working bearer credential in version control, and one without a token is a row nobody can accept.)
- [x] Issue 052 — Row-Level Security policies (implemented on organizations/memberships/invitations; `users` excluded because a user is a global identity spanning tenants. Policies fail closed on missing context, and use WITH CHECK as well as USING so cross-tenant *writes* are refused too. Tenant context is transaction-scoped via `set_config(..., is_local => true)` — session-scoped `SET` would leak across pooled connections, and `SET LOCAL` can't take bind parameters. **Known limitation, documented loudly: superusers bypass RLS unconditionally, and local/CI/testcontainers all connect as one, so RLS is currently inert in those environments.** The test creates an unprivileged role specifically so it verifies something real.)
- [x] Issue 053 — Connection pooling configuration (implemented; `DATABASE_POOL_SIZE`/`DATABASE_POOL_TIMEOUT_SECONDS` validated through `@verixa/config` and applied to the Prisma URL in the composition root. Capped at 100 since crossing stock `max_connections` turns queueing into refused connections. Load testing to validate the defaults empirically is Phase 23.)
- [x] Issue 054 — Soft-delete strategy for `User` (implemented; `deleted_at` column + indexed for the Phase 24 retention scan. `findById`/`findByEmail` exclude deleted by default; `findByIdIncludingDeleted` is a separate method rather than a boolean flag so privileged reads are greppable. `existsByEmail` deliberately *includes* deleted users so it agrees with the unique index — otherwise registration passes its own check then dies on a constraint violation. `reconstitute` throws if status and `deletedAt` disagree. Known limitation, documented: a deleted user's email stays taken; freeing it is anonymization-at-erasure work in Phase 24.)
- [x] Issue 055 — Index review (implemented; review found the schema already correct, verified by an EXPLAIN test seeding 3000 rows + ANALYZE — on the 3-row dev seed Postgres correctly picks a seq scan, so a small-dataset assertion would have failed. Also asserts an unselective query *does* seq-scan, and documents why `@@index([organizationId])` isn't redundant with the composite one, per leftmost-prefix.)
- [x] Issue 056 — Repository error mapping (implemented; Prisma error codes → domain errors at the boundary. Only actionable codes mapped — connection failures and unknown codes rethrow untouched, since flattening them would claim the failure was expected and discard diagnostics.)
- [x] Issue 057 — Backup/restore scripts (implemented; custom-format dumps, `--single-transaction` restore, and a guard refusing non-local hosts since restore drops every object. Manual drill documented.)
- [x] Issue 058 — Schema lint + drift detection in CI (implemented; `prisma validate`, `format --check`, and a shadow-database drift check. NOTE: the drift check's behavior against the unmanaged partial index / RLS policies is unverified locally — no shadow DB here — so CI is the first real test of it.)
- [x] Issue 059 — Performance baseline (implemented; p50/p95/p99 benchmark script. Baseline table deliberately left unrecorded rather than populated from a CI runner — cross-machine numbers are meaningless and a wrong number carries more authority than a missing one.)
- [x] Issue 060 — Persistence layer walkthrough (implemented; includes the two real bugs the contract suite caught, since those make the case better than the theory does.)
- [ ] Issues 190B–190D — Stellar **mainnet** readiness: KMS-backed key management, funding/balance monitoring, and a rehearsed cutover runbook. Added because the gap was previously invisible: 190A is testnet-only, and shipping it to mainnet needs operational work that no issue covered.
- [x] Issue 061 — Password hashing service (argon2id) (implemented; `PasswordHasher` port + `Argon2PasswordHasher` at OWASP minimum parameters. `needsRehash` had to be hand-implemented via `parseOptions` — the library has no such function, and an over-broad try/catch initially hid that as "unreadable hash". It reports upgrades only, never downgrades, so lowering a parameter can't silently re-hash every password down to it.)
- [x] Issue 062 — Password policy value object (implemented; NIST 800-63B — length over composition rules, no forced rotation. `RawPassword` redacts under `toString`, `toJSON`, `util.inspect` *and* spread, with `reveal()` named to stand out in review. Max length exists for DoS, not strength, and rejects rather than truncating.)
- [x] Issue 063 — `Credential` entity & repository port (implemented; separate aggregate from `User` so password-less accounts — SSO, passkey, service — are "no row" rather than a nullable column. Factory accepts a hash only, so the aggregate cannot hash and therefore cannot hash wrongly.)
- [x] Issue 064 — `credentials` table & Prisma repository (implemented; one-to-one optional, CASCADE on user delete since an orphaned hash is exactly the data that most needed to go. Hash redacted from all serialization paths.)
- [x] Issue 065 — Use case: `RegisterUserWithPassword` (implemented; first cross-context orchestration. Validation and hashing happen *before* the transaction opens — hashing invalid input hands an attacker a cheap CPU-burn, and holding a transaction across a 50-100ms hash wastes a pooled connection. Atomicity verified against real Postgres, since the in-memory unit of work deliberately does not roll back.)
- [x] **Vertical slice** (unnumbered; prerequisite for everything above being reachable) — composition root wired into `server.ts`, `POST /auth/register`, HTTP error mapping, graceful shutdown. Until this landed, every repository, use case and mapper in the workspace was unreachable from a running server and the architecture was unvalidated at the integration level.
- [x] Issue 066 — Use case: `AuthenticateWithPassword` (implemented; five distinct failure causes — unknown email, malformed email, no password credential, wrong password, suspended account — all return one identical `AUTHENTICATION_FAILED`. A matching message is not enough on its own, so when there is no credential to check the submitted password is verified against a decoy hash and the result discarded, closing the timing channel that would otherwise answer what the message refuses to. Explicitly *not* constant-time, and documented as such. The status check runs after the password check, which looks backwards until you see that checking it first identifies a suspended account to someone who never knew its password. `pending` users can log in — registration leaves them pending, so refusing them would mean nobody could sign in after signing up.)
- [x] **Login endpoint + unprivileged database role** (unnumbered; completes the vertical slice) — `POST /auth/login` returning the authenticated user and deliberately no token, since sessions are Phase 05 and a placeholder clients stored would be worse than none. The compose stack now connects the API as `verixa_app` (NOSUPERUSER, NOBYPASSRLS) rather than the cluster superuser: **superusers bypass row level security entirely**, so on the old connection every tenant-isolation policy was decoration and a missing `app.current_organization_id` would have read across tenants with no test failing. `FORCE ROW LEVEL SECURITY` closed only the owner half of that. Role wiring is unverified end to end — no Docker locally and CI builds the production image rather than running compose.
- [x] Issue 067 — Account lockout on repeated failures (implemented; five consecutive failures lock for a minute, doubling per further attempt to a one-hour cap. Exponential because a fixed window still permits ~480 guesses a day forever; capped because unbounded backoff is a denial of service handed to attackers. The issue asked for a “distinct (but still enumeration-safe) error”, and those pull against each other — lockout state exists only for accounts that exist, so any visible difference is an enumeration oracle. Resolved by making it distinct as a *type* and byte-identical on the wire, with an integration test pinning that. A visible-yet-safe lockout would need attempts tracked for non-existent addresses too; that is Phase 15. The lock is checked ahead of hashing, which makes it the fastest path, so the timing decoy runs there too.)
- [x] **Compose database-role CI job** (unnumbered) — closes the gap flagged when the `verixa_app` role landed. The init scripts in `infra/postgres/` had never been executed by anything: the `ci` job uses a bare service container and the `docker` job builds the production image. The job now starts Postgres from `docker-compose.yml`, migrates as the owner, and asserts the role is `f|f|f|f` on superuser/bypassrls/createdb/createrole, can read and write application tables, is refused an insert into an RLS-protected table, and is refused DDL.
- [x] Issue 068 — Email verification token flow (implemented; single-use, 24-hour, SHA-256 digest only. Deliberately *not* argon2 — 256 random bits have no dictionary to try, so the cost would buy nothing and add latency to a link a user just clicked. Confirmation reports *why* it failed, which is a considered departure from the login rule: reaching it requires already holding the token, so there is nothing left to enumerate, and “expired” versus “already used” lead to different actions.)
- [x] Issue 069 — Password reset request flow (implemented; identical response whether or not the account exists, with issuance observable only through an internal flag — the acceptance criterion's “verified via internal event, not response”. Refuses to issue for an account with no credential, since that would let someone *create* a password on an SSO-only account.)
- [x] Issue 070 — Password reset confirmation flow (implemented; policy checked before the token is consumed so a rejected password does not burn the link, credential replaced, lockout cleared, and **every session revoked**. `NoSessionsRevoker` is correct rather than a stub until Phase 05. Revocation failure is reported, not swallowed — a failed notification costs an email nobody received, a failed revocation costs a false sense of safety.)
- [x] Issue 085 — Signing key management & rotation (implemented ahead of the rest of Phase 05 as a self-contained slice — no session aggregate or refresh token needed. `SigningKeyProvider` holds a set of asymmetric keys addressed by `kid`: one current signer plus verification-only retired keys, config-driven via `@verixa/config`'s `loadSigningKeys`. A token signed by a retired-but-still-held key verifies; an unknown `kid` — removed or forged — is rejected. The verifier pins its accepted algorithms to the keys it holds, closing the `alg` substitution/`none` footgun. Includes a minimal `JwtTokenSigner` (the seam Issue 084 will formalise) so rotation is actually exercised rather than asserted in the abstract. Retired keys carry no private half, so an old key's leaked config cannot sign. See `docs/security/token-design.md`.)
- [x] Issue 088 — Redis-backed revocation / deny-list adapter (implemented as a self-contained slice; needs only a `SessionId`, not the full session aggregate. `RevocationList` port + `RedisRevocationList`: one key per revoked session, TTL = the token's remaining lifetime, so the list self-expires and its size is bounded by the access-token TTL rather than the all-time revocation count. **Fails closed** — an unreachable Redis makes `isRevoked` return `true`, trading availability for safety, because a silent revocation-bypass window is exactly what an attacker with a revoked token waits for; `revoke` propagates errors rather than reporting a revocation that did not happen. Same fake/contract/Testcontainers pattern as Issue 031/047. See `docs/security/token-design.md`.)
- [ ] Issues 071–500 — planned, not yet implemented (except 085, 088 above, and 190A). Issues 085 and 088 landed early because they stand alone; the rest of Phase 05 (the session aggregate 081–083, JWT signer 084, refresh tokens 086, and the issue/refresh/logout use cases 087+) is still outstanding, and the refresh-rotation and reuse-detection issues that build on it (089, 090) are blocked on it.
