# Authorization Model: RBAC + ABAC Composition

`AuthorizationService` (`packages/authorization/application/services/authorization-service.ts`,
Issue 152) is the central architectural decision of Phase 08: it composes
Phase 07's role/permission grant check (RBAC) with ABAC policy evaluation
into one decision, rather than treating them as two independent systems a
caller has to consult separately.

## Why compose rather than pick one

Coarse-grained role checks (`"editor"` can `"read"` any `"document"`) handle
the common case cheaply, but can't express attribute-sensitive rules
("only the owner, or only before the case closes"). ABAC policies can
express those, but evaluating a full policy set for every request when a
role already settles the question is unnecessary overhead. Hybrid RBAC+ABAC
systems — AWS IAM and Google Zanzibar-adjacent designs both work this way —
get their power from the _composition_ layer, not from either model alone.
Getting the composition's precedence wrong is, per this codebase's own
security tone, the single highest-risk authorization bug class: a silent
over-grant that looks like correct code enforcing an incorrect policy.

## Precedence order

```
1. An applicable DENY policy always wins, regardless of the RBAC result.
2. Otherwise, a definitive RBAC decision (PERMIT or DENY) passes through
   unchanged.
3. Otherwise (RBAC has no opinion), an applicable PERMIT policy grants.
4. Otherwise, deny. Fail-closed.
```

| RBAC           | ABAC           | Result     | Why                                                                |
| -------------- | -------------- | ---------- | ------------------------------------------------------------------ |
| PERMIT         | PERMIT         | **PERMIT** | rule 2                                                             |
| PERMIT         | DENY           | **DENY**   | rule 1 — an applicable deny policy overrides an RBAC grant         |
| DENY           | PERMIT         | **DENY**   | rule 2 — RBAC's own deny is authoritative                          |
| DENY           | DENY           | **DENY**   | rules 1 and 2 agree                                                |
| NOT_APPLICABLE | PERMIT         | **PERMIT** | rule 3                                                             |
| NOT_APPLICABLE | DENY           | **DENY**   | rule 1                                                             |
| NOT_APPLICABLE | NOT_APPLICABLE | **DENY**   | rule 4 — fail-closed default                                       |
| PERMIT         | NOT_APPLICABLE | **PERMIT** | rule 2 — RBAC-only decisions work unchanged from Phase 07 behavior |
| DENY           | NOT_APPLICABLE | **DENY**   | rule 2 — RBAC-only decisions work unchanged from Phase 07 behavior |

Every row above is a test in `authorization-service.spec.ts`. The rule worth
stating explicitly: an RBAC grant is not the last word. A permissive role
combined with an applicable `DENY` policy always ends in `DENY` — the ABAC
layer's job is precisely to _refine or override_ the coarse-grained role
check for attribute-sensitive resources, and a design where RBAC could
short-circuit past a policy that says otherwise would defeat that purpose
entirely.

ABAC's own multiple-policy, multiple-rule outcomes are reduced to one
`PERMIT`/`DENY`/`NOT_APPLICABLE` value first, via a `CombiningAlgorithm`
(default: `denyOverrides` — see `docs/security/policy-dsl-grammar.md`'s
combining-algorithms section) before this precedence table is applied.

## RBAC is a port, not a dependency on Phase 07

Phase 07 (RBAC — role/permission entities, role assignment, route guards)
doesn't exist in this codebase yet. `AuthorizationService` depends on
`RbacAuthorizationPort` (`packages/authorization/application/ports/rbac-authorization.ts`),
not on any concrete RBAC implementation:

```ts
export interface RbacAuthorizationPort {
  checkGrant(params: {
    subjectId: string;
    action: string;
    resourceType: string;
  }): Promise<"PERMIT" | "DENY" | "NOT_APPLICABLE">;
}
```

`NoRbacGrants` implements it today: it always returns `NOT_APPLICABLE`,
which is the truthful answer when no roles or permissions are defined
anywhere in the system — not a stand-in for a real answer. This mirrors an
existing pattern in this codebase, `packages/credentials/application/ports/session-revoker.ts`'s
`NoSessionsRevoker` ("correct rather than a stub until Phase 05"): the real
call site (`AuthorizationService`, and `AuthorizeAction` above it) exists
and is exercised by tests today, rather than being written later once its
dependency shows up. When Phase 07 lands, a real
`RbacAuthorizationPort` implementation (backed by the role/permission
tables Issues 121–140 introduce) replaces `NoRbacGrants` in the composition
root, and nothing in `AuthorizationService` or `AuthorizeAction`
(Issue 153) needs to change.

## Fail-closed by default

When neither RBAC nor ABAC has an opinion (both `NOT_APPLICABLE`), the
result is `DENY`, not `PERMIT`. Two systems each silently assuming the
other would catch an ungranted request is exactly the failure mode this
composition layer exists to prevent — an explicit default-deny is safer
than an implicit default-permit that only becomes visible once something
gets through that shouldn't have.
