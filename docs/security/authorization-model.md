# Authorization Model: RBAC × ABAC Composition

This document describes how Verixa decides "may this subject do this thing to this
resource", and — more importantly — _why_ the composition is ordered the way it is.
It is the design counterpart to Issue 152 (`AuthorizationService`), and it is written
for someone who has to change that code without breaking it.

The composition service lives in [`packages/authorization`](../../packages/authorization);
the security analysis of the same path is in [threat-model-abac.md](threat-model-abac.md).

---

## Two layers, one question

Verixa answers authorization with two layers that know different things:

| Layer                          | Knows                                       | Cost                                   | Answers                                                             |
| :----------------------------- | :------------------------------------------ | :------------------------------------- | :------------------------------------------------------------------ |
| **RBAC** (Phase 07)            | roles and permissions, tenant membership    | one indexed lookup                     | "does this subject's role allow this action on this resource type?" |
| **ABAC** (Phase 08, Issue 148) | attributes: ownership, status, time, labels | parse + attribute resolution + combine | "does any policy apply, and what does it say?"                      |

Neither layer is sufficient alone. Roles are cheap and coarse: they cannot express
"the admin may reopen the case, but only while it is still in draft". Policies are
expressive and expensive: routing every request through the engine pays attribute
resolution for the overwhelmingly common "a role holder doing something their role
covers" case.

So the service does RBAC first, and consults policies _in addition_ rather than only
in the alternative.

## The precedence contract

```
                 authorize(subject, action, resource)
                                │
                    ┌───────────▼───────────┐
                    │   RolePermissionGate  │  (Phase 07)
                    └───────────┬───────────┘
              deny ─────────────┤
              (final)           │ grant / no-match
                    ┌───────────▼───────────┐
                    │  PolicyDecisionPoint  │  (Issue 148, deny-overrides)
                    └───────────┬───────────┘
        DENY ───────────────────┤
        (overrides a grant)     │ PERMIT / NOT_APPLICABLE
                                ▼
                        RBAC grant ? PERMIT : DENY
```

| RBAC       | ABAC                        | Result                                            |
| :--------- | :-------------------------- | :------------------------------------------------ |
| `deny`     | not consulted               | `DENY` — role denials are final                   |
| `grant`    | `DENY`                      | `DENY` — an explicit policy denial overrides it   |
| `grant`    | `PERMIT` / `NOT_APPLICABLE` | `PERMIT` — Phase 07 behaviour, unchanged          |
| `no-match` | `PERMIT`                    | `PERMIT` — the policy layer is the only authority |
| `no-match` | `DENY`                      | `DENY`                                            |
| `no-match` | `NOT_APPLICABLE`            | `DENY` — absence of authority is not authority    |

Three decisions inside that table are worth stating explicitly, because each of them
is a place where a reasonable-looking alternative is wrong:

1. **A role _grant_ does not short-circuit the policy engine.** The tempting
   optimisation — "roles already said yes, skip the expensive part" — makes every
   policy denial unreachable for every subject who holds a role. The policy layer
   could then only ever _add_ authority. This is threat E-1, and it is the reason
   the service consults policies even when the role check granted.
2. **A role _denial_ does short-circuit the policy engine.** Nothing an attribute
   says should talk a revoked permission back into existence; keeping this
   short-circuit also means a deny path costs one lookup, not one lookup plus an
   evaluation.
3. **`NOT_APPLICABLE` is not a permit.** "No policy targets this" leaves an RBAC
   answer standing — including an RBAC "no" — and defaults to denial. Treating an
   empty policy set as approval is how a deployment that has not written its
   policies yet ships permit-by-default.

## Configuration, and what it refuses

The precedence order is resolved once, at construction, and carried as a value
(`AUTHORIZATION_PRECEDENCE`) that the service exposes as `precedenceOrder` so the
composition root can log the order it booted under.

It is configuration, but not free-form configuration. `resolveAuthorizationPrecedence`
and `assertAuthorizationPrecedenceIsSafe` reject any order that:

- sets `abacDenyOverridesRbacPermit: false` — a role grant outranking a policy denial (threat E-1),
- sets `abacPermitOverridesRbacDeny: true` — a policy resurrecting a revoked permission,
- sets `defaultEffectWhenNoPolicyMatches: "PERMIT"` — permit-by-default (threat E-2).

A refused configuration throws `UnsafeAuthorizationPrecedenceError` at boot. The
service therefore cannot be constructed in a state that silently over-grants, and a
deployment that tries to is stopped at startup rather than granted access at request
time.

### The alternative that was rejected

A fully free-form order — including an `rbac-first` mode that consults policies only
when no role matched — was implemented first and then removed. It is one indexed
lookup cheaper on the happy path, and it matches the summary sentence "check roles,
fall through to ABAC" verbatim. It is rejected because it converts a precedence
_decision_ into a precedence _bug with a config flag_: the mode's whole effect is
that policy denials stop applying to role holders, which is exactly the silent
over-grant that this phase is most likely to be blamed for. A configuration surface
that cannot express an unsafe order is worth more than one that can, and the
`assertAuthorizationPrecedenceIsSafe` tests document the shape of what is refused so
a future reader can see the reasoning rather than re-discovering it.

## Failure stance

| Failure                                 | Result                                                                      |
| :-------------------------------------- | :-------------------------------------------------------------------------- |
| Role store unreachable (throws)         | `DENY`, `source: "fail-closed"`, reason "Role permission store unavailable" |
| Policy repository unreachable (throws)  | `DENY`, `source: "fail-closed"`, reason "Policy repository unavailable"     |
| Structurally unusable request           | `DENY`, `source: "fail-closed"`, reason "Invalid authorization request: …"  |
| Unknown/unsafe precedence configuration | throws at construction — the process does not boot                          |

Every request-shaped outcome is a returned decision, not an exception, because the
caller (a Policy Enforcement Point in Phase 12) has to log and act on it either way.
The two `fail-closed` reasons are distinct on purpose: "the role store is down" and
"the policy repository is down" are different incidents, and the audit trail is the
only place that distinction survives.

Malformed requests are rejected before either layer is touched. An empty `action` or
`resourceType` is not harmless: a wildcard or prefix rule can match the empty string,
and a role store keyed on `(resourceType, action)` may answer from a bucket no real
resource shares — so those values must not reach either layer.

## Decisions carry their reason

Every returned decision includes a stable `reason` and the `matchedPolicyIds` that
contributed. That is deliberate: Phase 10's audit log records why access was granted
or denied, and re-deriving the reason later from the same inputs is both expensive
and a chance to derive it differently. `AUTHORIZATION_REASONS` is the closed set of
those strings — tests assert on them, so changing one is a deliberate, reviewable act.

## Related documentation

- [Threat Model: Policy Engine & ABAC Evaluation](threat-model-abac.md) — STRIDE analysis of this path, including threats E-1 and E-2.
- [Domain Modeling](../guides/domain-modeling.md) — the layering rules the port/service split follows.
- [Multi-Tenancy & Row-Level Security](multi-tenancy.md) — the tenant boundary every `SubjectRef` carries.
