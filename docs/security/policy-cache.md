# Policy Cache: Caching and Invalidation

This document describes the cache that sits in front of the ABAC evaluation path — why it
is shaped the way it is, what "invalidation" has to mean here, and which alternatives were
rejected. It is the design counterpart to Issue 154 (`PolicyCache`); the evaluation and
composition it accelerates are described in
[authorization-model.md](authorization-model.md), and the threat analysis of the same path in
[threat-model-abac.md](threat-model-abac.md) (threats E-3 and D-3).

---

## Why caching authorization is not caching an ordinary read

An ordinary cache that serves a stale value shows a user something out of date. This cache
sits on the path that decides whether a request is allowed, so a stale entry can be a
`DENY → PERMIT` transition — a revoked policy continuing to grant access. That changes the
requirements rather than the speed goal:

| Requirement               | Ordinary cache      | This cache                                                              |
| :------------------------ | :------------------ | :---------------------------------------------------------------------- |
| Stale value               | Tolerable for a TTL | A security bug: the TTL is a _memory_ bound, not a correctness bound    |
| Invalidation              | Best effort         | Synchronous on publish; "no stale window" is the acceptance criterion   |
| Store unavailable         | Fail the read       | Degrade to direct evaluation (slower, still correct, still fail-closed) |
| A read that cannot answer | Error               | A miss — never a decision                                               |

## Shape

```
publish (Issue 150)  ──▶ PolicyCache.invalidateResourceType(type)   ──▶ generation++
                                     │
evaluate (Issue 148) ──▶ PolicyCache.get({ resourceType, action })  ──▶ entry | miss
                                     │
                                     └── version mismatch? ──▶ miss ──▶ evaluate from source
```

Two mechanisms, doing two different jobs:

1. **Generations make invalidation instant and atomic.** Each resource type has a generation
   counter and every entry key embeds the generations in force when it was written.
   `invalidateResourceType("document")` is a single `INCR`: from that instant, the key a reader
   computes no longer matches the key the old entries live under, so they are unreachable
   without being deleted. Nothing partially fails, and no `SCAN`/`KEYS` runs against a shared
   Redis — a scan is itself an availability risk, and an invalidation that half-completes is
   worse than no cache at all, because it looks like it worked.
2. **The policy version on every entry makes a missed invalidation harmless.** Entries carry
   the `policyVersion` they were derived from, and a reader compares that with the version it
   believes is active, treating a mismatch as a miss. That is the second line of defence: it
   bounds the stale window to "until the reading node next reads" — zero for the node that
   published, one read for another node whose invalidation write has not landed yet — instead
   of "until the TTL expires".

The cost of (1) is superseded keys living until their TTL. That cost is bounded and visible
(`live entries + everything written within one TTL of the last publish`), and it is what buys
an invalidation that cannot half-succeed.

## Degrading instead of failing: `ResilientPolicyCache`

The adapter (`RedisPolicyCache`) lets Redis errors propagate, because "the store obeyed" is
its contract, and a `get` that silently converted a connection error into a miss would look
identical to a healthy miss from the outside — the resulting stampede on Postgres would arrive
with no signal explaining it.

`ResilientPolicyCache` is the decorator that decides what an outage _means_:

| Operation     | Wrapped failure becomes | Why                                                                                                                                                  |
| :------------ | :---------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------- |
| `get`         | a miss (`undefined`)    | The caller recomputes from the source of truth. `undefined` can only mean "not cached", never "not permitted"                                        |
| `set`         | no-op                   | A cache that cannot be written still serves; failing here turns an optimization into a dependency                                                    |
| `invalidate*` | no-op, **reported**     | Publishing is the operation that _removes_ authority; refusing a publish because Redis hiccuped would leave the broader policy in force indefinitely |

Every degradation is passed to `onDegrade`, so the outage — and the stale window an
invalidation failed to close — is observable rather than silent. Wiring that handler to the
context's logger is the difference between "slower" and "slower and unexplained".

## What was rejected

- **TTL-only invalidation.** The simplest cache: short TTLs, no invalidation API. Rejected
  because it makes the stale window a policy decision made by whoever set the TTL, and the
  worst case is exactly the one that matters: an admin narrowing a policy and the old, broader
  one continuing to permit for the remainder of the TTL. TTLs are kept, but as a memory bound.
- **Deleting keys on invalidation.** `DEL`/`SCAN` over the matching keys makes invalidation
  proportional to the keyspace and non-atomic: a failure midway leaves some entries live, and
  the caller cannot tell which. Generations make the same operation O(1) and total.
- **Decision caching in this PR.** The issue marks short-TTL caching of whole
  `(subject, action, resource)` decisions as optional. It is deferred deliberately: a decision
  key has to hash the _attribute context_, not just the identifiers, or two requests that
  differ only in an attribute a policy conditions on collide into one answer — a silent
  over-grant. The port is generic over the cached value, so the AST cache added here and a
  decision cache later use the same interface, but the key-derivation and correctness story
  for decisions deserves its own change.
- **A Testcontainers harness in this package.** The Redis-backed suite connects to
  `TEST_REDIS_URL` (which the CI job provides from a service container) and skips when it is
  unset, with `REQUIRE_REDIS_TESTS=1` turning the skip into a failure — the same convention as
  the sessions deny-list suite. A Docker lifecycle dependency here would duplicate Issue 047's
  harness for a case CI already covers.

## Operational notes

- **Keyspace growth** after a publish is bounded by one TTL's worth of superseded entries per
  resource type; sizing Redis for `live + one TTL of churn` is sufficient.
- **A cache miss is not an error.** Dashboards should track miss rate and the degradation
  counter separately: a rising miss rate is a cold cache, a rising degradation counter is an
  outage, and conflating them hides the second one.
- **`flushall` is not an operational tool.** `invalidateAll` bumps a generation; wiping the
  instance also evicts whatever else shares it.

## Related documentation

- [Authorization Model: RBAC × ABAC Composition](authorization-model.md) — the decision path this cache accelerates.
- [Threat Model: Policy Engine & ABAC Evaluation](threat-model-abac.md) — threats E-3 (stale cache) and D-3 (invalidation stampede).
- [Testing](../../docs/guides/testing.md) — the contract-suite and skip-without-service conventions.
