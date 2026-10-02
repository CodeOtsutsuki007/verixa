# Policy DSL grammar

This document defines the small expression language used to describe ABAC
policies. It deliberately handles expressions rather than declarations,
variables, or arbitrary code: authorization rules need to be readable and
auditable, and a constrained grammar makes their meaning predictable.

## Grammar

The grammar is EBNF. Terminals in quotes are literal tokens; `#` starts a
comment through the end of a line. Keywords are case-sensitive.

```ebnf
policy       = effect, "if", expression ;
effect       = "permit" | "deny" ;
expression   = disjunction ;
disjunction  = conjunction, { "or", conjunction } ;
conjunction  = negation, { "and", negation } ;
negation     = [ "not" ], comparison ;
comparison  = primary, [ comparison-op, primary ] ;
comparison-op = "==" | "!=" | "<" | "<=" | ">" | ">=" | "in"
              | "contains" | "matches" ;
primary      = literal | attribute | "(", expression, ")"
              | function-call ;
function-call = identifier, "(", [ arguments ], ")" ;
arguments    = expression, { ",", expression } ;
attribute    = bag, ".", identifier, { ".", identifier } ;
bag          = "subject" | "resource" | "action" | "environment" ;
literal      = string | number | "true" | "false" | "null"
             | date | array ;
array        = "[", [ literal, { ",", literal } ], "]" ;
string       = '"', { escaped-character | non-quote-character }, '"' ;
number       = [ "-" ], digit, { digit }, [ ".", digit, { digit } ] ;
date         = "date(", string, ")" ;
identifier   = letter, { letter | digit | "_" } ;
```

Attribute paths start with one of the four standard ABAC bags. Further path
segments are resolved as nested object properties by the attribute context;
missing segments evaluate as missing values. A date literal is an ISO-8601
string wrapped in `date(...)`, validated as a date when parsed. Arrays contain
literals only, which keeps membership checks deterministic and avoids hidden
evaluation in data literals.

## Operators and precedence

From highest to lowest precedence:

| Precedence | Operators | Associativity |
| --- | --- | --- |
| 1 | parentheses, function calls, attribute access | left to right |
| 2 | `not` | right to left |
| 3 | `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `contains`, `matches` | non-associative; chain comparisons with `and` |
| 4 | `and` | left to right |
| 5 | `or` | left to right |

`and` binds more tightly than `or`, so `a or b and c` means `a or (b and c)`.
Comparisons do not chain: `a < b < c` is invalid. Use
`a < b and b < c` to make the intent explicit. `matches` takes a string on the
right and interprets it as a regular expression; invalid patterns are rejected
when a policy is parsed. Operators do not coerce types: equality between
different types is false (and inequality is true), while ordering, membership,
containment, and matching with incompatible types evaluate false.

## Attribute model

An attribute reference is `bag.name` or a nested path such as
`resource.owner.id`:

| Bag | Meaning | Typical values |
| --- | --- | --- |
| `subject` | Principal making the request | `id`, `orgId`, `roles`, `emailVerified` |
| `resource` | Object being accessed | `ownerId`, `orgId`, `status`, `availableFrom` |
| `action` | Operation being requested | `name`, `resource`, `method` |
| `environment` | Request and execution context | `now`, `ip`, `userAgent`, `requestId` |

All bags are typed maps. Supported values are strings, finite numbers,
booleans, dates, arrays, and nested records made from those values. Looking up
a missing path produces an undefined value; it never throws. Evaluation of a
comparison involving a missing value is false, including `!=`, so missing
information cannot accidentally grant access. `not` applies to boolean
expressions and follows the same fail-closed rule when its operand cannot be
evaluated.

## Functions

Functions are deliberately allowlisted by the evaluator. The initial helper is
`between(value, start, end)`, an inclusive comparison (`start <= value <= end`)
for date or number values. It supports time-window policies without embedding
the system clock: policies compare an explicit `environment.now` attribute,
which request construction supplies from the application's clock port. Unknown
functions, wrong arity, invalid dates, and malformed regex patterns are
rejected during parsing.

## Attribute sourcing

The evaluation engine consumes an `AttributeContext`; it does not fetch data.
An application-layer `AttributeProvider` contributes context bags from one
source. Providers run in registration order and later values override earlier
values at the same path. Register trusted server-derived data after
request-supplied claims so callers cannot overwrite verified identity or
resource facts. A provider declares whether failure is `fail-open` or
`fail-closed`: optional enrichment can be skipped, while a source required for
an authorization invariant must fail the resolution. The pipeline preserves
that distinction and never silently treats a failed required source as an
empty bag.

## Examples

Each example is a complete policy expression after the `if` keyword.

1. **Resource ownership:** `permit if resource.ownerId == subject.id`
2. **Read-only access:** `permit if action.name == "read"`
3. **Organization boundary:** `permit if resource.orgId == subject.orgId`
4. **Verified account:** `permit if subject.emailVerified == true`
5. **Active resource:** `permit if resource.status == "active"`
6. **Organization admin:** `permit if subject.roles contains "org-admin" and resource.orgId == subject.orgId`
7. **Time window:** `permit if between(environment.now, resource.availableFrom, resource.availableUntil)`
8. **Business hours:** `permit if environment.hour >= 9 and environment.hour < 17`
9. **Network allowlist:** `permit if environment.ip in ["192.0.2.10", "192.0.2.11"]`
10. **Sensitive action requires MFA:** `permit if action.name != "delete" or subject.mfaSatisfied == true`
11. **Deny suspended subjects:** `deny if subject.status == "suspended"`
12. **Nested resource owner:** `permit if resource.owner.id == subject.id and action.name == "update"`

These examples use `environment.now` and other request facts as explicit
attributes. This keeps decisions reproducible in tests and audit replays: the
same context always produces the same result.
# Policy DSL Grammar

This document is the reference for `packages/authorization`'s ABAC policy
DSL — grammar, attribute sourcing, evaluation semantics, and operators. It
grows section by section as later Phase 08 issues land (the grammar itself
is Issue 142, the parser Issue 143, the attribute model Issues 144-145, the
evaluator Issue 146, operators Issue 147). Resource-attribute resolution
(Issue 151) is documented below since its implementation exists ahead of
the sections it depends on.

## Resource-attribute resolution

A policy condition can reference a resource's own attributes — `resource.ownerId`,
`resource.sensitivity`, `resource.status` — but `packages/authorization` has
no schema for a `document` or a `verificationCase`; those belong to
`packages/verification`, `packages/governance`, and every other bounded
context that owns a resource type policies might target.

`ResourceAttributeResolverRegistry`
(`packages/authorization/application/services/resource-attribute-resolver-registry.ts`)
is the seam that resolves this without creating a dependency in either
direction beyond the one port:

```ts
import type { ResourceAttributeResolver } from "@verixa/authorization";

// Implemented inside packages/verification, not packages/authorization.
const verificationCaseResolver: ResourceAttributeResolver = {
  async resolve(resourceId) {
    const verificationCase = await verificationCaseRepository.findById(asId(resourceId));
    return {
      ownerId: verificationCase.ownerId,
      status: verificationCase.status,
    };
  },
};

// Registered from composition-root wiring (Issue 157), once at startup.
registry.register("verificationCase", verificationCaseResolver);
```

At evaluation time, the engine (Issue 146) calls
`registry.resolve("verificationCase", resourceId)` and gets back a plain
`ResourceAttributes` map — it never imports anything from
`packages/verification` itself. This is the dependency direction
`ARCHITECTURE.md` §4 requires: contexts that own resources depend on and
register with `packages/authorization`; `packages/authorization` never
depends on them.

### Why a registry, not a lookup table of imports

The alternative — `packages/authorization` importing each context's
repository directly and switching on resource type — would work, but it
inverts the dependency graph specified in `ARCHITECTURE.md` §4: the
authorization context (which every other context needs to call into for
`AuthorizeAction`, Issue 153) would end up depending on all of them,
creating exactly the import cycle that architecture forbids. The registry
pattern keeps `packages/authorization` at the bottom of the dependency
graph: it defines a port, and everyone else implements and registers
against it.

### Unknown resource types fail loudly

`registry.resolve(resourceType, resourceId)` throws
`UnknownResourceTypeError` — naming the unresolved `resourceType` — rather
than resolving to `undefined` or an empty attribute set. A policy silently
evaluating with no resource attributes at all is a much more dangerous
failure mode than an exception: depending on how the policy is written, an
empty attribute set can make a `DENY` rule fail to match and fall through to
an unrelated `PERMIT`, silently over-granting. Registration bugs (a new
resource type added to a policy target without a matching resolver
registered anywhere) should surface immediately in tests and staging, not
manifest later as an authorization bug that looks like correct code
enforcing an incorrect policy — see `docs/security/threat-model-abac.md`
(Issue 159) once it exists.

### Registering twice for the same resource type

`register` overwrites rather than throwing on a duplicate registration for
the same resource type. Composition-root wiring runs once, in a fixed
order, at process startup — a second registration in that context is far
more likely to be a deliberate override (test setup swapping in a fake
resolver) than a bug worth crashing startup over.

## Attribute model

`AttributeContext` (`packages/authorization/domain/value-objects/attribute-context.ts`,
Issue 144) is the shape every condition is evaluated against: four typed
bags — `subject`, `resource`, `action`, `environment` — the same
categorization NIST SP 800-162 uses, so the vocabulary is legible to anyone
who already knows ABAC theory.

```ts
const context = AttributeContext.create({
  subject: { id: "user-1", role: "admin" },
  resource: { ownerId: "user-2", sensitivity: "high" },
  action: { name: "read" },
  environment: { requestedAt: new Date() },
});

context.get("subject", "role"); // "admin"
context.get("subject", "nonexistent"); // undefined — never throws
context.resolve("resource.ownerId"); // "user-2" — the dotted-path form Condition.comparison's `attribute` field uses
```

A missing attribute resolves to `undefined`, never throws — both `get` and
`resolve` are total functions over any category/key or dotted path,
including one that names a category nothing supplied a bag for (it's simply
empty) or doesn't match any of the four categories at all (`resolve`
returns `undefined` rather than guessing). This is what lets the evaluation
engine below treat "attribute wasn't supplied" as an ordinary, defined
outcome (a comparison that evaluates to `false`) instead of a special case
it has to guard against.

_Attribute sourcing_ — how each bag actually gets populated from Identity
records, request claims, and resource lookups (this doc's resource-attribute
section above covers the last of those) — is `AttributeProvider`'s job,
Issue 145, not yet built.

## Evaluation semantics

`evaluateCondition` (`packages/authorization/domain/services/policy-evaluation-engine.ts`,
Issue 146) is a pure function: no I/O, no repository calls, walking a
`Condition` tree against an `AttributeContext` and returning a `boolean`.
Purity is what makes exhaustive branch-coverage testing of authorization
logic tractable — an evaluator that can also fail on a network call has a
failure mode no unit test can exercise deterministically.

- **Short-circuiting**: `AND` uses `Array.prototype.every`, `OR` uses
  `Array.prototype.some` — both bail out of the remaining operands as soon
  as the overall result is decided, so a comparison later in an `AND` never
  runs once an earlier one is `false` (verified directly in
  `policy-evaluation-engine.spec.ts` via a spy operand that must not be
  read).
- **Missing attributes evaluate to `false`**, never throw — a comparison
  against an attribute nobody supplied is the same "this rule doesn't
  apply" outcome as one that resolved and didn't match, not a distinct
  error condition the caller has to guard against.
- **Type mismatches evaluate to `false`**, not coerced — comparing a number
  operator (`lt`/`lte`/`gt`/`gte`) against a non-numeric, non-`Date`
  attribute, or `eq`/`neq` against mismatched array-vs-scalar shapes, never
  silently succeeds via implicit coercion. This is the same rationale
  Issue 147's operator library will formalize further; this evaluator
  anticipates it minimally so it's usable today.

`evaluateRule` evaluates a `Rule`'s condition alone — it does not consult
`rule.effect`. Turning "did this rule's condition match" into a
`PERMIT`/`DENY`/`NOT_APPLICABLE` outcome is the combining-algorithm layer's
job, covered next.

## Combining algorithms

A policy can have several rules, and a resource type can have several
applicable policies — `combining-algorithms.ts` (Issue 148) reduces all of
their outcomes to one final decision. `deriveRuleOutcomes` maps each rule to
`rule.effect` if its condition matched, `NOT_APPLICABLE` otherwise; a
`CombiningAlgorithm` then reduces the full outcome list:

| Algorithm                                                                        | Rule                                                       | When to use it                                                                                                        |
| -------------------------------------------------------------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `denyOverrides` (**system default**, see `docs/security/authorization-model.md`) | any `DENY` wins over any `PERMIT`                          | Safety-favoring; one applicable deny should never be overridable by a more permissive rule elsewhere in the same set. |
| `permitOverrides`                                                                | any `PERMIT` wins over any `DENY`                          | Policy sets designed to be permissive-by-default.                                                                     |
| `firstApplicable`                                                                | the first non-`NOT_APPLICABLE` outcome wins, in rule order | Rule _order_ is meaningful and intentional — the other two algorithms are order-independent.                          |

All three return `NOT_APPLICABLE` when every input outcome is
`NOT_APPLICABLE` — "nothing had an opinion" is preserved rather than
defaulted to a `PERMIT` or `DENY` here; `AuthorizationService`
(`docs/security/authorization-model.md`) is where a fail-closed default is
actually applied, one layer up, once RBAC's opinion (or lack of one) is
also known.

These names are lifted directly from the XACML standard's
combining-algorithm vocabulary rather than invented — reusing established
names lets contributors bring prior ABAC knowledge to this code instead of
re-learning Verixa-specific terminology for a well-understood concept.
