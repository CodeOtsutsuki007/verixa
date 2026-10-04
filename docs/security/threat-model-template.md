# Threat Model Template

The format every Verixa threat model follows, and the rules that keep threat
models comparable enough to be indexed in one place
([Threat Register](threat-register.md)).

Until now each phase's threat model has invented its own layout. That was fine
for one document and stops being fine at three: a reader cannot tell whether
"Eliminated" in one model means the same thing as "Mitigated" in another, and
nobody can answer "which threats are still open across the platform?" without
reading everything. This template fixes the fields and — more importantly —
fixes what each status _means_.

## When to write one

Write a threat model for any bounded context, or any cross-cutting mechanism,
that handles credentials, tokens, authorization decisions, tenant boundaries or
audit data. Write it once the design has settled but before the phase closes,
so that every threat can name the issue that mitigates it — or be recorded as
open, which is equally useful.

A threat model is not finished when it is merged. Any pull request that adds,
removes or weakens a mitigation updates the affected entry here _and_ its row in
the register, in the same pull request. That is the rule that turns threat
modeling from a per-phase exercise into something that stays true.

## Document skeleton

Copy this, fill it in, and delete the guidance in italics.

```markdown
# Threat Model: <context or mechanism>

_One paragraph: what is being modeled, where it lives in the repo, and which
roadmap phase and issues it covers._

## Scope and assumptions

_What is in scope (entry points, stores, trust boundaries) and — just as
important — what is out of scope and why. State the attacker capabilities you
assumed: an unauthenticated internet client? an authenticated tenant user? an
operator with database access? Threats outside these assumptions are not
"mitigated", they are unexamined, and saying so prevents false confidence._

## Assets

_What is worth protecting here, in one line each (e.g. "password hashes",
"the integrity of audit history", "tenant isolation of policy data")._

## Trust boundaries and entry points

_Where untrusted input crosses into trusted code: HTTP routes, event
subscribers, database connections, external services. A diagram helps when
there are more than three._

## Threats

_One subsection per threat, grouped by STRIDE category, using the entry format
below._

## Accepted risks

_Every threat with status `accepted-risk`, with the reasoning that makes the
acceptance defensible. If the reasoning does not fit in a paragraph, the risk
probably has not been accepted — it has been postponed, and should be `open`._

## Related documentation
```

## Threat entry

Every threat has the same fields, in this order.

```markdown
#### <ID>: <short name>

- **STRIDE category:** Spoofing | Tampering | Repudiation | Information disclosure | Denial of service | Elevation of privilege
- **Actor:** who carries out the attack, and with what access
- **Entry point:** where the attack enters (route, port, table, file, process)
- **Asset:** what is harmed
- **Description:** how the attack works, concretely enough to write a test for
- **Impact:** what the attacker gains, or what the organization loses
- **Mitigation:** the control, with the file or issue that provides it
- **Verification:** the test (file and test name) that fails if the control is removed
- **Status:** mitigated | accepted-risk | open
- **Residual risk:** what remains even with the mitigation in place
```

### Field notes

**ID.** `<CONTEXT>-<STRIDE letter>-<n>`, for example `CRED-I-2` or `AUD-T-1`.
The context prefix is what lets the register hold every context's threats in
one namespace. IDs are permanent: a threat that stops applying keeps its ID
and moves to `mitigated` or is marked withdrawn, and the number is never
reused. Other documents, issues and commit messages refer to threats by ID, and
a reused ID silently changes what those references mean.

Registered prefixes: `CRED` (credentials, Phase 04), `AUD` (audit, Phase 10),
`ABAC` (policy engine, Phase 08). Add a new prefix in the register when a new
context gets its first threat model.

**STRIDE category.** Pick the _primary_ category — the one that names what the
attacker achieves. Account enumeration is Information disclosure even though it
is usually a step towards Spoofing; the later attack gets its own entry if it
needs a different mitigation.

**Actor and entry point.** These two fields are the reason this template
exists. The earlier ad-hoc format described attacks but often left implicit
_who_ could carry them out and _where_. That matters for prioritization: an
attack available to any anonymous client is a different order of problem from
one requiring database superuser access, and a mitigation that assumes the
second while the first is possible is not a mitigation.

**Verification.** A mitigation with no test is a claim. Name the test that
would fail if someone removed the control. If none exists, say "none" — that
is information a reviewer needs, not an embarrassment to omit.

## Status: three values, strictly defined

| Status          | Means                                                                                                                                                                     |
| :-------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `mitigated`     | A control exists **on the default branch today**, is wired into the running application where relevant, and a test — or a guarantee the compiler enforces — exercises it. |
| `accepted-risk` | The threat is real and deliberately not addressed further, with written reasoning a reviewer can disagree with. Revisit when the reasoning's premises change.             |
| `open`          | Anything else — including a mitigation that is designed, planned in the roadmap, or in an unmerged pull request.                                                          |

The strictness is the point, and it is the judgment call in this template worth
explaining. The rejected alternative was a richer scale (`planned`,
`in-progress`, `eliminated`, `partially mitigated`, ...), which is what the
Phase 08 ABAC model used. A richer scale reads as more precise, but in practice
every intermediate value is a way of saying "open" that sounds less alarming.
A threat whose mitigation is planned in Issue 154 is exactly as exploitable
today as one nobody has thought about; the register should say so, and put the
plan in the mitigation field where it belongs.

`eliminated` is also deliberately absent. Almost no control removes a threat
entirely — the ABAC model's own "eliminated" entries each list residual risk.
Use `mitigated`, and put what remains in **Residual risk**.

**Partial mitigations** are split, not graded. If lockout stops brute force
against one account but not credential stuffing across many, those are two
threats with two statuses, not one threat "partially mitigated". Splitting
keeps each entry's status a plain fact.

## Worked example

From the credentials context:

```markdown
#### CRED-I-1: Account enumeration through login responses

- **STRIDE category:** Information disclosure
- **Actor:** unauthenticated client on the internet
- **Entry point:** `POST /auth/login` (`apps/api/src/routes/auth.ts`)
- **Asset:** membership of the service (which email addresses have accounts)
- **Description:** submit candidate addresses with any password and compare
  the error returned for unknown addresses against the one for wrong passwords.
- **Impact:** a verified list of account holders, which makes credential
  stuffing cheaper and leaks who uses the service.
- **Mitigation:** every failure maps to `AuthenticationError` with one message;
  `AccountLockedError` is identical on the wire
  (`packages/shared-kernel/domain/errors.ts`,
  `packages/credentials/application/use-cases/authenticate-with-password.ts`).
- **Verification:** `packages/credentials/application/use-cases/authenticate-with-password.spec.ts`
- **Status:** mitigated
- **Residual risk:** response timing — tracked separately as CRED-I-2.
```

## Related documentation

- [Threat Register](threat-register.md) — every threat identified so far, with status.
- [Threat Model: Policy Engine & ABAC Evaluation](threat-model-abac.md) — the
  first published STRIDE model, whose format this template formalizes.
- [Authentication Flows](authentication-flows.md) — depth and tone to aim for
  when explaining a mitigation.
