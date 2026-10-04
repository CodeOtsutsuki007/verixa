# Integrating a Verification Provider

How to plug a third-party identity-verification vendor (or nothing at all)
into the verification workflow.

Implementation: the port is
`packages/verification/application/ports/verification-provider.ts`, the
normalized result is
`packages/verification/application/dtos/provider-check-result.ts`, and the
shipped default adapter is
`packages/verification/infrastructure/providers/manual-review-provider.ts`.

## The shape

```ts
export interface VerificationProvider {
  checkDocument(evidence: Evidence): Promise<ProviderCheckResult>;
  checkLiveness(evidence: Evidence): Promise<ProviderCheckResult>;
}
```

`ProviderCheckResult` is a plain value: an `outcome` of
`passed` / `failed` / `inconclusive`, a `confidenceScore` normalized to `0..1`,
and a `providerRawRef` that is stored opaquely so a dispute can be traced back
to the vendor's own record.

## Why the port exists

Verixa is infrastructure meant to be reused across projects. Hard-coding one
vendor's SDK into a use case would (a) violate the hexagonal dependency rule
the rest of the codebase follows and (b) lock every consumer into that vendor,
because the vendor's types would be part of the application layer's public
shape.

So the application layer names only `VerificationProvider`. Which concrete
implementation is in play is decided in the composition root. Swapping vendors
is a one-file change — this is the Adapter pattern doing exactly what it is
for.

### The alternative that was rejected: one method with a `kind` argument

`check(evidence, kind)` would have been fewer lines, and it is the obvious
refactor. It was rejected because document checking and liveness checking
already differ in ways that are growing: liveness is where a vendor's passive
anti-spoofing signal lands, documents are where OCR and authenticity checks
land, and any real vendor exposes them as separate endpoints with separate
error taxonomies and separate pricing. Collapsing them would mean every
adapter immediately branches on `kind` — at which point the interface is
lying about being uniform. Two named methods keep the divergence visible at
the port instead of hidden behind a flag.

## The contract every adapter must fulfil

Written out here because the contract comments _are_ what makes two adapters
interchangeable — a signature is not a promise.

1. **Return a normalized result, never a vendor type.** No vendor field names,
   error codes, or SDK classes may appear in the returned value. If a vendor
   answer cannot be mapped, return `inconclusive`.
2. **Say `inconclusive` when you cannot decide.** A timeout, a low-confidence
   score, a rule the vendor has no opinion on — none of those are `passed` or
   `failed`. This is the single most important rule: `inconclusive` is what
   routes a case to a human, and collapsing it into a verdict is how a person
   is wrongly denied or a fraudster wrongly admitted.
3. **Never decide the request.** A provider holds an opinion, not authority.
   It does not call `approve`/`reject` or move the request to a terminal state.
   `RunAutomatedCheck` (Issue 172) records the result and sends the case to
   `in_review` regardless of the outcome, and only a human makes the terminal
   decision in this phase.
4. **Do not throw for a negative result.** `failed` is an expected answer.
   Throw or reject only when the _check itself_ could not be completed;
   callers treat that as an infrastructure failure and still route the case to
   a human.
5. **Fetch evidence bytes through `EvidenceStorage`.** `evidence.storageRef` is
   an opaque pointer — never assume a filesystem path or a public URL.
6. **Treat the vendor response as untrusted input.** Validate through
   `ProviderCheckResult.isValid` before returning it.

## The default: `ManualReviewProvider`

The shipped default is a **null object**: both checks return `inconclusive`,
and every request lands in the reviewer queue. That is deliberately not a
stub. A verification workflow that only works once you have signed a contract
with a commercial vendor is not much of an open-source project — a
contributor cloning the repo, or an operator evaluating it, could not run the
flow end to end. With this as the default, the manual-review experience — the
part this phase is actually about — is fully exercisable with no third-party
account and no API key.

The default returns `inconclusive` rather than `passed` on purpose. A null
object that said `passed` would be a security hole wearing a default's
clothes: every deployment that forgot to configure a real vendor would
auto-pass every identity check. "No automated judgment was made" is the
honest answer, and it is exactly the answer that routes to a human. Doing
nothing, visibly, is the safe default.

## Writing a real adapter

1. Implement `VerificationProvider`.
2. Map each vendor outcome to `passed` / `failed` / `inconclusive`. When in
   doubt, `inconclusive`.
3. Run the shared contract suite against your adapter:

   ```ts
   import { verificationProviderContract } from "@verixa/verification/..."; // see below
   verificationProviderContract(() => new MyVendorProvider(config));
   ```

   The contract is `packages/verification/infrastructure/testing/contracts/verification-provider.contract.ts`.
   It asserts only the invariants every adapter shares — a well-formed result
   from both methods, for every evidence type — never a particular verdict,
   because a contract that demanded one answer would only fit one vendor. The
   same one-suite-many-implementations pattern the repository ports use is
   described in `docs/guides/testing.md`.

4. Add vendor-specific behaviour tests of your own. The contract proves your
   adapter is _substitutable_; it cannot prove its verdicts are _right_.
5. Wire it in the composition root in place of `ManualReviewProvider`.

## What is deliberately not handled here

Provider configuration (API keys, endpoints, retry policy) is the adapter's
own concern and belongs in the composition root, not in the port. Automated
_pacing_ of vendor calls, per-subject throttling, and cost controls are Phase
15 concerns. Storing the raw vendor payload is an audit/evidence-storage
question (Issue 166), not a provider one — the port deliberately carries only
an opaque `providerRawRef`.
