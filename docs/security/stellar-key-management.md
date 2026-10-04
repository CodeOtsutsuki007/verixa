# Stellar Anchoring Key Management

Who holds the key that signs anchoring transactions, how it is configured, and
how to change it. Applies to `@verixa/stellar-anchor`. Issue #129.

## Summary for reviewers

`STELLAR_ANCHOR_SECRET_KEY` is no longer the production signing path. The
adapter asks a `TransactionSigner` for a signature over 32 bytes and never
receives a private key. Two implementations ship: one backed by a key service,
one that reads a seed from the environment and is explicitly a development
convenience.

## Why the environment variable was removed

The previous arrangement read an `S...` Stellar secret key from the process
environment into a `Keypair` at startup. That is not key management; it is key
_placement_. Anything that can read the environment can read the secret:

- a sidecar or any other code in the same container
- `kubectl describe pod`, `docker inspect`, and every UI built on them
- a crash dump or a heap snapshot taken by an APM agent
- one misconfigured log line, or a debug logger that prints `process.env`
- the CI system that dumps env on a failed job
- every backup of every deployment manifest, indefinitely

On mainnet the account holds real XLM and its signatures mint
publicly-verifiable claims about this deployment's audit history. Both are
things an attacker can turn into profit, and the ledger keeps the evidence
forever.

With a signing interface, the process asks for a signature over specific bytes
and gets one. There is nothing in the address space to leak.

## The port

```ts
interface TransactionSigner {
  accountId(): Promise<Result<string, SigningError>>;
  sign(digest: Uint8Array): Promise<Result<Uint8Array, SigningError>>;
  describe(): string;
}
```

Five guarantees every implementation owes the caller are written out in
`packages/stellar-anchor/application/ports/transaction-signer.ts` and asserted
by a shared contract suite
(`infrastructure/testing/contracts/transaction-signer.contract.ts`):

1. The private half never enters this process.
2. `sign` covers **exactly** the bytes given — no re-hashing, no re-encoding.
3. No key material appears in `describe()`, `toJSON()`, `toString()`, or any
   `SigningError.message`.
4. Upstream failures are summarised, never echoed as a raw response body — and
   not attached as `error.cause` either. `JSON.stringify` hides a cause, a
   chain-walking logger does not, and a vendor SDK's error for a failed signing
   call routinely carries the request, which carries the digest. The error
   _name_ is what survives into the message.
5. `accountId()` is stable for the lifetime of an instance.

The contract takes a `secretMarker` — a substring guaranteed to appear in
whatever key material the implementation holds — and asserts it never reaches
any string the object can emit. Run against the local signer with a real seed,
and against the KMS signer with a marker the adapter provably does not have.

### Why the digest rather than the transaction

Passing a `Transaction` would drag `@stellar/stellar-sdk` into the application
layer and make every consumer depend on Stellar types — the inversion
`HashAnchor` exists to avoid. The bytes to sign are a SHA-256 digest regardless
of which chain or library produced them.

The practical consequence is a good one: `addSignature` verifies before
attaching, so a signer that returned bytes for a different transaction fails
locally instead of at submission, after a fee was spent.

## Implementations

### `KmsTransactionSigner` — production

Delegates to a key service through a one-method `KmsSignClient`:

```ts
const signer = new KmsTransactionSigner({
  keyId: "alias/verixa-anchor-mainnet",
  accountId: "G...",
  client: kmsClient, // your transport
});
```

It holds an _identifier_ and a _public_ account id. Both are safe in logs and
in a config dump, and the contract proves it.

The `KmsSignClient` seam is deliberately tiny, and the cloud SDK deliberately
is not a dependency of this package: the same reason the audit repositories
take a structural `AuditDelegate` rather than importing Prisma. Keeping vendor
clients out of a security-critical package means a credential-chain change
cannot silently alter what the signer does.

**Signature encoding.** The port returns a raw 64-byte Ed25519 signature, which
is what `Transaction.addSignature` needs. Several key services return DER-wrapped
signatures for some of their algorithms; unwrapping that is the transport
adapter's job, at the vendor boundary, where the encoding is known.
`KmsTransactionSigner` refuses anything that is not 64 bytes rather than
forwarding plausible-looking bytes that will fail on submission — a wrong-shaped
signature surfacing as a Stellar "failed signature verification" three steps
later is a much worse debugging experience than an error at the call.

Configured with `STELLAR_SIGNING_BACKEND=kms`. Because the transport is built by
the deployment (its own credential chain, its own region, its own SDK),
`buildContainer` takes it as an argument:

```ts
const container = buildContainer(undefined, { signer });
```

Setting `STELLAR_SIGNING_BACKEND=kms` without supplying a signer is a **startup
failure**, not a silent downgrade to "anchoring off". Discovering during an
audit that hardware-backed signing was configured but never wired is the worst
available outcome.

### `LocalTransactionSigner` — development and testnet only

Holds a `Keypair` built from a seed. Its name, its `describe()` output
(`local:G...`), and the documentation all say so.

It remains because a testnet experiment should not require a KMS, and because
the alternative — no local path at all — pushes operators to write their own
worse version. Two guards keep it out of production:

- the composition root refuses to sign on the **public** network with an
  environment-derived key unless `STELLAR_ALLOW_LOCAL_SIGNING=1` is set
  explicitly;
- the CLI applies the same refusal, and no longer constructs a throwaway
  keypair to satisfy a constructor that never needed one. Verification needs
  zero credentials, and `StellarHashAnchor` now accepts that.

## Configuration

| Variable                      | Purpose                                                                                                                                                 |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `STELLAR_NETWORK`             | `testnet` (default) or `public`. Selects the Horizon endpoint _and_ the network passphrase, which is what makes a testnet signature invalid on mainnet. |
| `STELLAR_SIGNING_BACKEND`     | `kms` or `local`. Unset means `local` if a seed is present, otherwise anchoring is disabled.                                                            |
| `STELLAR_ANCHOR_SECRET_KEY`   | Seed for the `local` backend. **Never** on a public-network deployment.                                                                                 |
| `STELLAR_ALLOW_LOCAL_SIGNING` | `1` to permit the `local` backend on the public network. An explicit statement that you accept the risk above.                                          |
| `STELLAR_ANCHOR_ACCOUNT_ID`   | The `G...` account a `kms` signer stands for; supplied by the deployment when it builds the signer.                                                     |

Verification needs **none of these except `STELLAR_NETWORK`**. An auditor — or
a regulator, or a suspicious user — can confirm an anchor with nothing but the
hash and the transaction reference, which is what makes the guarantee mean
anything. See [`docs/guides/stellar-anchoring.md`](../guides/stellar-anchoring.md).

## Rotation

Asymmetric keys in a key service are generally **not** rotatable in place, and
a Stellar account's key pair is fixed for the life of the account. So rotation
here is not "swap the key material"; it is **move to a new account**, and the
old anchors must keep verifying.

They do. An anchor record stores the transaction hash; verification fetches
that transaction from the ledger and reads its memo. Neither depends on the
signing account still existing or still being the one you use. History is
append-only on someone else's ledger — which is the entire point of anchoring
there.

### Planned rotation

1. **Create the new key** in the key service. Do not enable anything yet.
2. **Create and fund the new Stellar account** from it. Record its `G...` id.
   See [`docs/runbooks/stellar-mainnet-cutover.md`](../runbooks/stellar-mainnet-cutover.md)
   for funding amounts and the testnet rehearsal of the same steps.
3. **Verify the new key signs what you expect**, off the air: ask the signer for
   a signature over a fixed digest and check it against the new public key.
   `transactionSignerContract` does exactly this.
4. **Deploy** with the new `keyId` and `accountId`. The adapter pins the account
   id at construction, so a re-pointed alias without a redeploy produces a
   startup failure rather than transactions signed by a key you no longer
   expect — which is the reason to prefer pinning over alias indirection.
5. **Anchor a hash and verify it from the public ledger** before you call the
   rotation done. An operator who skips this has no evidence the new path works.
6. **Leave the old account alone.** Do not delete or merge it. Its transactions
   are the evidence for every anchor recorded before this rotation, and its
   account id is stored in `anchor_record`. Merging moves the remaining balance
   and destroys nothing on the ledger, but there is no benefit and it removes
   the ability to submit a final anchor under a key that is merely
   compromised-suspicious rather than confirmed stolen.
7. **Disable the key's sign permission** in the key service once step 5 is
   confirmed. Disabling is reversible; deletion of an asymmetric KMS key is not,
   and you want the reversible option until the new path has run for a while.

### Emergency rotation (key suspected compromised)

A compromised anchoring key is not a financial emergency alone — the attacker
can also publish **false** anchors under an account auditors trust.

1. **Disable the key in the key service first.** One API call, immediate, and it
   stops further signing without touching funds.
2. **Stop anchoring** (`STELLAR_SIGNING_BACKEND` unset, or the scheduled job
   paused). Do not keep anchoring with a key you distrust: a fraudulent anchor
   committed under a trusted account is worse than a gap in the log.
3. **Execute the planned rotation above** with a fresh account.
4. **Drain the old account** to a fresh, unrelated address — not to the new
   anchoring account, so the new one's history stays clean of the old one's.
5. **Re-anchor the current chain head under the new account** and record it. The
   old anchors remain valid evidence of what was true when they were made.
6. **Record the incident.** The window between the last trustworthy anchor and
   the re-anchor is exactly the window a rewrite could hide inside; an auditor
   asking about that window needs a dated answer, not a shrug.

### Cadence

No universal answer. Two considerations: the key never leaves the signer, so the
exposure surface is the key service's access log rather than a file on a server;
and each rotation invalidates every _monitoring_ configuration that names the
account id. Annual, plus immediately on any personnel or access change that
touches the key service, is a reasonable default for an account whose entire job
is signing 32-byte digests.

## Rejected alternatives

**Fetch the key from a secrets manager at startup and sign in-process.**
Better than a plain environment variable — access is audited and the value is
not in the manifest — but the secret still lands in the process's memory, which
is the thing being protected. It rotates the _storage_ and not the _exposure_.
For many deployments this is a reasonable intermediate step; it is not what this
port is for.

**Sign with a locally-held HMAC / symmetric key and anchor with a separate
account.** Rejected: it splits who can _create_ an anchor from who _owns_ it,
so a leaked symmetric key lets an attacker forge commitments attributable to an
account they cannot even spend from. A signature is the right primitive because
it binds the commitment to the account an auditor already knows.

**One key per anchored transaction.** Rejected: it multiplies funded accounts
(each needs XLM and a minimum balance) and destroys the aggregation an auditor
uses — "show me every anchor from account G…" is a query, and one-hundred
accounts turns it into a reconciliation exercise.

**Envelope-encrypt the seed and keep it in config.** Rejected. It is obfuscation
with extra steps: anything that can decrypt at runtime has the key at runtime.

**Point a KMS alias at a new key and leave the config alone.** Rejected — and
the reason `accountId` is pinned rather than derived per call. An alias swap
that silently changes which account signs would produce transactions that fail
to submit, and an operator would reasonably believe their audit trail was being
anchored when it was not. Failing loudly at startup is the alternative.

## Testing

- `packages/stellar-anchor/infrastructure/signing/transaction-signer.spec.ts`
  runs the contract against both implementations, plus adapter-specific failures
  (outage, wrong-shaped signature, empty digest, non-`G` account id).
- `packages/stellar-anchor/infrastructure/stellar/stellar-hash-anchor.spec.ts`
  proves the adapter works with **no** signer for verification, refuses to
  anchor without one, and accepts a signature produced outside the process.
- `stellar-hash-anchor.testnet.spec.ts` exercises the whole path against the
  live testnet and is excluded from default CI.

There is no test that asserts "the secret is absent from the serialized config"
by scanning `process.env`, because that would require putting a secret in
`process.env` in a test. Instead the assertion is stronger and local: the
signer object itself cannot produce the marker in any string, and the KMS
adapter is built from an identifier and a public key only.

## Related

- [`docs/guides/stellar-anchoring.md`](../guides/stellar-anchoring.md)
- [`docs/runbooks/stellar-mainnet-cutover.md`](../runbooks/stellar-mainnet-cutover.md)
- [`docs/adr/0003-stellar-audit-anchoring.md`](../adr/0003-stellar-audit-anchoring.md)
- [`docs/security/audit-log-integrity.md`](./audit-log-integrity.md)
