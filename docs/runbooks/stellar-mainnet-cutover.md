# Runbook: Stellar Testnet to Mainnet Anchoring Cutover

Moving a Verixa deployment's audit-log anchoring from the test network to
`public`. Issue #131.

**Owner:** whoever operates the anchoring account.
**Expected duration:** 45–90 minutes, most of it waiting on a funding
transaction and on a KMS key being created by whoever owns your cloud account.
**Blast radius:** anchoring only. Nothing in this runbook affects
authentication, authorization, or the audit log itself.
**Reversibility:** yes, at every step. The rollback is at the end.

## Before you start

Anchoring is a commitment other people can check. A cutover that leaves a
deployment writing mainnet anchors, or — worse — silently _not_ writing them
while the `anchor_record` table still fills up, breaks the one property the
subsystem has. The dry run below exists because it is the only step that
proves the wiring end to end; the runbook's test _is_ the dry run.

Checklist:

- [ ] You can log in to the cloud account that will hold the key.
- [ ] You have a way to move XLM from an exchange or an existing account.
      **There is no friendbot on mainnet.** Testnet funding is a GET request;
      mainnet funding is a withdrawal, and it costs real money.
- [ ] You know who to call when the key service is unavailable — anchoring
      stops cleanly when signing fails, and nobody gets paged by default.
- [ ] The current chain head is known and recorded: `VerifyAuditChain` prints
      it, and you will need it to prove the cutover worked.

Budget: the account needs the XLM account minimum reserve plus enough for
fees. An anchoring transaction costs 100 stroops (0.00001 XLM) in base fee, so
hourly anchoring for a year is a few hundredths of an XLM. Fund
**10–20 XLM**: enough to be unbothered for years, small enough that a
compromised key is a nuisance rather than a loss. Do not keep a working balance
in an account whose key sits in a key service you can audit but not physically
protect.

## 1. Create the mainnet key

In your key service, create an **asymmetric Ed25519** signing key. Asymmetric
KMS keys cannot be rotated in place, so the key you create here is the key for
this account's lifetime — a future rotation means a future new account
([`docs/security/stellar-key-management.md`](../security/stellar-key-management.md)).

Record the key id or alias. You will need it in step 5.

Do **not** export, wrap, or copy the private key. The point of this deployment
pattern is that the private half never enters the process that uses it.

## 2. Create and fund the mainnet account

The account is derived from the public half of that key. Get the strkey
(`G...`) from the key service's public key — your signer reports it via
`accountId()`, and any Stellar tool can convert a raw Ed25519 public key to a
strkey.

Then fund it. Two routes:

- **Exchange withdrawal** to that address. Watch for the exchange demanding a
  memo on _withdrawals to a new account_ — some require one and will reject a
  plain payment to an account it has not seen. If so, use route two.
- **Payment from an existing account** you already control. The receiving
  account does not need to exist first: a payment of at least the account
  minimum creates it. Confirm the current base reserve rather than trusting a
  number in a document; it changed in 2023 and it can change again by protocol
  vote.

The account must be **created by that payment**, not by you. There is no
create-account operation to run first.

```bash
# Confirm the account exists and holds what you sent.
curl -s "https://horizon.stellar.org/accounts/G...REPLACE..." \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const a=JSON.parse(s);console.log("balances:",a.balances.map(b=>b.balance).join(", "));console.log("signers:",a.signers.length)})'
```

If that returns a 404, the funding transaction has not landed yet. Ledger close
is 4–6 seconds; a 404 after a minute means the payment failed, not that it is
slow.

## 3. Network configuration

The network is selected by one variable, and it controls **both** the Horizon
endpoint and the network passphrase:

```bash
STELLAR_NETWORK=public
```

| Variable           | Mainnet value                                                                                                                                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `STELLAR_NETWORK`  | `public`                                                                                                                                                                                          |
| Horizon endpoint   | `https://horizon.stellar.org`. There is no environment variable for it; `StellarHashAnchorOptions.horizonUrl` exists for tests, and running your own Horizon is a code change at composition time |
| Network passphrase | `Public Global Stellar Network ; September 2015` (`Networks.PUBLIC` in the SDK, applied by the adapter from `STELLAR_NETWORK`)                                                                    |
| Signing backend    | `STELLAR_SIGNING_BACKEND=kms`                                                                                                                                                                     |

The passphrase is not a separate knob and that is deliberate. Signing a
testnet-built transaction under the mainnet passphrase — or the reverse —
produces a transaction the other network rejects, and the usual symptom is an
operator who believes their audit trail is anchored on mainnet when every
submission failed. Deriving the passphrase from the same variable that selects
the endpoint makes the mismatch unrepresentable.

Do not set `STELLAR_ALLOW_LOCAL_SIGNING`. It exists so a testnet experiment can
use an environment key; on `public` it means the secret is back in the process,
which is the thing the signing port was introduced to remove. The composition
root refuses to start in that combination by default.

## 4. Dry run — on testnet, with the real code path

Run the _mainnet_ wiring against testnet first, using a second key and a
testnet account funded by friendbot. This is the step that catches everything
the previous three can get wrong: wrong key type, wrong account id, permission
missing, signature encoding.

```bash
# Testnet account from a second, throwaway key.
STELLAR_NETWORK=testnet \
STELLAR_ANCHOR_SECRET_KEY=<throwaway S... seed> \
  pnpm --filter @verixa/audit demo
```

The demo funds a testnet account from friendbot, anchors a chain head, then
reads the hash back from the public ledger and compares — exactly what a third
party would do. If it prints a verification line you can reproduce with the
CLI, the code path is correct and only the _configuration_ changes for mainnet.

Then confirm the refusal behaviour, which is the safety property you are about
to depend on:

```bash
# Must FAIL: signing with an environment seed on the public network.
STELLAR_NETWORK=public STELLAR_ANCHOR_SECRET_KEY=<any seed> \
  pnpm --filter @verixa/stellar-anchor anchor <64-hex-chars>

# Must SUCCEED with no credentials at all: verification reads public ledger
# data. Use the hash and reference the demo printed, against testnet.
STELLAR_NETWORK=testnet \
  pnpm --filter @verixa/stellar-anchor anchor verify <demo-hash> <demo-ref>
```

If the first _succeeds_ — that is, if you had to set
`STELLAR_ALLOW_LOCAL_SIGNING` to get there — stop. The guardrails are not what
you think they are, and the rest of this runbook assumes they are.

The third guardrail is in the API process rather than the CLI:
`STELLAR_SIGNING_BACKEND=kms` with no signer wired makes `buildContainer` throw
at startup. It cannot be provoked from the CLI, and it is the reason step 5
says to watch startup instead of assuming a quiet log means a working anchor.

## 5. Cutover

1. Put the deployment into whatever mode your platform uses for a controlled
   restart. Anchoring is a background job; a gap in anchors is recoverable, and
   the hash chain keeps covering every event in the meantime.
2. Configure the key service so the deployment's identity can call
   `kms:Sign` (or the equivalent) on that key, and nothing else. Signing-only
   permission is enough; `kms:GetPublicKey` and `kms:Export` are not.
3. Set the environment:

   ```bash
   STELLAR_NETWORK=public
   STELLAR_SIGNING_BACKEND=kms
   STELLAR_ANCHOR_SECRET_KEY=        # explicitly empty; the seed must be gone
   ```

   and wire the signer at composition:
   `buildContainer(undefined, { signer: new KmsTransactionSigner({ keyId, accountId, client }) })`.

4. Deploy and restart.
5. Watch startup. `STELLAR_SIGNING_BACKEND=kms` without a supplied signer is a
   **startup failure** on purpose: the alternative is a deployment that
   believes it is anchoring and is not.

## 6. Verification: prove a known hash is on the public ledger

Do not accept "no errors in the log" as evidence. Evidence is retrieving a hash
you know, from a ledger you do not control.

1. Take the chain head Verixa just anchored — from `anchor_record`, or from
   `VerifyAuditChain`.
2. Look it up by transaction hash:

   ```bash
   curl -s "https://horizon.stellar.org/transactions/<anchor-ref-from-anchor_record>" \
     | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const t=JSON.parse(s);console.log("memo_type:",t.memo_type);console.log("memo:",Buffer.from(t.memo,"base64").toString("hex"));console.log("successful:",t.successful)})'
   ```

   The printed `memo` must equal the chain head hash, lowercase hex, 64
   characters. `successful: true` matters: a failed transaction is still
   permanently visible, and its memo proves nothing about a balance change.

3. Or use the tool an auditor would use, which is the same check:

   ```bash
   STELLAR_NETWORK=public \
     pnpm --filter @verixa/stellar-anchor anchor verify <chain-head-hash> <anchor-ref>
   ```

4. Paste the transaction hash into any public Stellar explorer. If someone
   without access to your systems can confirm the commitment, the property
   holds. That independent checkability is the entire reason anchoring exists,
   so it is the thing worth demonstrating to someone else rather than only to
   yourself.

Also confirm **the old network still verifies**. Testnet anchors made before the
cutover live on testnet, and `anchor_record.network` says so:

```bash
STELLAR_NETWORK=testnet \
  pnpm --filter @verixa/stellar-anchor anchor verify <old-hash> <old-ref>
```

Verification uses whichever network the adapter is configured for, so a single
deployment that has anchored on both networks must check each record against the
network it was written to. Any tooling that summarizes anchor health should read
`anchor_record.network` rather than assuming the current configuration.

## 7. If anchoring must be disabled mid-flight

Reasons you might need this: the key service is down, the key is suspected
compromised, XLM prices moved, or you are mid-rotation and do not want two
accounts anchoring at once.

**To pause:** unset `STELLAR_SIGNING_BACKEND` (and `STELLAR_ANCHOR_SECRET_KEY`),
then restart. The composition root wires no `HashAnchor`, `AuditUseCases.anchor`
is `undefined`, and the anchoring job has nothing to run. That absence is
deliberate rather than a no-op implementation: a deployment that has not
configured anchoring must not be able to believe it has.

**What keeps working while anchoring is off:**

- The audit log still records, still chains, still verifies internally.
  Chaining is what covers per-event tampering; anchoring covers the wholesale
  rewrite.
- Verification of _existing_ anchors still works for anyone who has the
  transaction references, on the network they were made on.

**What degrades:** the window in which a rewrite would go undetected externally
widens from "since the last anchor" to "since the last anchor, whenever that
was". That is the whole cost, and it is why the pause should be short and
recorded.

**Do not** keep anchoring with a key you suspect is compromised. An attacker who
holds it can publish false anchors under the account your auditors trust, which
is strictly worse than a gap. Disable the key in the key service first — one
API call, reversible, immediate — then follow the emergency rotation in
[`docs/security/stellar-key-management.md`](../security/stellar-key-management.md).

**On resuming,** anchor the current chain head immediately and record it. The
gap between the last anchor before the pause and the first after is a period an
auditor will ask about, and a dated pair of anchors is the answer.

## 8. Rollback

Rollback is "stop anchoring on mainnet", not "undo the anchors". Transactions
already on the public ledger cannot be undone, and nothing needs undoing: an
anchor record whose reference does not resolve is a visible gap, not a silent
lie.

1. Set `STELLAR_NETWORK=testnet`, or unset `STELLAR_SIGNING_BACKEND` to disable
   anchoring entirely.
2. Restart.
3. **Leave the mainnet account and its history alone.** Those transactions are
   evidence for every anchor made during the mainnet period, and
   `anchor_record` still points at them by transaction hash. Disabling the
   key's sign permission is fine; deleting the key is not, because you may need
   to reason about what it signed.
4. Confirm the chain still verifies internally:
   `pnpm --filter @verixa/audit test` covers the chain rules, and
   `VerifyAuditChain` covers this deployment's data.
5. Note the rollback in the same place you noted the cutover. An auditor
   reconciling anchors against a chain history needs the timeline, including the
   parts that were experiments.

A rollback to _testnet_ is only meaningful as a diagnostic step: testnet anchors
prove nothing to a third party about mainnet history, and mixing the two in one
`anchor_record` table without reading `network` produces exactly the kind of
"verified successfully" that means nothing.

## Known limitations

- The composition root cannot build a `KmsSignClient` itself: the cloud SDK is
  intentionally not a dependency of `@verixa/stellar-anchor`, so the transport
  is wired by the deployment. Step 5 is a code change, not a config change.
- The anchoring scheduler itself (the periodic job that picks a chain head and
  calls `AnchorAuditLog`) is part of Phase 10's wiring and is not in this
  repository yet. Until it is, cutover means the same configuration change plus
  whoever triggers anchoring today.
- There is no automated migration of `anchor_record` between networks, and there
  should not be: a row's `network` is part of what it claims.

## Related

- [`docs/guides/stellar-anchoring.md`](../guides/stellar-anchoring.md)
- [`docs/security/stellar-key-management.md`](../security/stellar-key-management.md)
- [`docs/security/audit-log-integrity.md`](../security/audit-log-integrity.md)
- [`docs/adr/0003-stellar-audit-anchoring.md`](../adr/0003-stellar-audit-anchoring.md)
