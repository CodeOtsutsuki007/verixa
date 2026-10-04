import { createHash } from "node:crypto";

import { Keypair } from "@stellar/stellar-sdk";
import { Result } from "@verixa/shared-kernel";
import { beforeAll, describe, expect, it } from "vitest";

import { LocalTransactionSigner } from "../signing/local-transaction-signer.js";
import { hashAnchorContract } from "../testing/contracts/hash-anchor.contract.js";

import { StellarHashAnchor } from "./stellar-hash-anchor.js";

/**
 * Exercises the real Stellar testnet: generates a throwaway account, funds it
 * from friendbot, and submits actual transactions to a real ledger.
 *
 * Excluded from the default `pnpm test` run (see `vitest.config.ts`) because
 * it needs network access and takes tens of seconds — run it deliberately
 * with `pnpm stellar:testnet`. It is not a unit test and shouldn't pretend to
 * be one; what it buys is the one thing the in-memory fake structurally
 * cannot prove, which is that the Stellar mechanics themselves are correct:
 * that a 32-byte MEMO_HASH really does round-trip through submission and
 * Horizon retrieval unchanged.
 *
 * Testnet only. Nothing here should ever be pointed at the public network —
 * these accounts are disposable and their secret keys are generated fresh
 * per run, in memory, and never persisted.
 */

const FRIENDBOT_URL = "https://friendbot.stellar.org";
const HORIZON_URL = "https://horizon-testnet.stellar.org";
const FUNDING_TIMEOUT_MS = 180_000;
const TRANSACTION_TIMEOUT_MS = 120_000;
const ACCOUNT_VISIBILITY_ATTEMPTS = 20;
const ACCOUNT_VISIBILITY_DELAY_MS = 1000;
const FETCH_ATTEMPTS = 5;
const FETCH_TIMEOUT_MS = 30_000;

const delay = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

/**
 * `fetch` with retries and an explicit timeout.
 *
 * Node's global fetch applies a 10-second *connect* timeout that isn't
 * configurable per call, and public infrastructure — friendbot and Horizon
 * are free, shared, and unthrottled — intermittently exceeds it. Retrying a
 * transient connection failure is the correct behavior for a test that
 * talks to a public testnet, not a workaround: a single dropped TCP
 * handshake says nothing about whether the code under test is right.
 */
async function fetchWithRetry(url: string): Promise<Response> {
  let lastError: unknown;

  for (let attempt = 1; attempt <= FETCH_ATTEMPTS; attempt += 1) {
    try {
      return await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    } catch (error) {
      lastError = error;
      if (attempt < FETCH_ATTEMPTS) {
        // Linear backoff: the failure mode here is a momentarily slow or
        // saturated public endpoint, which clears in seconds.
        await delay(attempt * 2000);
      }
    }
  }

  throw new Error(
    `Could not reach ${url} after ${String(FETCH_ATTEMPTS)} attempts: ${
      lastError instanceof Error ? lastError.message : String(lastError)
    }`,
  );
}

/**
 * Funds a fresh testnet account and waits until Horizon can actually see it.
 *
 * The wait is not optional. Friendbot returns HTTP 200 as soon as it has
 * *submitted* the funding transaction, which is a moment or two before the
 * new account is queryable — so building a transaction immediately after a
 * 200 intermittently fails with "account not found." That's a genuine race,
 * not flakiness to paper over with a blanket sleep: polling until the
 * account resolves waits exactly as long as it needs to and no longer.
 */
async function createFundedTestnetAccount(): Promise<Keypair> {
  const keypair = Keypair.random();

  const funding = await fetchWithRetry(
    `${FRIENDBOT_URL}?addr=${encodeURIComponent(keypair.publicKey())}`,
  );
  if (!funding.ok) {
    throw new Error(`Friendbot funding failed with HTTP ${String(funding.status)}.`);
  }

  for (let attempt = 0; attempt < ACCOUNT_VISIBILITY_ATTEMPTS; attempt += 1) {
    const response = await fetchWithRetry(`${HORIZON_URL}/accounts/${keypair.publicKey()}`);
    if (response.ok) {
      return keypair;
    }
    await delay(ACCOUNT_VISIBILITY_DELAY_MS);
  }

  throw new Error("Funded testnet account never became visible on Horizon.");
}

/**
 * One funded account for the whole file, created lazily on first use.
 *
 * Each account costs a friendbot round-trip plus ledger-close latency, and
 * nothing here depends on account isolation — the assertions are about
 * anchoring behavior. Sharing one account roughly halves the network work
 * and, with it, the exposure to transient public-endpoint failures.
 */
let sharedAccount: Promise<Keypair> | undefined;

function getSharedFundedAccount(): Promise<Keypair> {
  sharedAccount ??= createFundedTestnetAccount();
  return sharedAccount;
}

describe("StellarHashAnchor (live testnet)", () => {
  let anchor: StellarHashAnchor;

  beforeAll(async () => {
    const keypair = await getSharedFundedAccount();
    anchor = new StellarHashAnchor({
      signer: new LocalTransactionSigner(keypair.secret()),
      network: "testnet",
    });
  }, FUNDING_TIMEOUT_MS);

  it(
    "anchors a hash and reads back the identical digest from the ledger",
    async () => {
      const hash = createHash("sha256")
        .update(`chain-tip-${String(Date.now())}`)
        .digest("hex");

      const anchored = await anchor.anchor(hash);
      expect(Result.isOk(anchored)).toBe(true);
      if (!Result.isOk(anchored)) return;

      // A real Stellar transaction hash: 64 hex characters.
      expect(anchored.value.anchorRef).toMatch(/^[0-9a-f]{64}$/u);
      expect(anchored.value.network).toBe("stellar:testnet");

      const verified = await anchor.verify(hash, anchored.value.anchorRef);
      expect(Result.isOk(verified) && verified.value).toBe(true);
    },
    TRANSACTION_TIMEOUT_MS,
  );

  it(
    "refuses to verify a tampered hash against a real on-chain anchor",
    async () => {
      const original = createHash("sha256")
        .update(`original-${String(Date.now())}`)
        .digest("hex");
      const tampered = createHash("sha256")
        .update(`tampered-${String(Date.now())}`)
        .digest("hex");

      const anchored = await anchor.anchor(original);
      if (!Result.isOk(anchored)) throw new Error("fixture setup failed");

      const verified = await anchor.verify(tampered, anchored.value.anchorRef);

      // The whole point of the design, proven against a real ledger: a
      // rewritten audit chain yields a different tip hash, which no longer
      // matches the commitment already recorded on Stellar.
      expect(Result.isOk(verified) && verified.value).toBe(false);
    },
    TRANSACTION_TIMEOUT_MS,
  );

  it(
    "reports a verification failure for a transaction that does not exist",
    async () => {
      const hash = createHash("sha256").update("never-anchored").digest("hex");

      const verified = await anchor.verify(hash, "f".repeat(64));

      expect(Result.isErr(verified)).toBe(true);
    },
    TRANSACTION_TIMEOUT_MS,
  );
});

// The same behavioral contract the in-memory fake passes, run against the
// real ledger — proving the fake every other test relies on is faithful.
describe("StellarHashAnchor contract compliance (live testnet)", () => {
  let sharedAnchor: StellarHashAnchor;

  beforeAll(async () => {
    const keypair = await getSharedFundedAccount();
    sharedAnchor = new StellarHashAnchor({
      signer: new LocalTransactionSigner(keypair.secret()),
      network: "testnet",
    });
  }, FUNDING_TIMEOUT_MS);

  // Every contract case reuses one funded account rather than creating its
  // own: each new account costs a friendbot round-trip plus ledger-close
  // latency, and the contract's assertions are about anchoring behavior, not
  // account isolation.
  hashAnchorContract(() => sharedAnchor);
});
