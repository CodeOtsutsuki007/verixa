import {
  Account,
  Asset,
  BASE_FEE,
  Keypair,
  Memo,
  Networks,
  Operation,
  TransactionBuilder,
} from "@stellar/stellar-sdk";
import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { SigningError } from "../../application/ports/transaction-signer.js";
import { KmsTransactionSigner } from "../signing/kms-transaction-signer.js";
import { LocalTransactionSigner } from "../signing/local-transaction-signer.js";
import { fakeKmsClient } from "../testing/fake-kms-sign-client.js";

import { StellarHashAnchor } from "./stellar-hash-anchor.js";

/**
 * Offline tests for the credential surface of the Stellar adapter — the part
 * Issue #129 changed.
 *
 * The anchoring path itself needs a funded account and a reachable Horizon, so
 * `stellar-hash-anchor.testnet.spec.ts` covers it against the testnet and is
 * excluded from default CI. What *is* testable here, and what matters most, is
 * the boundary: which operations require a signer, what happens when one is
 * missing, and whether bytes produced across the `TransactionSigner` seam are
 * accepted by the SDK without the key ever being present in this process.
 *
 * Seeds are generated at runtime rather than committed: a fixture that looks
 * like a real key is a secret waiting to be mistaken for one, and the
 * contributor checks workflow fails the build on that shape alone.
 */
describe("StellarHashAnchor signing boundary", () => {
  describe("configured without a signer", () => {
    // The reason the constructor no longer demands a key: verification is meant
    // to be runnable by an auditor with no credentials at all, and the CLI used
    // to invent a throwaway keypair to satisfy a constructor that never needed
    // one. A credential-shaped fiction in a verify-only path is a documentation
    // bug waiting to become a production one.
    it("constructs", () => {
      expect(() => new StellarHashAnchor({ network: "testnet" })).not.toThrow();
    });

    it("refuses to anchor, and says why", async () => {
      const anchor = new StellarHashAnchor({ network: "testnet" });
      const result = await anchor.anchor("a".repeat(64));

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.message).toContain("without a signer");
        expect(result.error.message).toContain("verify");
      }
    });

    it("does not know an account id", async () => {
      const result = await new StellarHashAnchor({ network: "testnet" }).accountId();

      expect(Result.isErr(result)).toBe(true);
      if (Result.isErr(result)) {
        expect(result.error.message).toContain("No signer");
      }
    });
  });

  describe("configured with a signer", () => {
    it("reports the signer's account", async () => {
      const keypair = Keypair.random();
      const anchor = new StellarHashAnchor({
        signer: new LocalTransactionSigner(keypair.secret()),
        network: "testnet",
      });

      const result = await anchor.accountId();

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value).toBe(keypair.publicKey());
      }
    });

    it("turns a signer failure into an AnchorError", async () => {
      // A signer that cannot name its account cannot build a transaction either,
      // and the reason must reach the operator intact: "the key service is
      // unreachable" and "insufficient funds" call for very different fixes.
      const failure = new SigningError("the key service is unreachable");
      const signer: FailOnlySigner = {
        accountId: () => Promise.resolve(Result.err(failure)),
        sign: () => Promise.resolve(Result.err(failure)),
        describe: () => "failing:test",
      };

      const anchor = new StellarHashAnchor({ signer, network: "testnet" });

      const account = await anchor.accountId();
      expect(Result.isErr(account)).toBe(true);
      if (Result.isErr(account)) {
        expect(account.error.message).toContain("key service is unreachable");
      }

      const anchored = await anchor.anchor("b".repeat(64));
      expect(Result.isErr(anchored)).toBe(true);
      if (Result.isErr(anchored)) {
        expect(anchored.error.message).toContain("key service is unreachable");
      }
    });
  });

  /**
   * The seam this issue exists to create, tested against the real SDK rather
   * than a mock of it.
   *
   * `TransactionBuilder` produces a digest, a key service signs those 32 bytes
   * somewhere else, and the resulting signature has to be attachable to the
   * transaction. `addSignature` verifies before attaching, so this is also the
   * assertion that a remote signer's output is *the right kind of bytes* — a
   * DER-wrapped signature from the same key fails here, which is precisely the
   * failure `KmsTransactionSigner` refuses to pass on.
   */
  it("accepts a signature produced outside this process", async () => {
    const kms = fakeKmsClient();
    const signer = new KmsTransactionSigner({
      keyId: "alias/verixa-anchor",
      accountId: kms.keypair.publicKey(),
      client: kms.client,
    });

    const source = new Account(kms.keypair.publicKey(), "1");
    const transaction = new TransactionBuilder(source, {
      fee: BASE_FEE,
      networkPassphrase: Networks.TESTNET,
    })
      .addOperation(
        Operation.payment({
          destination: kms.keypair.publicKey(),
          asset: Asset.native(),
          amount: "0.0000001",
        }),
      )
      .addMemo(Memo.hash("c".repeat(64)))
      .setTimeout(60)
      .build();

    const signature = await signer.sign(transaction.hash());
    if (!Result.isOk(signature)) throw new Error("signing failed");
    expect(signature.value.byteLength).toBe(64);

    expect(() =>
      transaction.addSignature(
        kms.keypair.publicKey(),
        Buffer.from(signature.value).toString("base64"),
      ),
    ).not.toThrow();
    expect(transaction.signatures).toHaveLength(1);

    // The key never crossed the boundary: the client was asked to sign a digest
    // and nothing else.
    expect(kms.requests()).toHaveLength(1);
    expect(kms.requests()[0]?.digest.byteLength).toBe(32);
  });
});

/** A signer double that only fails, so no network and no key material are involved. */
interface FailOnlySigner {
  accountId(): Promise<Result<string, SigningError>>;
  sign(digest: Uint8Array): Promise<Result<Uint8Array, SigningError>>;
  describe(): string;
}
