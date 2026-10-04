import { createHash } from "node:crypto";

import { Keypair } from "@stellar/stellar-sdk";
import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { SigningError } from "../../application/ports/transaction-signer.js";
import { transactionSignerContract } from "../testing/contracts/transaction-signer.contract.js";
import { fakeKmsClient } from "../testing/fake-kms-sign-client.js";

import { KmsTransactionSigner } from "./kms-transaction-signer.js";
import { LocalTransactionSigner } from "./local-transaction-signer.js";

const KEY_ID = "alias/verixa-anchor";

describe("LocalTransactionSigner", () => {
  const keypair = Keypair.random();

  transactionSignerContract({
    createSigner: () => new LocalTransactionSigner(keypair.secret()),
    // The `S...` seed, which is what an accidental `toJSON` or interpolated error
    // would leak.
    secretMarker: keypair.secret(),
  });

  it("accepts a seed and reports the account it belongs to", async () => {
    const result = await new LocalTransactionSigner(keypair.secret()).accountId();

    expect(Result.isOk(result) && result.value).toBe(keypair.publicKey());
  });

  it("rejects a seed that is not a Stellar secret key", () => {
    expect(() => new LocalTransactionSigner("not-a-seed")).toThrow();
  });

  it("does not echo the supplied seed when it is rejected", () => {
    // The constructor is the one place a bad secret is guaranteed to be present,
    // and it throws before any `toJSON` exists — so the message itself is what a
    // stack trace would carry.
    const seed = "S".repeat(56);
    let message = "";
    try {
      new LocalTransactionSigner(seed);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).not.toContain(seed);
  });
});

describe("KmsTransactionSigner", () => {
  it("satisfies the signing contract through a fake key service", () => {
    const kms = fakeKmsClient();

    transactionSignerContract({
      createSigner: () =>
        new KmsTransactionSigner({
          keyId: KEY_ID,
          accountId: kms.keypair.publicKey(),
          client: kms.client,
        }),
      // The adapter holds no key material, so there is nothing to leak: the
      // assertions run and cannot fail, which is the point of the shape.
      secretMarker: "SECRETMATERIAL",
    });
  });

  it("never receives the private key", async () => {
    // The acceptance criterion in one assertion: whatever this object is given,
    // no seed-shaped value exists anywhere in it or in what it sends to the key
    // service. That is the whole reason the port replaced
    // `STELLAR_ANCHOR_SECRET_KEY`.
    const kms = fakeKmsClient();
    const signer = new KmsTransactionSigner({
      keyId: KEY_ID,
      accountId: kms.keypair.publicKey(),
      client: kms.client,
    });

    await signer.sign(new Uint8Array(createHash("sha256").update("head").digest()));

    const seedShape = /S[A-Za-z0-9]{55}/;
    const everything = JSON.stringify([
      signer.toJSON(),
      signer.describe(),
      // The requests carry only an identifier and a digest, both of which are
      // safe to have in a log.
      kms.requests().map((request) => ({
        keyId: request.keyId,
        digestLength: request.digest.byteLength,
      })),
    ]);

    expect(everything).not.toMatch(seedShape);
    expect(kms.requests()).toHaveLength(1);
    expect(kms.requests()[0]?.digest.byteLength).toBe(32);
  });

  it("forwards the key identifier and the digest unchanged", async () => {
    const kms = fakeKmsClient();
    const signer = new KmsTransactionSigner({
      keyId: "arn:aws:kms:eu-west-1:1:key/abc",
      accountId: kms.keypair.publicKey(),
      client: kms.client,
    });
    const digest = new Uint8Array([1, 2, 3, 4]);

    const signature = await signer.sign(digest);

    expect(Result.isOk(signature)).toBe(true);
    expect(kms.requests()[0]?.keyId).toBe("arn:aws:kms:eu-west-1:1:key/abc");
    expect([...(kms.requests()[0]?.digest ?? [])]).toEqual([1, 2, 3, 4]);
  });

  it("surfaces a key-service outage as a SigningError without leaking the request", async () => {
    // A vendor error body routinely includes the request, and the request contains
    // the digest of the transaction being signed. Summarizing is not tidiness, it
    // is keeping signing material out of log aggregators.
    const kms = fakeKmsClient();
    const outage = new Error(
      `InvalidStateException while signing digest ${"00".repeat(32)} key ${KEY_ID}`,
    );
    outage.name = "InvalidStateException";
    kms.failWith(outage);
    const signer = new KmsTransactionSigner({
      keyId: KEY_ID,
      accountId: kms.keypair.publicKey(),
      client: kms.client,
    });

    const result = await signer.sign(new Uint8Array(createHash("sha256").update("x").digest()));

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBeInstanceOf(SigningError);
      // The class name survives, because "which failure" is what an operator
      // needs; the message body does not.
      expect(result.error.message).toBe(
        "Transaction signing failed: the key service refused the signing request (InvalidStateException)",
      );
      expect(result.error.message).not.toContain("00".repeat(32));
      expect(JSON.stringify(result.error)).not.toContain("00".repeat(32));
      // And no `cause`: `JSON.stringify(new Error("", { cause: leaked }))` does
      // not show it, but any logger that walks the error chain does, which makes
      // preserving it a disclosure path in exactly the situation this adapter
      // exists to close.
      expect(result.error.cause).toBeUndefined();
    }
  });

  it("rejects a signature the service did not unwrap from DER", async () => {
    // AWS returns ECDSA signatures DER-encoded. Forwarding a DER blob as if it
    // were Ed25519 would reach the network as an invalid signature, so this
    // catches it locally instead of after a fee.
    const kms = fakeKmsClient();
    kms.respondWith(new Uint8Array(71));
    const signer = new KmsTransactionSigner({
      keyId: KEY_ID,
      accountId: kms.keypair.publicKey(),
      client: kms.client,
    });

    const result = await signer.sign(new Uint8Array(createHash("sha256").update("x").digest()));

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.message).toContain("71-byte");
      expect(result.error.message).toContain("DER");
    }
  });

  it("refuses to sign nothing", async () => {
    const kms = fakeKmsClient();
    const signer = new KmsTransactionSigner({
      keyId: KEY_ID,
      accountId: kms.keypair.publicKey(),
      client: kms.client,
    });

    const result = await signer.sign(new Uint8Array());

    expect(Result.isErr(result)).toBe(true);
    // Not asked of the key service at all: an empty request is a bug in the
    // caller, and billing a KMS call for it would hide that.
    expect(kms.requests()).toHaveLength(0);
  });

  it("refuses a configured account that is not a Stellar account key", async () => {
    // The realistic misconfiguration: an operator pastes the anchoring account's
    // *seed* into the account-id field. That must fail here, with a message that
    // does not repeat what they pasted.
    const leaked = Keypair.random();
    const signer = new KmsTransactionSigner({
      keyId: KEY_ID,
      accountId: leaked.secret(),
      client: fakeKmsClient().client,
    });

    const result = await signer.accountId();

    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error.message).not.toContain(leaked.secret());
      expect(result.error.message).toContain("expected a G... strkey");
    }
  });

  it("describes itself as the KMS it signs through", () => {
    const signer = new KmsTransactionSigner({
      keyId: KEY_ID,
      accountId: fakeKmsClient().keypair.publicKey(),
      client: fakeKmsClient().client,
    });

    expect(signer.describe()).toBe(`kms:${KEY_ID}`);
    expect(signer.toJSON().kind).toBe("kms");
  });
});
