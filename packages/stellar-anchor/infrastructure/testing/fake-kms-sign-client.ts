import { Keypair } from "@stellar/stellar-sdk";

import type { KmsSignClient, KmsSignRequest } from "../signing/kms-transaction-signer.js";

/**
 * A `KmsSignClient` that signs in-process, so `KmsTransactionSigner` can be
 * tested without a cloud account.
 *
 * It stands in for the *transport*, not for the port: what is under test is the
 * adapter's own behaviour — length validation, error summarization, refusing to
 * echo key material — and a `sign()` that always returned a fixed buffer would
 * never exercise any of it. Signing with a real Ed25519 key is what lets the
 * contract suite check the signature the way the network would.
 */
export interface FakeKmsClient {
  readonly client: KmsSignClient;
  /** The key standing in for the one a real KMS would hold. */
  readonly keypair: Keypair;
  /** Every request the adapter made, in order. */
  requests(): readonly KmsSignRequest[];
  /** Make subsequent calls throw, as a denied IAM policy or an outage does. */
  failWith(error: Error): void;
  /** Make subsequent calls return something that is not a 64-byte signature. */
  respondWith(signature: Uint8Array): void;
}

export function fakeKmsClient(): FakeKmsClient {
  const keypair = Keypair.random();
  const seen: KmsSignRequest[] = [];
  let failure: Error | undefined;
  let canned: Uint8Array | undefined;

  const client: KmsSignClient = {
    sign: async (request) => {
      seen.push(request);
      // Yields a microtask the way a network round trip would, so concurrent
      // signatures interleave here as they do against a real endpoint.
      await Promise.resolve();
      if (failure !== undefined) {
        throw failure;
      }
      if (canned !== undefined) {
        return canned;
      }
      return keypair.sign(Buffer.from(request.digest));
    },
  };

  return {
    client,
    keypair,
    requests: () => seen,
    failWith: (error) => {
      failure = error;
    },
    respondWith: (signature) => {
      canned = signature;
    },
  };
}
