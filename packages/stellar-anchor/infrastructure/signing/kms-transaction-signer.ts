import { Result } from "@verixa/shared-kernel";

import {
  SigningError,
  type TransactionSigner,
} from "../../application/ports/transaction-signer.js";

/**
 * The remote signing capability this adapter needs, and nothing more.
 *
 * Deliberately one method, taking the key's identifier and the bytes to sign.
 * Every cloud KMS offers that shape — AWS `kms:Sign`, GCP Cloud KMS
 * `asymmetricSign`, Azure Key Vault `sign` — so an operator's adapter is a
 * request mapper, not a redesign. Anything more capable than this (create key,
 * rotate, enable/disable) belongs in the operator's runbook, not in a signing
 * interface used by application code: the more of the KMS API a request path can
 * reach, the more of it is exposed to whatever can compromise the request path.
 */
export interface KmsSignClient {
  /**
   * Signs `digest` under `keyId` and resolves with the resulting 64-byte raw
   * Ed25519 signature.
   *
   * Raw, not DER: AWS returns ECDSA signatures DER-encoded, so an AWS adapter
   * must unwrap them. Ed25519 in AWS KMS returns the 64 bytes directly. The
   * unwrap belongs in the adapter because it is a vendor detail, and the
   * application must not learn about vendor details.
   */
  sign(request: KmsSignRequest): Promise<Uint8Array>;
}

export interface KmsSignRequest {
  readonly keyId: string;
  readonly digest: Uint8Array;
}

export interface KmsTransactionSignerOptions {
  /**
   * Identifier of the asymmetric signing key — an ARN, a key-version resource
   * name, a Vault key name. Not secret: it appears in request paths and audit
   * logs by design.
   */
  readonly keyId: string;
  /**
   * The Stellar account (`G...`) this key signs for. Passed in rather than
   * derived from the KMS because the mapping between a KMS key and a Stellar
   * strkey is not the KMS's job, and a deployment that got it wrong should fail
   * at startup with a clear message rather than at submission with a confusing
   * one. See `docs/runbooks/stellar-mainnet-cutover.md` for the derivation step.
   */
  readonly accountId: string;
  readonly client: KmsSignClient;
}

/**
 * Signs through a KMS or HSM, so the anchoring account's private key never
 * exists in this process.
 *
 * ## What this buys, stated exactly
 *
 * The application holds a key *identifier* and a public account. It never holds
 * a seed. That removes every disclosure path that made the environment-variable
 * arrangement dangerous: there is nothing to print in a crash dump, nothing to
 * leak in a log line, nothing in a manifest backup, and nothing an
 * over-privileged CI job can read. What an attacker who fully compromises this
 * process gets is the ability to *ask* the KMS to sign anchoring transactions —
 * which still costs the account's funds, still requires network access to the
 * KMS, still is authorized only by that service's IAM policy, and above all is
 * recorded in the KMS's own CloudTrail-equivalent audit log. The difference is
 * not "impossible" versus "possible", it is that the operation now has a
 * permission system, an alert, and a paper trail.
 *
 * ## What it does not buy
 *
 * If the deployment's IAM role can call `kms:Sign`, so can anything running as
 * that role. This adapter is why a leaked secret stops being possible; it is not
 * a substitute for scoping who may call the key, which is the other half of the
 * runbook.
 */
export class KmsTransactionSigner implements TransactionSigner {
  constructor(private readonly options: KmsTransactionSignerOptions) {}

  accountId(): Promise<Result<string, SigningError>> {
    // Resolved from configuration rather than a remote call, and asserted here so
    // a deployment that pasted a seed instead of an account gets a `Result` at
    // startup rather than an inscrutable submission failure later.
    if (!this.options.accountId.startsWith("G")) {
      return Promise.resolve(
        Result.err(
          new SigningError(
            `configured account is not a Stellar account key (expected a G... strkey, got a ${String(this.options.accountId.length)}-character value)`,
          ),
        ),
      );
    }
    return Promise.resolve(Result.ok(this.options.accountId));
  }

  async sign(digest: Uint8Array): Promise<Result<Uint8Array, SigningError>> {
    if (digest.byteLength === 0) {
      return Result.err(new SigningError("refused to sign an empty digest"));
    }

    let signature: Uint8Array;
    try {
      signature = await this.options.client.sign({
        keyId: this.options.keyId,
        digest,
      });
    } catch (error) {
      // A summary, and deliberately no `cause`. This is the one place a vendor
      // SDK's error object could reach a log, and such errors routinely carry
      // the request they failed — which contains the digest. Guarantee 4 of the
      // port exists precisely so that nothing helping to reconstruct a
      // signature travels with the failure, and `error.cause` would smuggle it
      // past a `message` check into any logger that walks the chain. The error
      // *name* is enough to diagnose "which failure", which is what an operator
      // needs at 3am; "what bytes did you send" is not a debugging requirement
      // for a signing call whose inputs the caller already knows.
      return Result.err(
        new SigningError(
          `the key service refused the signing request (${error instanceof Error ? error.name : "unspecified error"})`,
        ),
      );
    }

    // Checked before returning, so a mis-unwrapped DER signature surfaces here
    // with a clear reason instead of arriving at the network as an invalid
    // signature against a spent fee.
    if (signature.byteLength !== 64) {
      return Result.err(
        new SigningError(
          `key service returned a ${String(signature.byteLength)}-byte signature; Ed25519 signatures are 64 bytes, so the response was probably not unwrapped from its DER encoding`,
        ),
      );
    }

    return Result.ok(signature);
  }

  describe(): string {
    return `kms:${this.options.keyId}`;
  }

  /**
   * Safe to serialize: the key identifier is public by design and the client is
   * an object with no key material in it, but the point of this method is that a
   * future field cannot accidentally become loggable.
   */
  toJSON(): Record<string, string> {
    return { kind: "kms", keyId: this.options.keyId, accountId: this.options.accountId };
  }

  toString(): string {
    return this.describe();
  }
}
