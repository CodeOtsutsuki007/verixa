import { DomainError, type Result } from "@verixa/shared-kernel";

/**
 * Signing failed remotely, or the key was unusable.
 *
 * Returned rather than thrown because a deployment whose KMS is briefly
 * unreachable should skip an anchoring tick and try again, not take down the
 * process — the same reasoning that keeps `AnchorError` a `Result`. A signing
 * failure is an *infrastructure* state, and infrastructure state changes.
 *
 * The message is deliberately generic in the type: implementations must not put
 * key material into it (see the redaction contract in
 * `infrastructure/testing/contracts/transaction-signer.contract.ts`).
 */
export class SigningError extends DomainError {
  readonly code = "SIGNING_FAILED";
  // 502: an upstream service the caller depends on refused to do its job.
  readonly httpStatusHint = 502;

  /**
   * @param detail - a human-readable reason that contains **no** key material,
   * identifiers for the key are fine, the key itself never is.
   */
  constructor(detail: string, options?: ErrorOptions) {
    super(`Transaction signing failed: ${detail}`, options);
  }
}

/**
 * Produces Ed25519 signatures for a Stellar account without ever handing the
 * private half to the caller.
 *
 * ## Why this port exists at all
 *
 * The previous arrangement was a `STELLAR_ANCHOR_SECRET_KEY` environment
 * variable read into a `Keypair` at startup. That is not key management; it is
 * key *placement*. Anything that can read the process environment can read the
 * secret: a sidecar, a `kubectl describe pod`, a crash dump, a misconfigured
 * log line, the CI system that prints env for debugging, and every backup of
 * the deployment manifest. On mainnet the account holds real XLM and the key
 * mints publicly-verifiable claims about this deployment's audit log, so both
 * of those are things an attacker can turn into profit — and the ledger keeps
 * the evidence forever.
 *
 * A signing *interface* is what closes that gap. The application asks for a
 * signature over specific bytes and receives one; the key material stays inside
 * whatever the implementation delegates to — an HSM, a KMS, an external signer.
 * Nothing in the process can log, dump, or serialize what the process never
 * holds.
 *
 * ## What every implementation must guarantee
 *
 * 1. **The private half never enters this process's address space.** If an
 *    implementation holds a `Keypair` built from a secret, it is a development
 *    convenience and must say so loudly, both in its name and in `describe()`.
 *
 * 2. **`sign` is over exactly the bytes it is given.** No hashing, no
 *    re-encoding, no "helpful" canonicalization. The caller supplies a digest
 *    the network expects; a signature over anything else is invalid in a way
 *    that only shows up at submission time, against a real fee.
 *
 * 3. **No secret in any string this object can produce.** `describe()`,
 *    `toJSON()`, `toString()`, and every `SigningError.message` must be safe to
 *    log. The contract suite asserts this against an implementation whose key
 *    material is a recognizable marker.
 *
 * 4. **Failures are `Result`, never a leaked upstream payload.** A KMS error
 *    body can contain a request that included the message bytes; implementations
 *    must surface a code and a summary, not the raw response. That rules out
 *    `new SigningError(detail, { cause: upstreamError })` as well: the error
 *    *name* is diagnostic, the object attached to `cause` is the payload, and a
 *    logger that walks the chain prints it even though `JSON.stringify` does
 *    not.
 *
 * 5. **`accountId()` is stable for an instance.** A signer that changed which
 *    account it signs for mid-life would produce transactions that fail to
 *    submit, and an operator would reasonably assume their audit trail was
 *    anchored when it was not.
 *
 * ## Why the digest, not the transaction
 *
 * Passing a `Transaction` would drag the SDK into the application layer and
 * make every consumer of this port depend on Stellar types — the exact inversion
 * `HashAnchor` was introduced to avoid. The bytes to sign are a 32-value hash
 * regardless of which chain or which library built them, so the port stays a
 * boundary rather than becoming a wrapper around one vendor's object model.
 */
export interface TransactionSigner {
  /**
   * The Stellar account (strkey, `G...`) whose key signs. Public and safe to
   * log; it is how an auditor finds the anchors on the ledger.
   */
  accountId(): Promise<Result<string, SigningError>>;

  /**
   * Signs `digest` — the raw bytes a Stellar transaction is signed over, i.e.
   * `transaction.hash()` — and returns a 64-byte raw Ed25519 signature.
   *
   * Returns raw bytes rather than a decorated signature or base64 string so
   * callers can attach it however their SDK version expects, and so a
   * signature-validity test can compare against the public key without parsing.
   */
  sign(digest: Uint8Array): Promise<Result<Uint8Array, SigningError>>;

  /**
   * One line describing where signing happens, for logs and startup banners:
   * `kms:alias/verixa-anchor`, or `local:` followed by the *public* account id.
   * Never contains key material — see guarantee 3 above.
   */
  describe(): string;
}
