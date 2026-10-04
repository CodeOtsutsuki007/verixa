import {
  Asset,
  BASE_FEE,
  Horizon,
  Memo,
  Networks,
  Operation,
  TransactionBuilder,
} from "@stellar/stellar-sdk";
import { Result } from "@verixa/shared-kernel";

import type { AnchorFundingGuard } from "../../application/ports/account-balance.js";
import {
  AnchorError,
  type AnchorReceipt,
  type HashAnchor,
  isValidSha256Hex,
} from "../../application/ports/hash-anchor.js";
import type { TransactionSigner } from "../../application/ports/transaction-signer.js";
import { isUnderfundedLedgerError } from "../balance-monitor.js";

export type StellarNetwork = "testnet" | "public";

const HORIZON_URLS: Readonly<Record<StellarNetwork, string>> = {
  testnet: "https://horizon-testnet.stellar.org",
  public: "https://horizon.stellar.org",
};

const NETWORK_PASSPHRASES: Readonly<Record<StellarNetwork, string>> = {
  testnet: Networks.TESTNET,
  public: Networks.PUBLIC,
};

/**
 * The smallest amount Stellar can represent (1 stroop). The anchoring
 * transaction pays this to the anchoring account itself: a transaction needs
 * at least one operation to carry a memo, and a self-payment of one stroop
 * is the least consequential operation available — it moves no value
 * anywhere and leaves no lasting state, unlike `manageData`, which would
 * permanently raise the account's minimum balance requirement.
 */
const SELF_PAYMENT_AMOUNT = "0.0000001";

const TRANSACTION_TIMEOUT_SECONDS = 60;

export interface StellarHashAnchorOptions {
  /**
   * Where the anchoring account's signature comes from.
   *
   * Optional because the two halves of this adapter have genuinely different
   * credential needs: `verify` reads public ledger data and must work with no
   * credentials at all, while `anchor` spends from an account. Omitting the
   * signer therefore produces an adapter that can verify and refuses to anchor,
   * rather than one that throws on construction — which is what the CLI's
   * throwaway-keypair workaround was pretending to need.
   *
   * The adapter never sees a secret key. See
   * `application/ports/transaction-signer.ts`.
   */
  readonly signer?: TransactionSigner;
  readonly network: StellarNetwork;
  /** Overrides the default Horizon endpoint for the chosen network. Mainly for tests. */
  readonly horizonUrl?: string;
  /**
   * Checks that the account can pay the fee before submitting, and hears about
   * a rejection caused by insufficient funds. See {@link AnchorFundingGuard}.
   *
   * Optional because the guard costs an extra Horizon call per anchor — worth
   * paying when anchoring runs unattended, and skippable in a CLI one-shot
   * where the operator is watching the output anyway.
   */
  readonly fundingGuard?: AnchorFundingGuard | undefined;
}

/**
 * Anchors hashes to Stellar by submitting a minimal transaction whose
 * `MEMO_HASH` memo *is* the hash.
 *
 * Why a memo rather than a smart contract: the entire requirement is "record
 * 32 bytes on an append-only public ledger, cheaply, and be able to read
 * them back." Stellar's `MEMO_HASH` field is exactly 32 bytes — the exact
 * size of a SHA-256 digest, so the hash goes in whole, with no truncation
 * or encoding workaround. No Soroban contract, no token, no on-chain logic:
 * less to deploy, less to audit, and nothing that can be exploited beyond
 * the transaction itself.
 *
 * **Only ever anchor a hash.** A hash is a one-way commitment — it proves
 * the underlying record existed unchanged, while revealing nothing about
 * its contents. The audit log itself stays entirely in the operator's own
 * database. Putting audit *content* on a public ledger would be an
 * irreversible data leak, so this adapter accepts nothing but a validated
 * SHA-256 digest.
 */
export class StellarHashAnchor implements HashAnchor {
  private readonly signer: TransactionSigner | undefined;
  private readonly server: Horizon.Server;
  private readonly networkPassphrase: string;
  private readonly networkId: string;
  private readonly fundingGuard: AnchorFundingGuard | undefined;

  constructor(options: StellarHashAnchorOptions) {
    this.signer = options.signer;
    this.server = new Horizon.Server(options.horizonUrl ?? HORIZON_URLS[options.network]);
    this.networkPassphrase = NETWORK_PASSPHRASES[options.network];
    this.networkId = `stellar:${options.network}`;
    this.fundingGuard = options.fundingGuard;
  }

  /**
   * The account anchoring transactions are submitted from. Safe to log and share
   * — it is how anyone locates the anchor history.
   *
   * Asynchronous because a KMS-backed signer may have to ask the key service
   * which account its key belongs to, and a secret key is no longer available
   * locally to derive it from.
   */
  async accountId(): Promise<Result<string, AnchorError>> {
    if (this.signer === undefined) {
      return Result.err(
        new AnchorError("No signer is configured, so this adapter does not know an account."),
      );
    }
    const result = await this.signer.accountId();
    return Result.isErr(result)
      ? Result.err(new AnchorError(result.error.message, { cause: result.error }))
      : Result.ok(result.value);
  }

  async anchor(hash: string): Promise<Result<AnchorReceipt, AnchorError>> {
    if (!isValidSha256Hex(hash)) {
      return Result.err(
        new AnchorError(
          `Expected a 64-character lowercase hex SHA-256 digest, received ${String(hash.length)} characters.`,
        ),
      );
    }

    if (this.signer === undefined) {
      // Refused here rather than at construction: the same configured adapter is
      // used for verification, and an operator who has deliberately not given it
      // signing capability should get a message saying so instead of a
      // constructor error at startup.
      return Result.err(
        new AnchorError(
          "Anchoring is not available: this adapter was configured without a signer, so it can verify anchors but not create them.",
        ),
      );
    }

    const account = await this.signer.accountId();
    if (Result.isErr(account)) {
      return Result.err(new AnchorError(account.error.message, { cause: account.error }));
    if (this.fundingGuard !== undefined) {
      const cleared = await this.fundingGuard.beforeAnchor();
      if (Result.isErr(cleared)) {
        // Returned as-is: the guard has already raised its own alarm, and
        // re-wrapping it here would bury that under a second, vaguer error.
        return cleared;
      }
    }

    try {
      const source = await this.server.loadAccount(account.value);

      const transaction = new TransactionBuilder(source, {
        fee: BASE_FEE,
        networkPassphrase: this.networkPassphrase,
      })
        .addOperation(
          Operation.payment({
            destination: account.value,
            asset: Asset.native(),
            amount: SELF_PAYMENT_AMOUNT,
          }),
        )
        .addMemo(Memo.hash(hash))
        .setTimeout(TRANSACTION_TIMEOUT_SECONDS)
        .build();

      // The digest the network expects signed: SHA-256 over the transaction
      // signature payload, which already commits to the network passphrase.
      // Handing the signer a `Transaction` instead would put the SDK in the
      // application layer, so only these 32 bytes cross the boundary.
      const signature = await this.signer.sign(transaction.hash());
      if (Result.isErr(signature)) {
        return Result.err(new AnchorError(signature.error.message, { cause: signature.error }));
      }

      // `addSignature` takes the public key and a base64 signature, and verifies
      // it against the transaction hash before attaching it — so a signer that
      // returned bytes for a different transaction fails here, locally, rather
      // than at submission after the fee is spent.
      transaction.addSignature(account.value, Buffer.from(signature.value).toString("base64"));

      const response = await this.server.submitTransaction(transaction);

      return Result.ok({
        hash,
        anchorRef: response.hash,
        anchoredAt: new Date(),
        network: this.networkId,
      });
    } catch (error) {
      if (this.fundingGuard !== undefined && isUnderfundedLedgerError(error)) {
        // Reported and then still returned as a failure. A submission refused
        // for want of funds is the one anchoring error that will never fix
        // itself on a retry, so it has to reach the funding alarm rather than
        // the scheduler's "warn and try again on the next tick" path.
        await this.fundingGuard.reportUnderfundedRejection(describeError(error));
      }

      return Result.err(
        new AnchorError(`Failed to anchor hash to Stellar: ${describeError(error)}`, {
          cause: error,
        }),
      );
    }
  }

  async verify(hash: string, anchorRef: string): Promise<Result<boolean, AnchorError>> {
    if (!isValidSha256Hex(hash)) {
      return Result.err(new AnchorError("Expected a 64-character lowercase hex SHA-256 digest."));
    }

    try {
      const transaction = await this.server.transactions().transaction(anchorRef).call();

      if (transaction.memo_type !== "hash" || transaction.memo === undefined) {
        return Result.ok(false);
      }

      // Horizon returns a MEMO_HASH memo base64-encoded; the anchored value
      // is the raw 32 bytes, so compare in hex rather than trying to match
      // encodings.
      const anchoredHash = Buffer.from(transaction.memo, "base64").toString("hex");

      return Result.ok(anchoredHash === hash);
    } catch (error) {
      return Result.err(
        new AnchorError(`Failed to verify anchor ${anchorRef}: ${describeError(error)}`, {
          cause: error,
        }),
      );
    }
  }
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
