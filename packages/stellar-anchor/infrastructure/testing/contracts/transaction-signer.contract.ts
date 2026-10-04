import { createHash } from "node:crypto";

import { Keypair } from "@stellar/stellar-sdk";
import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { TransactionSigner } from "../../../application/ports/transaction-signer.js";

function digestOf(label: string): Buffer {
  return createHash("sha256").update(label).digest();
}

/**
 * Behavioral contract every `TransactionSigner` implementation must satisfy,
 * local or remote.
 *
 * The verification assertions are the substance: a signer that returns 64
 * plausible bytes which do not verify against its own advertised account would
 * pass any test that only checked types, and would fail at submission — after a
 * fee was spent and after the operator had recorded an anchor that never
 * landed. The redaction assertions are equally load-bearing but easy to write
 * carelessly, so the contract requires a `secretMarker` (a substring guaranteed
 * to appear in whatever key material the implementation holds) and then proves
 * that substring never reaches any string the object can emit.
 */
export function transactionSignerContract(params: {
  createSigner: () => TransactionSigner;
  /**
   * A substring of the key material this signer holds. `""` means the
   * implementation holds no key material at all, and redaction is then
   * vacuously true — the assertions still run, they just cannot fail.
   */
  secretMarker: string;
}): void {
  const { createSigner, secretMarker } = params;

  describe("TransactionSigner contract", () => {
    it("advertises a Stellar account key", async () => {
      const result = await createSigner().accountId();

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.startsWith("G")).toBe(true);
        // Throws for anything that is not a valid strkey, which is the only
        // assertion here that proves "account id" means an account and not,
        // say, a seed by accident.
        expect(() => Keypair.fromPublicKey(result.value)).not.toThrow();
      }
    });

    it("produces a 64-byte signature", async () => {
      const signer = createSigner();
      const result = await signer.sign(digestOf("anchoring digest"));

      expect(Result.isOk(result)).toBe(true);
      if (Result.isOk(result)) {
        expect(result.value.byteLength).toBe(64);
      }
    });

    it("produces a signature that verifies against the account it advertises", async () => {
      // The pair of assertions the port actually exists to guarantee: the
      // account you can find on the ledger is the account whose key signed.
      const signer = createSigner();
      const account = await signer.accountId();
      if (!Result.isOk(account)) throw new Error("contract setup failed");

      const digest = digestOf("chain head to anchor");
      const signature = await signer.sign(digest);
      if (!Result.isOk(signature)) throw new Error("contract setup failed");

      expect(
        Keypair.fromPublicKey(account.value).verify(digest, Buffer.from(signature.value)),
      ).toBe(true);
    });

    it("signs the exact bytes it was given", async () => {
      // No re-hashing, no re-encoding. A signer that "helpfully" hashed the
      // digest first would produce a signature the network rejects, and the
      // failure would surface as an invalid-memo transaction at best.
      const signer = createSigner();
      const account = await signer.accountId();
      if (!Result.isOk(account)) throw new Error("contract setup failed");

      const arbitrary = Buffer.from([0x00, 0x01, 0xfe, 0xff, 0x7f]);
      const signature = await signer.sign(arbitrary);
      if (!Result.isOk(signature)) throw new Error("contract setup failed");

      expect(
        Keypair.fromPublicKey(account.value).verify(arbitrary, Buffer.from(signature.value)),
      ).toBe(true);
    });

    it("never puts key material in describe()", () => {
      expect(createSigner().describe()).not.toContain(secretMarker);
    });

    it("never puts key material in a serialized form", () => {
      // `JSON.stringify(signer)` is what a structured logger does to an object it
      // was handed, which is the disclosure path this test exists for.
      expect(JSON.stringify(createSigner())).not.toContain(secretMarker);
      // `String()` is what `console.log(signer)`, a template literal, or an
      // error message that interpolates the signer produces. The port declares
      // no `toString`, so the type says the result is always `[object Object]`
      // and the rule wants to call this assertion pointless — but an
      // implementation that *adds* a `toString` is free to do so, and that is
      // exactly the disclosure being tested. The type cannot see it; the test
      // can.
      // eslint-disable-next-line @typescript-eslint/no-base-to-string
      expect(String(createSigner())).not.toContain(secretMarker);
    });

    it("never puts key material in a failure message", async () => {
      // Errors are the string most likely to be logged, printed, and pasted into
      // an issue. The signing path is where a careless implementation would
      // interpolate the key it could not use.
      const signer = createSigner();
      const failures = await Promise.all([
        signer.sign(new Uint8Array()),
        signer.sign(new Uint8Array([0x00])),
      ]);

      for (const failure of failures) {
        if (Result.isErr(failure)) {
          expect(failure.error.message).not.toContain(secretMarker);
          // Guarantee 4 rules out a `cause` holding the upstream payload, which
          // a `message` check alone would not catch: `JSON.stringify` hides it,
          // a chain-walking logger does not.
          expect(failure.error.cause).toBeUndefined();
        }
      }
    });
  });
}
