import { createId } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import type { WebAuthnCredentialRepository } from "../../../application/ports/webauthn-credential-repository.js";
import { WebAuthnCredential } from "../../../domain/entities/webauthn-credential.js";

function makeCredential(userId = createId<"UserId">(), mfaMethodId = createId<"MfaMethodId">(), credentialId = "cred-abc") {
  const credResult = WebAuthnCredential.register({
    userId,
    mfaMethodId,
    credentialId,
    publicKey: "pub-key-data",
    transports: ["internal"],
    attestationType: "none",
  });
  if (!credResult.isOk()) {
    throw new Error("contract fixture setup failed");
  }
  return credResult.value;
}

export function webAuthnCredentialRepositoryContract(createRepository: () => WebAuthnCredentialRepository): void {
  describe("WebAuthnCredentialRepository contract", () => {
    it("returns undefined for credential that was never saved", async () => {
      const repo = createRepository();
      await expect(repo.findById(createId<"WebAuthnCredentialId">())).resolves.toBeUndefined();
      await expect(repo.findByCredentialId("nonexistent")).resolves.toBeUndefined();
    });

    it("finds saved credential by id and credentialId", async () => {
      const repo = createRepository();
      const cred = makeCredential();

      await repo.save(cred);

      const foundById = await repo.findById(cred.id);
      expect(foundById?.id).toBe(cred.id);
      expect(foundById?.publicKey).toBe(cred.publicKey);

      const foundByCredId = await repo.findByCredentialId(cred.credentialId);
      expect(foundByCredId?.id).toBe(cred.id);
    });

    it("finds credentials by userId", async () => {
      const repo = createRepository();
      const userId = createId<"UserId">();
      const cred1 = makeCredential(userId, createId<"MfaMethodId">(), "cred-1");
      const cred2 = makeCredential(userId, createId<"MfaMethodId">(), "cred-2");

      await repo.save(cred1);
      await repo.save(cred2);

      const list = await repo.findByUserId(userId);
      expect(list.length).toBe(2);
      expect(list.map((c) => c.credentialId).sort()).toEqual(["cred-1", "cred-2"]);
    });

    it("supports upsert / idempotent save", async () => {
      const repo = createRepository();
      const cred = makeCredential();

      await repo.save(cred);

      const updatedRes = cred.updateSignCounter(5);
      if (!updatedRes.isOk()) throw new Error("setup failed");

      await repo.save(updatedRes.value);

      const found = await repo.findById(cred.id);
      expect(found?.signCounter).toBe(5);
    });

    it("deletes a credential", async () => {
      const repo = createRepository();
      const cred = makeCredential();

      await repo.save(cred);
      await repo.delete(cred.id);

      await expect(repo.findById(cred.id)).resolves.toBeUndefined();
    });
  });
}
