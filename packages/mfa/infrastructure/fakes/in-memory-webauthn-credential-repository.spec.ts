import { describe } from "vitest";
import { webAuthnCredentialRepositoryContract } from "../testing/contracts/webauthn-credential-repository.contract.js";
import { InMemoryWebAuthnCredentialRepository } from "./in-memory-webauthn-credential-repository.js";

describe("InMemoryWebAuthnCredentialRepository", () => {
  webAuthnCredentialRepositoryContract(() => new InMemoryWebAuthnCredentialRepository());
});
