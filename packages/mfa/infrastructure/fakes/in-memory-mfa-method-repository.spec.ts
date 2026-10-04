import { InMemoryMfaMethodRepository } from "./in-memory-mfa-method-repository.js";
import { mfaMethodRepositoryContract } from "../testing/contracts/mfa-method-repository.contract.js";

mfaMethodRepositoryContract(() => new InMemoryMfaMethodRepository());
