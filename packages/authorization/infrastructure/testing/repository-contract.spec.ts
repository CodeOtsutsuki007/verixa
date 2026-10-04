import { InMemoryPolicyRepository } from "../fakes/in-memory-policy-repository.js";

import { policyRepositoryContract } from "./contracts/policy-repository.contract.js";

policyRepositoryContract(() => new InMemoryPolicyRepository());
