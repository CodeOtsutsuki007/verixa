import { sessionRepositoryContract } from "./contracts/session-repository.contract.js";
import { InMemorySessionRepository } from "./in-memory-session-repository.js";

sessionRepositoryContract(() => new InMemorySessionRepository());
