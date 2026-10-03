import { describe } from "vitest";

import { InMemorySessionRepository } from "./in-memory-session-repository.js";
import { sessionRepositoryContract } from "./contracts/session-repository.contract.js";

/**
 * Run the SessionRepository contract test suite against the in-memory fake.
 * This verifies that the fake implementation satisfies the port's contract.
 * Later (Issue 083), the same contract will be run against PrismaSessionRepository.
 */
describe("InMemorySessionRepository", () => {
  sessionRepositoryContract(() => new InMemorySessionRepository());
});
