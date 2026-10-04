import type { StepUpAssertion } from "../../domain/value-objects/step-up-assertion.js";

/**
 * Persists the most recent step-up assertion for a user.
 *
 * Only the latest assertion matters — a fresh verification supersedes any
 * earlier one — so the port exposes no history, just a single "latest" read.
 * The session/adapter layer embeds the returned expiry in whatever claim it
 * issues.
 */
export interface StepUpAssertionStore {
  record(assertion: StepUpAssertion): Promise<void>;
  findLatest(userId: string): Promise<StepUpAssertion | undefined>;
}
