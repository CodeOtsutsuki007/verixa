import { describe, expect, it } from "vitest";

import { ManualReviewProvider } from "./manual-review-provider.js";

/**
 * The safety property of the default provider, asserted directly rather than
 * only through the shared contract (which cannot assume any particular
 * outcome, or it could not also fit a real vendor).
 *
 * If any of these ever fail, the consequence is severe and silent: a
 * deployment with no vendor configured would begin auto-passing or
 * auto-failing identity checks instead of routing them to a human. That is
 * why the expectation is spelled out explicitly and not left to the generic
 * shape test.
 */
describe("ManualReviewProvider", () => {
  it("returns inconclusive for a document check, never a verdict", async () => {
    const provider = new ManualReviewProvider();

    const result = await provider.checkDocument();

    expect(result.outcome).toBe("inconclusive");
  });

  it("returns inconclusive for a liveness check, never a verdict", async () => {
    const provider = new ManualReviewProvider();

    const result = await provider.checkLiveness();

    expect(result.outcome).toBe("inconclusive");
  });

  it("reports no confidence and no vendor reference, since it called nobody", async () => {
    const provider = new ManualReviewProvider();

    const document = await provider.checkDocument();
    const liveness = await provider.checkLiveness();

    expect(document.confidenceScore).toBe(0);
    expect(document.providerRawRef).toBeNull();
    expect(liveness.confidenceScore).toBe(0);
    expect(liveness.providerRawRef).toBeNull();
  });

  it("defers every check to manual review, regardless of how many are made", async () => {
    const provider = new ManualReviewProvider();

    const results = await Promise.all([
      provider.checkDocument(),
      provider.checkDocument(),
      provider.checkDocument(),
      provider.checkLiveness(),
      provider.checkLiveness(),
    ]);

    expect(results.map((result) => result.outcome)).toEqual([
      "inconclusive",
      "inconclusive",
      "inconclusive",
      "inconclusive",
      "inconclusive",
    ]);
  });
});
