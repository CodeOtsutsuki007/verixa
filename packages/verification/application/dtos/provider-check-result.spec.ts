import { describe, expect, it } from "vitest";

import { ProviderCheckResult } from "./provider-check-result.js";

describe("ProviderCheckResult", () => {
  it("builds a passed result with full confidence by default", () => {
    const result = ProviderCheckResult.passed("vendor-check-1");

    expect(result).toEqual({
      outcome: "passed",
      confidenceScore: 1,
      providerRawRef: "vendor-check-1",
    });
    expect(ProviderCheckResult.isValid(result)).toBe(true);
  });

  it("builds a failed result carrying the vendor reference", () => {
    const result = ProviderCheckResult.failed("vendor-check-2", 1);

    expect(result.outcome).toBe("failed");
    expect(result.providerRawRef).toBe("vendor-check-2");
    expect(ProviderCheckResult.isValid(result)).toBe(true);
  });

  it("builds an inconclusive result with zero confidence and no reference by default", () => {
    const result = ProviderCheckResult.inconclusive();

    expect(result).toEqual({
      outcome: "inconclusive",
      confidenceScore: 0,
      providerRawRef: null,
    });
    expect(ProviderCheckResult.isValid(result)).toBe(true);
  });

  it("rejects a confidence score outside 0..1 as malformed input", () => {
    expect(
      ProviderCheckResult.isValid({
        outcome: "passed",
        confidenceScore: 1.5,
        providerRawRef: null,
      }),
    ).toBe(false);
    expect(
      ProviderCheckResult.isValid({
        outcome: "failed",
        confidenceScore: -0.1,
        providerRawRef: null,
      }),
    ).toBe(false);
    expect(
      ProviderCheckResult.isValid({
        outcome: "passed",
        confidenceScore: Number.NaN,
        providerRawRef: null,
      }),
    ).toBe(false);
  });
});
