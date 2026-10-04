/**
 * The three things an automated provider check can conclude.
 *
 * `inconclusive` is the one that matters and the one vendor SDKs usually do
 * not have. It means "the provider could not decide" — not passed, not
 * failed. Without it, a provider that returns a low-confidence "maybe" has to
 * be squeezed into a pass or a fail by the adapter, and a wrong guess here is
 * a real person denied a service or a fraudster waved through. Making it a
 * first-class outcome lets the workflow route it to a human, which is what
 * the manual-review default provider does for *every* check.
 */
export type ProviderCheckOutcome = "passed" | "failed" | "inconclusive";

/**
 * A provider's normalized answer about one piece of evidence.
 *
 * Provider-agnostic by construction: no vendor field names, no vendor error
 * codes, no SDK types. An adapter translates its vendor's response into this
 * shape, and every consumer above it works the same regardless of who
 * answered. That is the whole point of the port this belongs to — see
 * `docs/guides/verification-provider-integration.md`.
 */
export interface ProviderCheckResult {
  readonly outcome: ProviderCheckOutcome;
  /**
   * The provider's confidence in `outcome`, normalized to `0..1`. `0` is
   * "no confidence" and `inconclusive` results conventionally carry `0`,
   * because there is no outcome to be confident in.
   */
  readonly confidenceScore: number;
  /**
   * The provider's own handle for the check, stored opaquely so a dispute can
   * be traced back to the vendor's record. Never parsed, never assumed to be
   * a URL or an id in any particular format. `null` when the provider has
   * nothing to reference (e.g. the manual-review default, which called
   * nobody).
   */
  readonly providerRawRef: string | null;
}

/**
 * The maximum sensible confidence. A single named constant so "in range"
 * means the same thing everywhere, and so a future `0..100` provider is
 * normalized in one place rather than compared against a literal.
 */
export const MAX_CONFIDENCE_SCORE = 1;

/**
 * Factories for the three outcomes. Prefer these over object literals so an
 * out-of-range confidence is impossible to construct by accident, and so a
 * reader can see at a glance which outcome a call site means.
 *
 * The factories take positional arguments rather than an options object
 * because the common call reads better and there are only two fields; the
 * full validated constructor is {@link isValidProviderCheckResult}.
 */
export const ProviderCheckResult = {
  /** The provider is confident the evidence is genuine. */
  passed(
    providerRawRef: string | null = null,
    confidenceScore = MAX_CONFIDENCE_SCORE,
  ): ProviderCheckResult {
    return { outcome: "passed", confidenceScore, providerRawRef };
  },

  /** The provider is confident the evidence is not genuine. */
  failed(
    providerRawRef: string | null = null,
    confidenceScore = MAX_CONFIDENCE_SCORE,
  ): ProviderCheckResult {
    return { outcome: "failed", confidenceScore, providerRawRef };
  },

  /** The provider could not decide, or there is no provider — the signal to send the case to a human. */
  inconclusive(providerRawRef: string | null = null): ProviderCheckResult {
    return { outcome: "inconclusive", confidenceScore: 0, providerRawRef };
  },

  /**
   * Whether a value is a well-formed result: a known outcome and a confidence
   * in range. Vendor responses are untrusted input, so adapters validate
   * through this before anything downstream trusts a score.
   */
  isValid(result: ProviderCheckResult): boolean {
    return (
      (result.outcome === "passed" ||
        result.outcome === "failed" ||
        result.outcome === "inconclusive") &&
      Number.isFinite(result.confidenceScore) &&
      result.confidenceScore >= 0 &&
      result.confidenceScore <= MAX_CONFIDENCE_SCORE
    );
  },
} as const;
