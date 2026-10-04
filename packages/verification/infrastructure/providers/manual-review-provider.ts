import { ProviderCheckResult } from "../../application/dtos/provider-check-result.js";
import type { VerificationProvider } from "../../application/ports/verification-provider.js";

/**
 * The shipped default `VerificationProvider`: a **null object** that answers
 * every check with `inconclusive`, deferring the decision to a human reviewer.
 *
 * ## Why this exists at all
 *
 * It keeps Verixa self-contained. A verification workflow that only works
 * once you have signed a contract with a commercial KYC vendor is not much of
 * an open-source project: a contributor cloning the repo, or an operator
 * evaluating it, would be unable to run the flow end to end. With this as the
 * default, every request simply lands in the reviewer queue, and the manual
 * review experience — the part this phase is actually about — is fully
 * exercisable with no third-party account and no API key.
 *
 * It is also the reference implementation for anyone writing a real adapter
 * (`docs/guides/verification-provider-integration.md`): it shows the port's
 * contract in the fewest lines that can still satisfy it, and it demonstrates
 * the one rule a vendor adapter most easily gets wrong — *never decide*.
 *
 * ## Why `inconclusive` and not `passed`
 *
 * A null object that returned `passed` would be a security hole wearing a
 * default's clothes: every deployment that forgot to configure a real vendor
 * would auto-pass every identity check. `inconclusive` is the honest answer
 * for "no automated judgment was made", and it is exactly the outcome the
 * workflow routes to a human. Doing nothing, visibly, is the safe default.
 */
export class ManualReviewProvider implements VerificationProvider {
  /**
   * No parameter: the check is deliberately a constant, and naming an
   * argument nothing reads would suggest the result depends on it.
   */
  checkDocument(): Promise<ProviderCheckResult> {
    return Promise.resolve(ProviderCheckResult.inconclusive());
  }

  /** See {@link checkDocument} — liveness is deferred to a human for the same reason. */
  checkLiveness(): Promise<ProviderCheckResult> {
    return Promise.resolve(ProviderCheckResult.inconclusive());
  }
}
