import type { Evidence } from "../../domain/entities/evidence.js";
import type { ProviderCheckResult } from "../dtos/provider-check-result.js";

/**
 * A third-party automated identity-verification vendor, behind a port.
 *
 * ## Why a port and not a direct SDK call
 *
 * Verixa is infrastructure meant to be reused across projects, so hardcoding
 * one vendor's SDK into a use case would violate the hexagonal dependency
 * rule and lock every consumer into that vendor. The application layer names
 * only this interface; the concrete adapter — vendor A, vendor B, or the
 * shipped `ManualReviewProvider` that calls nobody — is chosen in the
 * composition root. Swapping vendors is then a one-file change, which is the
 * Adapter pattern doing exactly what it is for.
 *
 * See `docs/guides/verification-provider-integration.md` for the reference
 * implementation a new adapter should copy.
 *
 * ## The contract every implementation must fulfil
 *
 * - **Return a normalized {@link ProviderCheckResult}, never a vendor type.**
 *   No vendor field names, error codes, or SDK classes may appear in the
 *   returned value. If a vendor's answer cannot be mapped, return
 *   `inconclusive` — do not invent a pass or a fail.
 * - **Say `inconclusive` when you cannot decide.** A provider that is unsure,
 *   timed out at the vendor, or has no opinion (the manual-review default)
 *   must not be represented as `passed` or `failed`. This is the outcome that
 *   routes a case to a human, and collapsing it is how a person is wrongly
 *   denied or a fraudster wrongly admitted.
 * - **Never decide the request.** A provider returns an *opinion*. It does not
 *   approve, reject, or transition the request — `RunAutomatedCheck` (Issue
 *   172) records the result and sends the case to `in_review` regardless of
 *   the outcome, and only a human reviewer makes the terminal decision in this
 *   phase.
 * - **Do not throw for a negative result.** `failed` is an expected answer,
 *   not an error. Throw/reject only when the *check itself* could not be
 *   completed (network failure, misconfiguration); the caller treats that as
 *   an infrastructure failure and still routes the case to a human.
 * - **Handle exactly the evidence given.** `evidence.storageRef` is an opaque
 *   pointer — fetch the bytes through `EvidenceStorage` (Issue 166), never
 *   assume a filesystem path or a public URL.
 * - **Treat the result as untrusted input on the way back.** Validate through
 *   `ProviderCheckResult.isValid` before returning it.
 */
export interface VerificationProvider {
  /**
   * Checks a document evidence item (government ID, proof of address) and
   * returns a normalized outcome.
   */
  checkDocument(evidence: Evidence): Promise<ProviderCheckResult>;

  /**
   * Checks a liveness/selfie evidence item and returns a normalized outcome.
   */
  checkLiveness(evidence: Evidence): Promise<ProviderCheckResult>;
}
