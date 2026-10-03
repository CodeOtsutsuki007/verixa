import { Result, ValidationError } from "@verixa/shared-kernel";

import type { VerificationTypeValue } from "./verification-type.js";

/** The closed set of evidence artifacts a subject can submit. */
export type EvidenceTypeValue =
  "government-id-front" | "government-id-back" | "selfie" | "proof-of-address";

const EVIDENCE_TYPES: readonly EvidenceTypeValue[] = [
  "government-id-front",
  "government-id-back",
  "selfie",
  "proof-of-address",
];

/**
 * Which evidence types are meaningful for each verification type.
 *
 * A closed table rather than "any evidence type for any request", because
 * the pairing is a domain invariant: a selfie attached to an
 * `identity-document` request is not a collectible item that happens to be
 * missing, it is a request the reviewer cannot act on. Rejecting it at
 * attachment time keeps a nonsensical combination out of the reviewer queue
 * entirely, rather than surfacing it as a confusing "insufficient evidence"
 * later.
 *
 * The order of each list is the order evidence is considered complete, which
 * is the order a UI should prompt for it.
 */
// A Map rather than a plain object so the lookup is never a dynamic property
// access on an object — the same reasoning `ValidationErrorAggregator` uses.
const EVIDENCE_TYPES_BY_VERIFICATION_TYPE: ReadonlyMap<
  VerificationTypeValue,
  readonly EvidenceTypeValue[]
> = new Map<VerificationTypeValue, readonly EvidenceTypeValue[]>([
  ["identity-document", ["government-id-front", "government-id-back"]],
  ["address", ["proof-of-address"]],
  ["liveness", ["selfie"]],
]);

export class EvidenceType {
  readonly value: EvidenceTypeValue;

  private constructor(value: EvidenceTypeValue) {
    this.value = value;
  }

  static create(raw: string): Result<EvidenceType, ValidationError> {
    if (!isEvidenceType(raw)) {
      return Result.err(
        new ValidationError("Evidence type is not supported.", {
          evidenceType: ["unsupported"],
        }),
      );
    }
    return Result.ok(new EvidenceType(raw));
  }

  /** Rebuilds from already-trusted data (e.g. a database row). */
  static reconstitute(value: EvidenceTypeValue): EvidenceType {
    return new EvidenceType(value);
  }

  /** Whether this evidence type is valid for a request of `verificationType`. */
  isValidFor(verificationType: VerificationTypeValue): boolean {
    return requiredEvidenceTypesFor(verificationType).includes(this.value);
  }

  equals(other: EvidenceType): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }
}

/** The evidence types required (in prompt order) to satisfy a request of `verificationType`. */
export function requiredEvidenceTypesFor(
  verificationType: VerificationTypeValue,
): readonly EvidenceTypeValue[] {
  // The fallback is unreachable for a well-typed caller — the Map covers every
  // `VerificationTypeValue` — and exists only because `Map.get` is typed
  // `T | undefined`.
  return EVIDENCE_TYPES_BY_VERIFICATION_TYPE.get(verificationType) ?? [];
}

/** Whether `value` is one of the supported evidence types. */
export function isEvidenceType(value: string): value is EvidenceTypeValue {
  return (EVIDENCE_TYPES as readonly string[]).includes(value);
}
