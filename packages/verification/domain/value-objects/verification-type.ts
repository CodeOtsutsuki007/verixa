import { Result, ValidationError } from "@verixa/shared-kernel";

/**
 * The closed set of things a subject can be asked to prove. A union rather
 * than a free string because everything downstream — which evidence types are
 * valid (see `evidence-type.ts`), what a provider may be asked to check, what
 * the reviewer queue groups by — branches on this value, and an unrecognised
 * string would silently match none of those branches.
 */
export type VerificationTypeValue = "identity-document" | "address" | "liveness";

const VERIFICATION_TYPES: readonly VerificationTypeValue[] = [
  "identity-document",
  "address",
  "liveness",
];

/**
 * What a `VerificationRequest` is asking the subject to prove.
 *
 * Modelled as a value object rather than a bare union on the aggregate so
 * that unknown input is rejected in one place (`create`) instead of at every
 * call site, and so a successful construction is a compile-time guarantee
 * that the value is one of the supported types.
 */
export class VerificationType {
  readonly value: VerificationTypeValue;

  private constructor(value: VerificationTypeValue) {
    this.value = value;
  }

  static create(raw: string): Result<VerificationType, ValidationError> {
    if (!isVerificationType(raw)) {
      return Result.err(
        new ValidationError("Verification type is not supported.", {
          verificationType: ["unsupported"],
        }),
      );
    }
    return Result.ok(new VerificationType(raw));
  }

  /** Rebuilds from already-trusted data (e.g. a database row). See `VerificationStatus.reconstitute`. */
  static reconstitute(value: VerificationTypeValue): VerificationType {
    return new VerificationType(value);
  }

  equals(other: VerificationType): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }
}

/** Whether `value` is one of the supported verification types — the guard the persistence mapper validates rows against. */
export function isVerificationType(value: string): value is VerificationTypeValue {
  return (VERIFICATION_TYPES as readonly string[]).includes(value);
}
