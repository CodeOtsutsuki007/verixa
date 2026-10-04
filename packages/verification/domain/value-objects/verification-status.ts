import { Result, ValidationError } from "@verixa/shared-kernel";

/**
 * The lifecycle of a `VerificationRequest`.
 *
 * ```
 * pending_evidence ──► submitted ──► in_review ──┬──► approved   (terminal)
 *        ▲                                        ├──► rejected   (terminal)
 *        │                                        └──► needs_more_info
 *        └──────────────────────────────────────────────┘
 *              (re-submission re-enters the evidence flow)
 * ```
 *
 * The `needs_more_info → pending_evidence` loop is why this is not a strictly
 * forward state machine. Real verification work is not linear — a blurry
 * document is rejected and re-uploaded, repeatedly — and modelling that as a
 * brand-new request would discard the decision history and re-queue the
 * subject behind everyone else. See Issue 176.
 */
export type VerificationStatusValue =
  "pending_evidence" | "submitted" | "in_review" | "needs_more_info" | "approved" | "rejected";

/**
 * The transition table, written once.
 *
 * This is the entire reason the status lives in a value object instead of
 * being a string column the use cases mutate directly: every caller that
 * asks "can I move this to X?" gets the same answer, and a new status is
 * added in exactly one place. Terminal states map to an empty set, so
 * `approved` and `rejected` reject *every* further transition without a
 * special case.
 */
const ALLOWED_TRANSITIONS: Readonly<
  Record<VerificationStatusValue, ReadonlySet<VerificationStatusValue>>
> = {
  pending_evidence: new Set<VerificationStatusValue>(["submitted"]),
  submitted: new Set<VerificationStatusValue>(["in_review"]),
  in_review: new Set<VerificationStatusValue>(["approved", "rejected", "needs_more_info"]),
  needs_more_info: new Set<VerificationStatusValue>(["pending_evidence"]),
  approved: new Set<VerificationStatusValue>(),
  rejected: new Set<VerificationStatusValue>(),
};

/** Statuses from which no further transition is possible. A decided request is final. */
export const TERMINAL_STATUSES: readonly VerificationStatusValue[] = ["approved", "rejected"];

const ALL_STATUSES: readonly VerificationStatusValue[] = [
  "pending_evidence",
  "submitted",
  "in_review",
  "needs_more_info",
  "approved",
  "rejected",
];

export class VerificationStatus {
  readonly value: VerificationStatusValue;

  private constructor(value: VerificationStatusValue) {
    this.value = value;
  }

  static create(raw: string): Result<VerificationStatus, ValidationError> {
    if (!isVerificationStatus(raw)) {
      return Result.err(
        new ValidationError("Verification status is not recognised.", {
          status: ["unsupported"],
        }),
      );
    }
    return Result.ok(new VerificationStatus(raw));
  }

  /**
   * Rebuilds from already-trusted data (e.g. a database row). Does not
   * re-validate the transition that produced the value — a stored status
   * represents a transition that already happened and was already checked.
   */
  static reconstitute(value: VerificationStatusValue): VerificationStatus {
    return new VerificationStatus(value);
  }

  /**
   * Whether this status may move to `next`. The single source of truth every
   * mutation path on the aggregate consults — see `VerificationRequest`.
   */
  canTransitionTo(next: VerificationStatus): boolean {
    return ALLOWED_TRANSITIONS[this.value].has(next.value);
  }

  /** Whether this status is final. Derived from the transition table so the two can never disagree. */
  get isTerminal(): boolean {
    return ALLOWED_TRANSITIONS[this.value].size === 0;
  }

  equals(other: VerificationStatus): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }
}

/** Whether `value` is a status the domain defines — the guard the persistence mapper validates rows against. */
export function isVerificationStatus(value: string): value is VerificationStatusValue {
  return (ALL_STATUSES as readonly string[]).includes(value);
}
