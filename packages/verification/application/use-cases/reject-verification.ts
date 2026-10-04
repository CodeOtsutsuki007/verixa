import { NotFoundError, Result, ValidationError } from "@verixa/shared-kernel";

import type { ReviewerId } from "../../domain/entities/review-assignment.js";
import type {
  VerificationRequest,
  VerificationRequestId,
} from "../../domain/entities/verification-request.js";
import type { InvalidStatusTransitionError } from "../../domain/errors/invalid-status-transition.js";
import type { ReviewDecisionNotPermittedError } from "../../domain/errors/review-decision-not-permitted.js";
import type { VerificationRequestRepository } from "../ports/verification-request-repository.js";

export interface RejectVerificationCommand {
  readonly requestId: VerificationRequestId;
  readonly reviewerId: ReviewerId;
  /** Why the request was rejected. Mandatory and non-empty. */
  readonly note: string;
  /** Injected clock for tests; defaults to `new Date()`. */
  readonly now?: Date;
}

export type RejectVerificationError =
  ValidationError | NotFoundError | InvalidStatusTransitionError | ReviewDecisionNotPermittedError;

/**
 * Records a reviewer's decision to reject a verification request.
 *
 * Structurally identical to {@link ApproveVerification} — the transition, the
 * claim check and the event all differ only in the `decision` value the
 * aggregate records — and that repetition is deliberate. The two decisions
 * are the same shape today and *may not stay that way*: rejection is the
 * direction a "cooling-off period before re-application" rule would attach to,
 * and approval is the one a "reason required by policy, not by law" flag
 * would. Merging them behind a boolean now would make that divergence a
 * rewrite of a shared method rather than a change to one file.
 *
 * The rationale requirement is sharper here than on approval: a *denial* is
 * the decision most likely to be challenged, by the subject directly and by a
 * regulator, and it is the one where "the system said no and nobody recorded
 * why" is least acceptable. See Issue 175.
 */
export class RejectVerification {
  constructor(private readonly requests: VerificationRequestRepository) {}

  async execute(
    command: RejectVerificationCommand,
  ): Promise<Result<VerificationRequest, RejectVerificationError>> {
    const note = command.note.trim();
    if (note.length === 0) {
      return Result.err(
        new ValidationError("A rationale note is required to reject a verification request.", {
          note: ["required"],
        }),
      );
    }

    const request = await this.requests.findById(command.requestId);
    if (request === undefined) {
      return Result.err(
        new NotFoundError(`Verification request ${command.requestId} was not found.`),
      );
    }

    const rejected = request.reject({
      reviewerId: command.reviewerId,
      note,
      now: command.now ?? new Date(),
    });
    if (Result.isErr(rejected)) {
      return rejected;
    }

    await this.requests.save(rejected.value);
    return Result.ok(rejected.value);
  }
}
