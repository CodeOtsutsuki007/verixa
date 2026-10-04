import { NotFoundError, Result, ValidationError } from "@verixa/shared-kernel";

import type { ReviewerId } from "../../domain/entities/review-assignment.js";
import type {
  VerificationRequest,
  VerificationRequestId,
} from "../../domain/entities/verification-request.js";
import type { InvalidStatusTransitionError } from "../../domain/errors/invalid-status-transition.js";
import type { ReviewDecisionNotPermittedError } from "../../domain/errors/review-decision-not-permitted.js";
import type { VerificationRequestRepository } from "../ports/verification-request-repository.js";

export interface RequestMoreInformationCommand {
  readonly requestId: VerificationRequestId;
  readonly reviewerId: ReviewerId;
  /** What is missing, visible to the subject. Mandatory and non-empty. */
  readonly note: string;
  /** Injected clock for tests; defaults to `new Date()`. */
  readonly now?: Date;
}

export type RequestMoreInformationError =
  ValidationError | NotFoundError | InvalidStatusTransitionError | ReviewDecisionNotPermittedError;

/**
 * `in_review → needs_more_info`: the reviewer cannot decide yet and asks the
 * subject for something specific (a clearer scan, a second document).
 *
 * This is the non-terminal third option a real review flow needs. Without it
 * a reviewer facing incomplete evidence has only two choices, both wrong:
 * approve on partial evidence, or reject a subject who could have fixed the
 * problem in two minutes. The note is mandatory for the same reason a
 * decision's rationale is — the subject has to be told what to do next, and
 * "your verification needs more information" with no information is not an
 * instruction.
 *
 * The request is *not* decided and keeps its history: the subject re-enters
 * the evidence flow via `VerificationRequest.reopenForEvidence`, and the
 * request can cycle through this state repeatedly. See Issue 176.
 */
export class RequestMoreInformation {
  constructor(private readonly requests: VerificationRequestRepository) {}

  async execute(
    command: RequestMoreInformationCommand,
  ): Promise<Result<VerificationRequest, RequestMoreInformationError>> {
    const note = command.note.trim();
    if (note.length === 0) {
      return Result.err(
        new ValidationError("A note describing the missing information is required.", {
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

    const updated = request.requestMoreInformation({
      reviewerId: command.reviewerId,
      note,
      now: command.now ?? new Date(),
    });
    if (Result.isErr(updated)) {
      return updated;
    }

    await this.requests.save(updated.value);
    return Result.ok(updated.value);
  }
}
