import { NotFoundError, Result, ValidationError } from "@verixa/shared-kernel";

import type { ReviewerId } from "../../domain/entities/review-assignment.js";
import type {
  VerificationRequest,
  VerificationRequestId,
} from "../../domain/entities/verification-request.js";
import type { InvalidStatusTransitionError } from "../../domain/errors/invalid-status-transition.js";
import type { ReviewDecisionNotPermittedError } from "../../domain/errors/review-decision-not-permitted.js";
import type { VerificationRequestRepository } from "../ports/verification-request-repository.js";

export interface ApproveVerificationCommand {
  readonly requestId: VerificationRequestId;
  readonly reviewerId: ReviewerId;
  /** Why the request was approved. Mandatory and non-empty. */
  readonly note: string;
  /** Injected clock for tests; defaults to `new Date()`. */
  readonly now?: Date;
}

export type ApproveVerificationError =
  ValidationError | NotFoundError | InvalidStatusTransitionError | ReviewDecisionNotPermittedError;

/**
 * Records a reviewer's decision to approve a verification request.
 *
 * ## Why the rationale note is mandatory
 *
 * This is a governance requirement, not UX polish. A verification approval
 * grants a person a trusted status that later has to be defensible — to an
 * auditor, to a regulator, or to the subject if the decision is disputed
 * months later. "Who approved this and on what basis" is exactly the kind of
 * question a decision log exists to answer, and a decision recorded with no
 * reason cannot answer it.
 *
 * The requirement lives here rather than on the aggregate for the same reason
 * `SuspendUser`'s reason does (see `docs/guides/use-cases.md`): a
 * `VerificationRequest` *can* be approved without a note — what is forbidden
 * is this administrative *action* being taken without one.
 *
 * ## Why the request is loaded then decided
 *
 * Authorization ("you hold this case") and legality ("this request is in a
 * state that can be approved") are checked by the aggregate from its own
 * current state, not re-derived here. The use case loads the current
 * aggregate, asks it to decide, and persists the result — so two reviewers
 * racing on the same case both load `in_review`, and the second one's
 * aggregate decision fails on the claim check rather than silently
 * double-deciding. See Issue 175.
 */
export class ApproveVerification {
  constructor(private readonly requests: VerificationRequestRepository) {}

  async execute(
    command: ApproveVerificationCommand,
  ): Promise<Result<VerificationRequest, ApproveVerificationError>> {
    const note = command.note.trim();
    if (note.length === 0) {
      return Result.err(
        new ValidationError("A rationale note is required to approve a verification request.", {
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

    const approved = request.approve({
      reviewerId: command.reviewerId,
      note,
      now: command.now ?? new Date(),
    });
    if (Result.isErr(approved)) {
      return approved;
    }

    await this.requests.save(approved.value);

    // The returned aggregate carries the `VerificationDecided` event; pulling
    // and publishing it is the composition root's job once a publisher exists
    // (see `docs/guides/domain-events.md`), exactly as with `RegisterUser`.
    return Result.ok(approved.value);
  }
}
