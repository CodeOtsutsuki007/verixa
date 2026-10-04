// Curated public surface of @verixa/verification. Nothing outside this package
// should import from a deep path (`@verixa/verification/domain/...`) — the
// eslint boundary rule enforces it. See docs/guides/domain-modeling.md
// ("Package encapsulation").

// Domain: value objects
export {
  EvidenceType,
  type EvidenceTypeValue,
  isEvidenceType,
  requiredEvidenceTypesFor,
} from "./domain/value-objects/evidence-type.js";
export {
  isVerificationStatus,
  TERMINAL_STATUSES,
  VerificationStatus,
  type VerificationStatusValue,
} from "./domain/value-objects/verification-status.js";
export {
  isVerificationType,
  VerificationType,
  type VerificationTypeValue,
} from "./domain/value-objects/verification-type.js";

// Domain: entities and their identifier types
export { Evidence, type EvidenceId, isValidSha256Hex } from "./domain/entities/evidence.js";
export {
  DEFAULT_CLAIM_TTL_MS,
  ReviewAssignment,
  type ReviewerId,
} from "./domain/entities/review-assignment.js";
export {
  VerificationRequest,
  type VerificationDecision,
  type VerificationOrganizationId,
  type VerificationRequestId,
  type VerificationRequestProps,
  type VerificationSubjectId,
} from "./domain/entities/verification-request.js";

// Domain: errors
export { InvalidStatusTransitionError } from "./domain/errors/invalid-status-transition.js";
export { ReviewClaimConflictError } from "./domain/errors/review-claim-conflict.js";
export { ReviewDecisionNotPermittedError } from "./domain/errors/review-decision-not-permitted.js";

// Domain: events
export {
  VerificationDecided,
  type VerificationDecidedParams,
  type VerificationDecisionValue,
} from "./domain/events/verification-decided.js";

// Application: DTOs
export {
  MAX_CONFIDENCE_SCORE,
  ProviderCheckResult,
  type ProviderCheckOutcome,
} from "./application/dtos/provider-check-result.js";

// Application: ports (for infrastructure adapters and the composition root)
export type { VerificationProvider } from "./application/ports/verification-provider.js";
export type {
  ClaimNextInReviewParams,
  ClaimNextOutcome,
  QueueCandidateOptions,
  VerificationRequestRepository,
} from "./application/ports/verification-request-repository.js";

// Application: use cases
export {
  ApproveVerification,
  type ApproveVerificationCommand,
  type ApproveVerificationError,
} from "./application/use-cases/approve-verification.js";
export {
  ClaimNextReviewCase,
  type ClaimNextReviewCaseCommand,
  type ClaimNextReviewCasePolicy,
} from "./application/use-cases/claim-next-review-case.js";
export {
  RejectVerification,
  type RejectVerificationCommand,
  type RejectVerificationError,
} from "./application/use-cases/reject-verification.js";
export {
  RequestMoreInformation,
  type RequestMoreInformationCommand,
  type RequestMoreInformationError,
} from "./application/use-cases/request-more-information.js";

// Infrastructure: adapters. Exported so the composition root can construct
// them — it is the one place allowed to know which concrete implementation is
// in use.
export { ManualReviewProvider } from "./infrastructure/providers/manual-review-provider.js";
export { PrismaVerificationRequestRepository } from "./infrastructure/persistence/prisma-verification-request-repository.js";

// Infrastructure: testing fakes, for contexts that build on verification.
export { InMemoryVerificationRequestRepository } from "./infrastructure/testing/in-memory-verification-request-repository.js";
