import { createId } from "@verixa/shared-kernel";

import { verificationRequestRepositoryContract } from "./contracts/verification-request-repository.contract.js";
import { InMemoryVerificationRequestRepository } from "./in-memory-verification-request-repository.js";

// The fake has no referential integrity, so any branded ids will do; the
// Prisma adapter's spec supplies ids that actually exist.
verificationRequestRepositoryContract(
  () => new InMemoryVerificationRequestRepository(),
  () =>
    Promise.resolve({
      subjectUserId: createId<"VerificationSubjectId">(),
      otherSubjectUserId: createId<"VerificationSubjectId">(),
      organizationId: createId<"VerificationOrganizationId">(),
    }),
);
