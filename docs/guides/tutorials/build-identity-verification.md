# Tutorial: Building an Identity Verification Workflow

This tutorial walks through the complete identity verification system in Phase 09 (`packages/verification`), explaining the request → evidence → automated-check → review → decision flow using real code from the repository.

By the end, you'll understand:
- Why verification is modeled as a separate bounded context from Identity
- How the status state machine prevents illegal transitions
- How evidence storage and provider adapters maintain a clean architecture
- How the manual review queue handles concurrency and assignment fairness
- How every decision is attributed, auditable, and non-repudiable

This is **not** an API usage guide (see OpenAPI spec for that). It's a deep dive into the design decisions, showing you *why* the code is shaped this way and what problems each pattern solves.

---

## Why Verification Is Not Part of Identity

The most fundamental design decision in Phase 09 is that identity verification lives in `packages/verification`, **not** `packages/identity`.

### The Separation Rationale

Adding verification fields directly to the `User` entity would be simpler in the short term:

```typescript
// ❌ What we explicitly did NOT do
class User {
  readonly id: UserId;
  readonly email: Email;
  readonly displayName: DisplayName;
  readonly verificationStatus: "pending" | "approved" | "rejected";  // ← Tempting but wrong
  readonly governmentIdUrl?: string;  // ← Coupling domain model to storage
  readonly verificationCompletedAt?: Date;
}
```

This approach fails on multiple dimensions:

1. **Single Responsibility Violation**: `User` represents a person's profile and account status. Verification is a *process* that happens to a user, not an intrinsic property of user identity. Mixing the two means every change to verification workflow (adding evidence types, provider integration, review queues) touches the Identity context.

2. **Impossible State Representation**: What does it mean for a user to have `verificationStatus: "pending"` but no evidence uploaded? Or `verificationStatus: "approved"` but no `verificationCompletedAt` timestamp? Modeling verification as entity properties makes these illegal states representable and relies on runtime validation to catch them.

3. **Bounded Context Boundaries**: DDD's strategic design principle is that unrelated concerns should live in separate bounded contexts with explicit integration points. Identity (who a user is) and Verification (proving who they claim to be) are related but distinct concerns, like Inventory and Shipping in an e-commerce system—tightly coupled operationally, cleanly separated architecturally.

4. **Audit and Compliance Separation**: Verification involves government-issued documents, biometric data, and decisions with legal/regulatory weight. These artifacts have different retention policies, access controls, and audit requirements than user profile data. Storing them in the same context forces one-size-fits-all security policies.

### The Aggregate Root: `VerificationRequest`

Instead, verification is modeled as its own aggregate:

```typescript
// packages/verification/domain/entities/verification-request.ts
class VerificationRequest {
  readonly id: VerificationRequestId;
  readonly subjectUserId: UserId;  // ← References Identity context
  readonly organizationId: OrganizationId;
  readonly verificationType: VerificationType;  // e.g., "identity-document"
  private status: VerificationStatus;
  private evidence: Evidence[];
  readonly createdAt: Date;
  private decidedAt?: Date;
  private decidedBy?: ReviewerId;
  
  // Behavior, not setters
  submitEvidence(item: Evidence): Result<void, SubmitEvidenceError> { /* ... */ }
  transitionTo(newStatus: VerificationStatus): Result<void, TransitionError> { /* ... */ }
  recordDecision(reviewerId: ReviewerId, rationale: string): void { /* ... */ }
}
```

**Key properties**:
- `VerificationRequest` owns its lifecycle (`status`) and child entities (`evidence`)
- The `User` entity in `packages/identity` is unaware verification exists
- Integration happens via `subjectUserId` foreign key and domain events (`VerificationDecided`)
- Multiple verification requests can exist for one user (initial verification, re-verification after document expiry, address verification separate from identity verification)

---

## The Status State Machine: Making Illegal States Unrepresentable

The second core design is the explicit status state machine that governs request lifecycle.

### The Complete Transition Table

Issue 162 implements `VerificationStatus` as a value object with an exhaustive transition table:

```typescript
// packages/verification/domain/value-objects/verification-status.ts
export type VerificationStatusValue =
  | "pending_evidence"    // Initial state: waiting for user to upload docs
  | "submitted"           // Evidence complete, ready for automated check
  | "in_review"           // Under human reviewer evaluation
  | "needs_more_info"     // Reviewer requests additional evidence
  | "approved"            // Terminal: verification passed
  | "rejected";           // Terminal: verification failed

class VerificationStatus {
  private constructor(private readonly value: VerificationStatusValue) {}

  canTransitionTo(next: VerificationStatus): boolean {
    const transitions: Record<VerificationStatusValue, VerificationStatusValue[]> = {
      pending_evidence: ["submitted"],
      submitted: ["in_review"],
      in_review: ["approved", "rejected", "needs_more_info"],
      needs_more_info: ["pending_evidence"],  // ← Loop back for re-submission
      approved: [],   // Terminal: no further transitions
      rejected: [],   // Terminal: no further transitions
    };

    return transitions[this.value].includes(next.value);
  }

  transitionTo(next: VerificationStatus): Result<VerificationStatus, InvalidTransitionError> {
    if (!this.canTransitionTo(next)) {
      return Result.err(new InvalidTransitionError(this.value, next.value));
    }
    return Result.ok(next);
  }
}
```

### Why Explicit Beats Implicit

Without the state machine, status transitions would be scattered across use cases as unstructured string assignments:

```typescript
// ❌ Anti-pattern: implicit transitions
async function approveVerification(requestId: string) {
  const request = await repo.findById(requestId);
  request.status = "approved";  // What if current status is "pending_evidence"?
  await repo.save(request);     // No validation, database accepts anything
}
```

Problems:
- Nothing prevents jumping from `pending_evidence` directly to `approved` (bypassing review entirely)
- Terminal status immutability is a comment in the code, not enforced
- The cyclic `needs_more_info` → `pending_evidence` loop is invisible; developers might assume all transitions are forward-only

The state machine makes these rules **compile-time knowledge**:

```typescript
// ✅ Enforced by type system
const result = currentStatus.transitionTo(VerificationStatus.approved());
if (result.isErr()) {
  // This path is forced into existence by Result<T, E> type
  throw new DomainError(`Cannot transition from ${currentStatus} to approved`);
}
```

**What you learn from this**: State machines are not over-engineering for simple workflows. They're the difference between "code that works when used correctly" and "code that can't be used incorrectly."

---

## Evidence Storage: Separating Domain from Infrastructure

Government ID images, selfies, and proof-of-address documents are the most sensitive data in the entire platform. Issue 165–166 model evidence with deliberate architectural boundaries.

### The Evidence Entity: Pointer, Not Payload

```typescript
// packages/verification/domain/entities/evidence.ts
class Evidence {
  readonly id: EvidenceId;
  readonly requestId: VerificationRequestId;
  readonly evidenceType: EvidenceType;  // "government-id-front", "selfie", etc.
  readonly storageRef: string;  // Opaque: "s3://bucket/org-123/request-456/evidence-789.enc"
  readonly checksum: string;    // SHA-256 of file bytes
  readonly uploadedAt: Date;
  readonly metadata: EvidenceMetadata;  // MIME type, size, original filename

  // Deliberately NO: readonly fileBytes: Buffer
  // Deliberately NO: readonly publicUrl: string
}
```

**Why `storageRef` is opaque**:
- The domain layer must never know whether storage is S3, local filesystem, Azure Blob, or a future provider
- Leaking `s3://` into the domain would couple entity serialization to AWS SDK types
- An opaque string lets infrastructure adapters use whatever addressing scheme they need (UUIDs, content hashes, encrypted paths) without domain model changes

**Why checksum is first-class**:
- Stored alongside metadata, not computed on-demand
- Allows verification that retrieved file matches uploaded file, detecting tampering or substitution
- Enables deduplication (same file uploaded twice → same checksum → storage adapter can reuse blob)

### The Storage Port

```typescript
// packages/verification/application/ports/evidence-storage.ts
interface EvidenceStorage {
  put(
    organizationId: OrganizationId,
    requestId: VerificationRequestId,
    file: FileUpload,
  ): Promise<Result<StorageReference, StorageError>>;

  getSignedUrl(
    storageRef: string,
    expiresInSeconds: number,
  ): Promise<Result<SignedUrl, StorageError>>;

  delete(storageRef: string): Promise<Result<void, StorageError>>;
}
```

**Why signed URLs, not public paths**:
- Public URLs are permanent: leak one into logs → evidence is exposed forever
- Signed URLs expire (default: 5 minutes): leaked URL becomes useless quickly
- URL generation is auditable: every `getSignedUrl()` call logs actor + timestamp (Phase 10 audit event)

**Encryption at rest** (Issue 166): Concrete implementations (S3, local filesystem) handle encryption:

```typescript
// packages/verification/infrastructure/storage/s3-evidence-storage.ts
class S3EvidenceStorage implements EvidenceStorage {
  async put(orgId: string, requestId: string, file: FileUpload) {
    // Server-side encryption with KMS-managed keys (SSE-KMS)
    await this.s3Client.putObject({
      Bucket: this.bucketName,
      Key: `${orgId}/${requestId}/${uuid()}.enc`,
      Body: file.buffer,
      ServerSideEncryption: "aws:kms",
      SSEKMSKeyId: this.kmsKeyId,  // Rotated per compliance policy
      Metadata: { checksum: file.checksum, mimeType: file.mimeType },
    });
  }
}
```

Domain layer never sees encryption keys, S3 SDK imports, or KMS configuration. It only sees `Result<StorageReference, StorageError>`.

---

## Automated Providers: The Adapter Pattern in Action

Third-party KYC vendors (Onfido, Jumio, Persona, etc.) each have bespoke APIs with different request/response formats, authentication schemes, and confidence-scoring models. Issue 170 abstracts them behind a **provider port**.

### The Port: Vendor-Agnostic Interface

```typescript
// packages/verification/application/ports/verification-provider.ts
interface VerificationProvider {
  checkDocument(evidence: Evidence): Promise<ProviderCheckResult>;
  checkLiveness(evidence: Evidence): Promise<ProviderCheckResult>;
}

type ProviderCheckResult = {
  outcome: "passed" | "failed" | "inconclusive";
  confidenceScore: number;  // 0.0 to 1.0, normalized across providers
  providerRawRef: string;   // Vendor's transaction ID for audit trail
  details?: Record<string, unknown>;  // Vendor-specific metadata (not exposed to use cases)
};
```

**Why not `OnfidoCheckResult` or `JumioCheckResult`?**
- Use cases (Issue 172 `RunAutomatedCheck`) depend on the port, not a concrete adapter
- Swapping vendors is a configuration change, not a code change
- Tests use a fake `ManualReviewProvider` (always returns `inconclusive`) without needing Onfido API keys

### The Default Adapter: Manual Review

Issue 171 ships a no-op adapter that routes everything to human review:

```typescript
// packages/verification/infrastructure/providers/manual-review-provider.ts
class ManualReviewProvider implements VerificationProvider {
  async checkDocument(evidence: Evidence): Promise<ProviderCheckResult> {
    return {
      outcome: "inconclusive",
      confidenceScore: 0.0,
      providerRawRef: "manual-review",  // No external vendor involved
      details: { reason: "Manual review required (no automated provider configured)" },
    };
  }

  async checkLiveness(evidence: Evidence): Promise<ProviderCheckResult> {
    return { outcome: "inconclusive", confidenceScore: 0.0, providerRawRef: "manual-review" };
  }
}
```

**Why this is the default**:
- Verixa works fully out-of-the-box without signing up for Onfido/Jumio accounts
- Contributors can run the complete verification flow end-to-end in tests and local dev
- Production deployments opt-in to automated providers via environment variable configuration:

```typescript
// apps/api/src/composition-root.ts
const providerType = process.env.VERIFICATION_PROVIDER ?? "manual";

const provider: VerificationProvider =
  providerType === "onfido"
    ? new OnfidoProviderAdapter({ apiKey: process.env.ONFIDO_API_KEY! })
    : new ManualReviewProvider();
```

### Real Adapter Example: Onfido (Conceptual)

A real Onfido adapter (Phase 16+) would look like:

```typescript
class OnfidoProviderAdapter implements VerificationProvider {
  constructor(private readonly client: OnfidoSDK) {}

  async checkDocument(evidence: Evidence): Promise<ProviderCheckResult> {
    // 1. Upload evidence to Onfido's storage
    const onfidoDocumentId = await this.client.uploadDocument({
      file: await this.retrieveFile(evidence.storageRef),  // Signed URL → bytes
      type: this.mapEvidenceType(evidence.evidenceType),
    });

    // 2. Create a document check
    const check = await this.client.createCheck({
      applicantId: evidence.requestId,  // Onfido's identifier
      documentIds: [onfidoDocumentId],
      reportNames: ["document", "facial_similarity"],
    });

    // 3. Poll for result (Onfido is async)
    const result = await this.pollCheckResult(check.id, { timeoutMs: 30000 });

    // 4. Normalize to ProviderCheckResult
    return {
      outcome: this.mapOutcome(result.status),  // "clear" → "passed", "consider" → "inconclusive"
      confidenceScore: result.breakdown.document.authenticity.score / 100,
      providerRawRef: check.id,  // Onfido check ID for audit/debugging
      details: { onfidoResult: result },  // Full response, not used by use cases
    };
  }
}
```

Use cases never see Onfido SDK types—they work against `ProviderCheckResult`, and the adapter handles translation.

---

## The Review Queue: Concurrency Without Races

Manual review (Issues 173–177) is where the hardest concurrency problems live. Multiple reviewers compete for the same pool of unassigned cases, and double-processing must be impossible.

### The Naive Approach (What We Don't Do)

```typescript
// ❌ Race-prone queue implementation
async function claimNextCase(reviewerId: string) {
  const cases = await repo.find({ status: "in_review", assignedTo: null }, { limit: 1 });
  if (cases.length === 0) return null;

  const claimed = cases[0];
  claimed.assignedTo = reviewerId;
  claimed.claimedAt = new Date();
  await repo.save(claimed);  // ← RACE: two reviewers can both pass the find() check
  return claimed;
}
```

**Timeline of failure**:
```
Time T+0:  Reviewer A: SELECT * FROM requests WHERE assigned_to IS NULL LIMIT 1;
           → returns request-123

Time T+1:  Reviewer B: SELECT * FROM requests WHERE assigned_to IS NULL LIMIT 1;
           → returns request-123 (still unassigned from DB perspective)

Time T+2:  Reviewer A: UPDATE requests SET assigned_to = 'A' WHERE id = 'request-123';
           ✓ success

Time T+3:  Reviewer B: UPDATE requests SET assigned_to = 'B' WHERE id = 'request-123';
           ✓ success (overwrites A's claim)
```

Result: Both reviewers believe they own the case. One's decision will be lost or cause a constraint violation.

### The Correct Approach: Database-Level Locking

Issue 174 uses PostgreSQL's `FOR UPDATE SKIP LOCKED`:

```typescript
// packages/verification/application/use-cases/claim-next-review-case.ts
class ClaimNextReviewCase {
  async execute(reviewerId: ReviewerId): Promise<Result<VerificationRequest, ClaimError>> {
    return this.repo.claimNextForReview(reviewerId);
  }
}

// packages/verification/infrastructure/persistence/prisma-verification-request-repository.ts
class PrismaVerificationRequestRepository {
  async claimNextForReview(reviewerId: string): Promise<VerificationRequest | null> {
    // Raw SQL for Postgres-specific locking
    const [claimed] = await this.prisma.$queryRaw<VerificationRequestRow[]>`
      UPDATE verification_requests
      SET assigned_to = ${reviewerId},
          claimed_at = NOW(),
          claim_expires_at = NOW() + INTERVAL '30 minutes'
      WHERE id = (
        SELECT id
        FROM verification_requests
        WHERE status = 'in_review'
          AND (assigned_to IS NULL OR claim_expires_at < NOW())  -- Unclaimed or expired
          AND organization_id = ${getCurrentTenantId()}  -- RLS enforcement
        ORDER BY created_at ASC  -- FIFO fairness
        LIMIT 1
        FOR UPDATE SKIP LOCKED  -- ← The magic
      )
      RETURNING *;
    `;

    return claimed ? this.mapToDomain(claimed) : null;
  }
}
```

**How `FOR UPDATE SKIP LOCKED` prevents races**:
1. Reviewer A's transaction locks request-123 with `FOR UPDATE`
2. Reviewer B's concurrent transaction sees request-123 is locked
3. Instead of waiting (`FOR UPDATE` alone would block), `SKIP LOCKED` makes B's query skip request-123 and select request-124 (the next unclaimed case)
4. Both reviewers get different cases atomically

**Claim expiry** (Issue 173):
- `claim_expires_at = NOW() + INTERVAL '30 minutes'` auto-releases stale claims
- A reviewer whose browser crashes doesn't permanently lock a case
- The query's `OR claim_expires_at < NOW()` clause treats expired claims as claimable

**One-at-a-time policy**:
```typescript
async claimNextForReview(reviewerId: string): Promise<Result<Request, ClaimError>> {
  // Pre-check: does this reviewer already have an active claim?
  const existingClaim = await this.findActiveClaimForReviewer(reviewerId);
  if (existingClaim !== null) {
    return Result.err({ type: "already_has_active_claim", existingRequestId: existingClaim.id });
  }
  // Proceed with claim...
}
```

Prevents queue hoarding (one reviewer claiming 50 cases without deciding any).

---

## Decision Recording: Non-Repudiation

Issue 175 implements `ApproveVerification` and `RejectVerification` with an emphasis on **attribution**—every decision is traceable to a specific reviewer with a specific rationale at a specific time.

### Mandatory Rationale

```typescript
// packages/verification/application/use-cases/approve-verification.ts
class ApproveVerification {
  execute(command: ApproveVerificationCommand): Promise<Result<void, ApproveError>> {
    if (command.rationale.trim().length === 0) {
      return Result.err({ type: "rationale_required" });
    }

    const request = await this.repo.findById(command.requestId);
    if (request.status !== VerificationStatus.inReview()) {
      return Result.err({ type: "invalid_status", current: request.status });
    }

    if (request.assignedTo !== command.reviewerId) {
      return Result.err({ type: "not_assigned_to_you" });  // Authorization check
    }

    // Record immutable decision
    request.recordDecision({
      decidedBy: command.reviewerId,
      decidedAt: new Date(),
      outcome: "approved",
      rationale: command.rationale,
    });

    await this.repo.save(request);

    // Emit domain event for audit log (Phase 10)
    await this.publisher.publish(
      new VerificationDecided({
        requestId: request.id,
        subjectUserId: request.subjectUserId,
        outcome: "approved",
        decidedBy: command.reviewerId,
        rationale: command.rationale,
        occurredAt: new Date(),
      }),
    );

    return Result.ok();
  }
}
```

**Why rationale is mandatory**:
- Regulatory compliance (KYC/AML): denials must be explainable to auditors
- Reviewer accountability: "I clicked the wrong button" is detectable when rationales are vague or copied
- Quality feedback: rationales are data for training reviewers and refining policies

**Why decisions are immutable**:
- Once `approved` or `rejected`, the status cannot change (state machine enforces this)
- Database schema has `NOT NULL` constraints on `decided_by`, `decided_at`, `rationale` columns for terminal states
- Direct SQL UPDATE bypassing domain layer fails constraints

### Domain Event for Audit

The `VerificationDecided` event is captured by Phase 10's audit subscriber:

```typescript
// packages/audit/infrastructure/event-handlers/verification-audit-subscriber.ts
class VerificationAuditSubscriber implements DomainEventHandler<VerificationDecided> {
  async handle(event: VerificationDecided): Promise<void> {
    await this.recordAuditEvent.execute({
      action: "verification.review.approved",  // or "rejected"
      actorId: event.decidedBy,
      resourceType: "verification_request",
      resourceId: event.requestId,
      organizationId: event.organizationId,
      metadata: {
        subjectUserId: event.subjectUserId,
        rationale: event.rationale,
        outcome: event.outcome,
      },
    });
  }
}
```

Every verification decision is now:
- Recorded in the `verification_requests` table (transaction data)
- Logged in the `audit_events` table (append-only, immutable, hash-chained per Phase 10)
- Non-repudiable: reviewer cannot deny making the decision (logged session IP, user agent, MFA verification)

---

## The `needs_more_info` Loop: Non-Linear State Machines

Issue 176 adds a realistic complication: not every verification can be decided with the first evidence submission. Reviewers need to request additional documents or clarifications.

### The Cycle

```
pending_evidence → submitted → in_review → needs_more_info → pending_evidence (cycle)
                                         ↘ approved (terminal)
                                         ↘ rejected (terminal)
```

### Why This Is Not a Separate Request

Naive approach: "more info needed → reject current request, user submits new request"

Problems:
- Loses history: why was the first request insufficient?
- Duplicate requests clutter the queue
- User experience: "I already uploaded my ID, why am I starting over?"

Better approach: Allow the same request to loop back for re-submission:

```typescript
// packages/verification/application/use-cases/request-more-information.ts
class RequestMoreInformation {
  execute(command: RequestMoreInfoCommand): Promise<Result<void, RequestMoreInfoError>> {
    const request = await this.repo.findById(command.requestId);

    if (request.status !== VerificationStatus.inReview()) {
      return Result.err({ type: "invalid_status" });
    }

    if (command.requiredEvidenceTypes.length === 0 || command.note.trim().length === 0) {
      return Result.err({ type: "missing_requirements" });
    }

    // Transition to needs_more_info
    request.transitionTo(VerificationStatus.needsMoreInfo());
    request.recordReviewerNote({
      reviewerId: command.reviewerId,
      note: command.note,  // "Please upload a clearer photo of the back of your ID"
      requiredEvidenceTypes: command.requiredEvidenceTypes,  // ["government-id-back"]
    });

    await this.repo.save(request);

    // User-facing notification (Phase 14: email/SMS)
    await this.notifier.sendMoreInfoRequest(request.subjectUserId, command.note);

    return Result.ok();
  }
}
```

User receives notification, uploads additional evidence via `SubmitEvidence`:

```typescript
// packages/verification/application/use-cases/submit-evidence.ts
class SubmitEvidence {
  execute(command: SubmitEvidenceCommand): Promise<Result<void, SubmitEvidenceError>> {
    const request = await this.repo.findById(command.requestId);

    // Accept evidence in both pending_evidence and needs_more_info states
    if (!request.canAcceptEvidence()) {
      return Result.err({ type: "cannot_accept_evidence", status: request.status });
    }

    // Store evidence, validate, etc. (same as initial submission)
    const storedEvidence = await this.storage.put(command.file);
    request.attachEvidence(storedEvidence);

    // Check if all required evidence is now present
    if (request.hasAllRequiredEvidence()) {
      request.transitionTo(VerificationStatus.submitted());
      // Automatically re-enters the workflow: submitted → (automated check) → in_review
    } else {
      request.transitionTo(VerificationStatus.pendingEvidence());  // Still waiting for more
    }

    await this.repo.save(request);
    return Result.ok();
  }
}
```

The same request cycles through:
1. `needs_more_info` (reviewer requests clarification)
2. `pending_evidence` (user uploads additional doc)
3. `submitted` (evidence complete again)
4. `in_review` (back in queue for the same or different reviewer)

All history preserved: original evidence, reviewer notes, re-submissions—everything is attached to one aggregate.

---

## Testing Strategies

### Unit Tests: Fake Repositories

```typescript
// packages/verification/infrastructure/testing/in-memory-verification-request-repository.ts
class InMemoryVerificationRequestRepository implements VerificationRequestRepository {
  private requests = new Map<VerificationRequestId, VerificationRequest>();

  async save(request: VerificationRequest): Promise<void> {
    this.requests.set(request.id, request);
  }

  async findById(id: VerificationRequestId): Promise<VerificationRequest | undefined> {
    return this.requests.get(id);
  }

  async claimNextForReview(reviewerId: ReviewerId): Promise<VerificationRequest | null> {
    // In-memory simulation of FOR UPDATE SKIP LOCKED
    for (const request of this.requests.values()) {
      if (request.status === VerificationStatus.inReview() && request.assignedTo === null) {
        request.assignTo(reviewerId);
        return request;
      }
    }
    return null;
  }
}
```

Use cases are tested against fakes with zero database:

```typescript
test("ApproveVerification requires reviewer to be assigned to the case", async () => {
  const repo = new InMemoryVerificationRequestRepository();
  const request = VerificationRequest.create({ /* ... */ });
  request.assignTo("reviewer-1");
  await repo.save(request);

  const useCase = new ApproveVerification(repo);
  const result = await useCase.execute({
    requestId: request.id,
    reviewerId: "reviewer-2",  // ← Different reviewer
    rationale: "Looks good",
  });

  expect(result.isErr()).toBe(true);
  expect(result.error.type).toBe("not_assigned_to_you");
});
```

### Integration Tests: Testcontainers

```typescript
// packages/verification/infrastructure/persistence/__tests__/prisma-repository.integration.spec.ts
describe("PrismaVerificationRequestRepository", () => {
  let container: PostgreSqlContainer;
  let prisma: PrismaClient;
  let repo: PrismaVerificationRequestRepository;

  beforeAll(async () => {
    container = await new PostgreSqlContainer().start();
    prisma = new PrismaClient({ datasources: { db: { url: container.getConnectionString() } } });
    repo = new PrismaVerificationRequestRepository(prisma);
  });

  test("claimNextForReview prevents double-claim under concurrency", async () => {
    const request = await repo.save(VerificationRequest.create({ /* ... */ }));

    // Simulate two reviewers claiming simultaneously
    const [claim1, claim2] = await Promise.all([
      repo.claimNextForReview("reviewer-1"),
      repo.claimNextForReview("reviewer-2"),
    ]);

    // One succeeds, one gets null (no double-claim)
    expect([claim1, claim2].filter((c) => c !== null)).toHaveLength(1);
  });

  afterAll(async () => {
    await prisma.$disconnect();
    await container.stop();
  });
});
```

Real database, real concurrency, real `FOR UPDATE SKIP LOCKED` semantics.

---

## What You've Learned

By building this verification workflow, you've seen:

1. **Bounded Contexts in Practice**: Verification is cleanly separated from Identity despite tight operational coupling. Integration via foreign keys + domain events, not shared tables.

2. **State Machines as First-Class Citizens**: Explicit transition tables enforce invariants at compile time. Illegal transitions are unrepresentable.

3. **Hexagonal Architecture with Adapters**: Evidence storage and KYC providers are swappable without touching use cases. Ports define contracts; adapters implement them.

4. **Database-Level Concurrency Control**: `FOR UPDATE SKIP LOCKED` is the standard pattern for fair, race-free work queues. Naive application-level locking always has race windows.

5. **Non-Repudiation Through Immutability**: Decisions are immutable aggregates + append-only audit logs + mandatory rationale. No one can claim "I didn't approve that."

6. **Fail-Closed Defaults**: Every external dependency (storage, provider, scanner) fails closed. Degraded mode is "no evidence accepted" or "route to manual review," never "approve without checks."

This is not just verification—it's a blueprint for building any high-stakes workflow where correctness, auditability, and safety matter more than convenience.

---

## Next Steps

- **Phase 10 (Audit Logging)**: Every verification action is logged as structured audit events with hash-chain integrity.
- **Phase 14 (Notifications)**: Subject users receive emails/SMS when verification is approved, rejected, or more info is needed.
- **Phase 16 (Auto-Approval Workflows)**: Integrate real KYC vendors (Onfido, Jumio) and allow auto-approval for high-confidence automated checks (with comprehensive threat model updates).
- **Phase 24 (Compliance & Retention)**: Evidence deletion policies, legal hold mechanisms, GDPR/CCPA erasure request handling.

The foundation is built. Now we scale it with real-world operational requirements.
