# Threat Model: Identity Verification Workflow

This document presents a **STRIDE-based threat model** for Phase 09 — Identity Verification (`packages/verification`).

It analyzes threats across the verification request lifecycle, evidence submission and storage, automated provider integration, and manual review workflow, explicitly mapping each threat to its mitigating implementation issue(s) or documenting accepted risk tradeoffs.

---

## The Core Security Thesis

Identity verification (KYC-style workflows) handles some of the most sensitive personal data in the entire platform: government-issued ID documents, facial biometric images (selfies), proof-of-address documents, and personally identifiable information (PII) extracted from these sources.

The threat landscape therefore extends beyond typical application security concerns:

> **The primary threats are unauthorized access to evidence artifacts, tampering with verification decisions, and data exfiltration through provider integration points or reviewer access.**

While code-level vulnerabilities remain relevant (injection attacks, authentication bypass, race conditions), the highest-severity security failures in identity verification stem from:

1. **Evidence confidentiality breaches** — leaked government IDs or biometric images
2. **Decision integrity failures** — spoofed approvals or rejections
3. **Provider trust boundary violations** — malicious or compromised third-party KYC vendors
4. **Reviewer access control failures** — unauthorized queue access or cross-tenant data exposure
5. **Queue manipulation** — duplicate processing, claim theft, or stale assignment locks

This threat model demonstrates how Verixa's verification architecture addresses each category through defense-in-depth controls spanning cryptography, access control, state machine enforcement, and audit logging.

---

## Architectural Boundaries & Failure Stance

Verixa's identity verification architecture consists of components spanning request submission, evidence storage, automated provider checks, manual review workflow, and decision recording. Security controls enforce **explicit state transitions** and **fail-closed access policies** at every boundary.

```
                     +--------------------------------+
                     |   User/Subject: Submit Request |
                     |     (Issue 167)                |
                     +--------------+-----------------+
                                    |
                                    v
                     +--------------+-----------------+
                     | Evidence Submission & Storage  |
                     | (Issue 168, 166, 169)          |
                     +--------------+-----------------+
                                    |
                    +---------------+---------------+
                    |                               |
                    v                               v
      +-------------+-------------+   +-------------+-------------+
      | Automated Provider Check  |   |   Manual Review Queue     |
      |    (Issue 170, 171, 172)  |   |  (Issue 173, 174, 177)    |
      +-------------+-------------+   +-------------+-------------+
                    |                               |
                    +---------------+---------------+
                                    |
                                    v
                     +--------------+-----------------+
                     |  Verification Decision Record  |
                     |    (Issue 175, 176)            |
                     +--------------------------------+
```

### Component Failure Policy

Every component in the verification workflow enforces strict fail-closed behavior:

| Component                      | Failure Mode                                              | Behavior & Security Stance                                                                                                                                             | Mitigating Issue     |
|:-------------------------------|:----------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------|
| **Evidence Storage**           | S3/storage backend unavailable, encryption failure        | **Fail Closed.** Evidence submission returns error to user. Request remains in `pending_evidence` state. No evidence bytes are accepted if encryption fails.           | Issue 166            |
| **Malware Scanner**            | Scanner timeout, service unavailable                      | **Fail Closed.** Evidence submission is rejected. No file reaches storage if scanner cannot verify safety.                                                             | Issue 169            |
| **Verification Provider**      | Provider API timeout, network failure, invalid response   | **Fail Safe.** Automated check result records as `inconclusive`. Request transitions to `in_review` for manual reviewer decision. No auto-approval on provider failure. | Issue 170, 172       |
| **Review Queue Assignment**    | Database lock timeout, concurrent claim collision         | **Fail Safe.** Claim attempt returns error. Reviewer must retry. No double-assignment occurs due to `SELECT FOR UPDATE SKIP LOCKED` serialization.                     | Issue 174            |
| **Status Transition**          | Illegal state transition attempted                        | **Fail Closed.** State machine (Issue 162) rejects transition with domain error. Request remains in prior state. Audit log records attempted illegal transition.       | Issue 162            |

---

## STRIDE Threat Analysis

### 1. Spoofing (Identity & Evidence Authenticity)

#### Threat S-1: Forged Evidence Upload (Tampered Government ID)

- **Description**: An attacker uploads a digitally altered or fabricated government ID document (e.g., Photoshopped passport, deepfaked selfie) attempting to pass identity verification.
- **Impact**: Fraudulent account approval, identity theft, regulatory non-compliance (KYC/AML failures).
- **Mitigation**:
  - **Automated Provider Integration** (Issue 170, 171): Pluggable provider adapter allows integration with specialized KYC vendors (Onfido, Jumio, etc.) that perform document authenticity checks, liveness detection, and forensic image analysis.
  - **Manual Review Workflow** (Issue 173-177): Even when automated checks pass, requests flow through human reviewer queue for final approval. This two-stage verification (automated + human) catches sophisticated forgeries that automated systems miss.
  - **Accepted Risk**: Verixa does not implement its own computer-vision-based forgery detection. Detection quality depends entirely on the configured provider adapter. Operators must choose reputable KYC vendors with proven anti-fraud capabilities.

#### Threat S-2: Reviewer Impersonation

- **Description**: An attacker gains access to reviewer credentials or JWT tokens and claims/decides verification cases they are not authorized to handle.
- **Impact**: Unauthorized approval of verification requests, potential collusion with fraudulent applicants.
- **Mitigation**:
  - **RBAC Integration** (Issue 178, dependency on Phase 04): Review queue routes (`/verification/review-queue`) require explicit `reviewer` role. Non-reviewer users receive 403 Forbidden.
  - **Claim Attribution** (Issue 175): Every approve/reject decision records `decidedBy` (reviewer ID) and `rationale` (mandatory explanation). Attribution is immutable and auditable.
  - **Session Security** (Dependency on Phase 05): Reviewer JWTs are short-lived, require MFA for sensitive role assignment, and are invalidated on role revocation.

#### Threat S-3: Evidence Substitution Post-Upload

- **Description**: After a user uploads legitimate evidence, an attacker with storage access replaces the file with a different document before review occurs.
- **Impact**: Reviewer sees altered evidence, potentially leading to incorrect decision based on substituted documents.
- **Mitigation**:
  - **Cryptographic Checksums** (Issue 165): Each `Evidence` entity stores a SHA-256 checksum of the uploaded file at submission time. Any retrieval for review re-computes the checksum and rejects mismatches.
  - **Immutable Storage References** (Issue 166): `Evidence.storageRef` is an opaque pointer. The storage adapter (S3 or equivalent) uses versioned objects with immutability guarantees (S3 Object Lock). Overwrites are prevented at infrastructure level.
  - **Audit Trail** (Issue 180, dependency on Phase 10): Evidence uploads, retrieval operations, and checksum verification results are logged as audit events, making substitution attempts forensically detectable.

---

### 2. Tampering (Decision & State Manipulation)

#### Threat T-1: Verification Decision Spoofing

- **Description**: An attacker directly modifies the database to change a `rejected` verification request to `approved` status, bypassing the review workflow entirely.
- **Impact**: Fraudulent accounts gain verified status without legitimate evidence or human review. Catastrophic compliance failure.
- **Mitigation**:
  - **State Machine Enforcement** (Issue 162): `VerificationStatus` value object enforces explicit transition rules. Only `in_review` status can transition to `approved`/`rejected`. Attempting to write `approved` directly from `pending_evidence` is rejected by domain logic before database write occurs.
  - **Decision Attribution Requirements** (Issue 175): Database schema enforces `NOT NULL` constraints on `decidedBy`, `decidedAt`, and `rationale` columns for terminal states. Direct SQL UPDATE bypassing domain layer fails constraint checks.
  - **Immutable Decision Records** (Issue 162): Terminal status transitions are append-only. Once `approved` or `rejected`, no further status changes are permitted by domain model or database triggers.
  - **Audit Logging** (Dependency on Phase 10): Every status transition emits a `VerificationDecided` domain event captured in the append-only audit log. Manual database tampering is detectable via audit chain gaps or out-of-order sequence numbers.

#### Threat T-2: Race Condition in Review Queue Assignment

- **Description**: Two reviewers simultaneously claim the same verification request, both believing they own exclusive access. One reviewer's decision could overwrite the other's, or duplicate approval decisions could occur.
- **Impact**: Wasted reviewer effort, inconsistent decision records, potential for decision conflicts if both reviewers reach opposite conclusions.
- **Mitigation**:
  - **Database-Level Locking** (Issue 174): `ClaimNextReviewCase` use case uses `SELECT ... FOR UPDATE SKIP LOCKED` (PostgreSQL) to atomically claim a request. Concurrent claim attempts serialize at database level; the second transaction skips the locked row and claims the next available case.
  - **Claim Expiry** (Issue 173): `ReviewAssignment` includes `claimExpiresAt` timestamp. Stale claims (reviewer session died, browser closed) automatically release back to queue after configurable timeout. No manual cleanup required.
  - **One-at-a-Time Policy** (Issue 174): A reviewer with an active, non-expired claim cannot claim a second case. Prevents queue hoarding.

#### Threat T-3: Evidence Metadata Tampering

- **Description**: An attacker modifies `Evidence` entity metadata (e.g., changes `evidenceType` from `government-id-front` to `government-id-back`) to confuse automated checks or mislead reviewers.
- **Impact**: Automated provider receives misclassified evidence, produces incorrect check results. Reviewer UI displays wrong evidence type labels.
- **Mitigation**:
  - **Immutable Evidence Entities** (Issue 165): `Evidence` domain entity has no setter methods. Once created and persisted, all properties are readonly.
  - **Type-Evidence Pairing Validation** (Issue 165): Evidence type must be valid for the parent request's `verificationType`. Attempting to attach `proof-of-address` evidence to an `identity-document` verification fails validation.
  - **Checksum Binding** (Issue 165): Evidence checksum is computed at creation time and stored alongside metadata. Any metadata modification can be detected by comparing stored checksum against current file hash.

---

### 3. Repudiation (Decision Attribution & Audit Gaps)

#### Threat R-1: Reviewer Denies Making a Decision

- **Description**: A reviewer claims they never approved/rejected a particular request, alleging their account was compromised or the decision was fabricated.
- **Impact**: Erosion of trust in verification process, potential legal disputes, inability to prove compliance with KYC regulations.
- **Mitigation**:
  - **Mandatory Attribution** (Issue 175): Every `approved`/`rejected` decision records `decidedBy` (reviewer user ID), `decidedAt` (server timestamp), and `rationale` (human-supplied explanation). These fields are immutable and stored in the domain entity.
  - **Session Context Logging** (Dependency on Phase 10): Decision events log IP address, user agent, and session ID from the reviewer's authenticated session. Non-repudiable session evidence.
  - **MFA for Reviewers** (Dependency on Phase 06): High-privilege reviewer roles require MFA. Decision attribution includes MFA verification timestamp, raising the bar for "my account was compromised" claims.

#### Threat R-2: Audit Log Gap for Evidence Access

- **Description**: A malicious insider accesses evidence files (views government IDs or selfies) without leaving a trace, making unauthorized data exfiltration undetectable.
- **Impact**: Privacy breach, GDPR/CCPA violation, inability to demonstrate who accessed what evidence and when.
- **Mitigation**:
  - **Signed URL Access Logging** (Issue 166): Evidence retrieval uses short-lived signed URLs (5-minute expiry). Every `getSignedUrl()` call is logged as an audit event before URL generation, capturing actor, timestamp, and evidence ID.
  - **No Public URLs** (Issue 166): Evidence storage adapter never returns public or long-lived URLs. All access is gated through the application layer where audit logging occurs.
  - **Reviewer Queue Audit** (Dependency on Phase 10): Claiming a review case, viewing evidence, and rendering a decision are all logged as separate audit events with actor attribution.

#### Threat R-3: Provider Check Result Forgery

- **Description**: An attacker or malicious provider adapter reports fabricated automated check results (e.g., claims a forged document "passed" biometric liveness check).
- **Impact**: Fraudulent verification approvals based on false provider signals. Compliance failures if regulators question decision basis.
- **Mitigation**:
  - **Provider Result Provenance** (Issue 172): `ProviderCheckResult` includes `providerRawRef` (opaque external transaction/check ID from the vendor). This reference is stored alongside the check outcome in the verification request record.
  - **Vendor API Webhooks** (Future Phase): Real KYC vendors (Onfido, Jumio) provide webhook callbacks with signed payloads. Signature verification proves result authenticity. Not implemented in Issue 172's default adapter but documented as integration pattern.
  - **Manual Review Override** (Issue 172): Automated check results inform but never auto-decide. Even `passed` outcomes flow to `in_review` status for human confirmation in Phase 09. Auto-approval based on provider signal alone is deferred to Phase 16 (once trust in provider integration is established).

---

### 4. Information Disclosure (Evidence Exfiltration & Cross-Tenant Leaks)

#### Threat I-1: Cross-Tenant Evidence Access

- **Description**: A reviewer from Organization A claims a verification request from Organization B's queue and views their users' evidence (government IDs, selfies).
- **Impact**: Catastrophic multi-tenancy isolation failure. Privacy breach, regulatory violation, loss of customer trust.
- **Mitigation**:
  - **Row-Level Security** (Issue 164, dependency on Issue 052): Database `verification_requests` table uses PostgreSQL Row-Level Security (RLS) policies scoped by `organizationId`. Queries lacking tenant filter or specifying wrong tenant return zero rows even with valid SQL syntax.
  - **Tenant Context Validation** (Issue 177): `ListReviewQueue` use case enforces tenant scoping: reviewer's organization ID (from authenticated JWT) is injected into repository query filter. Cross-org filter attempts fail at application layer before reaching database.
  - **Evidence Storage Isolation** (Issue 166): Storage adapter paths include organization ID as prefix (`org-123/request-456/evidence-789.jpg`). Even with a guessed storage key, cross-org access fails at storage bucket policy level.

#### Threat I-2: Evidence URL Leakage via Logs or Referrer Headers

- **Description**: Signed evidence URLs appear in application logs, browser referrer headers, or HTTP access logs, allowing unauthorized future access if logs are compromised.
- **Impact**: Evidence exposure beyond intended reviewer, especially if logs are aggregated to third-party services or insufficiently secured.
- **Mitigation**:
  - **Short-Lived URLs** (Issue 166): Evidence signed URLs expire within 5 minutes. Leaked URLs become useless quickly. URL generation logs record evidence ID but never the full signed URL itself.
  - **No Referrer Leakage** (Issue 178): Review UI serves evidence images with `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY` headers, preventing URL leakage via referrer or iframe embedding.
  - **Structured Logging** (Dependency on Issue 008): Application logs use structured JSON format. Evidence URLs are never interpolated into log messages as strings; evidence ID is logged instead.

#### Threat I-3: Provider API Request/Response Interception

- **Description**: Network traffic between Verixa and a third-party KYC provider is intercepted (MITM attack), exposing government ID images or biometric data in transit.
- **Impact**: Evidence exfiltration during provider check execution. PII breach even if evidence storage is secure.
- **Mitigation**:
  - **TLS Enforcement** (Issue 170, 171): All provider adapters must use HTTPS endpoints. Adapter interface forbids plain HTTP connections. Certificate validation is mandatory (no self-signed certs accepted in production).
  - **Provider Response Validation** (Issue 172): Provider adapter validates API response signatures (if supported by vendor) and checks for expected schema structure. Tampered or malformed responses are rejected.
  - **Minimal Evidence Transmission** (Issue 170): Adapter interface design allows for local-only evidence check workflows where evidence never leaves Verixa infrastructure (e.g., on-premises OCR/liveness detection models). Default manual-review adapter (Issue 171) performs zero external transmission.

---

### 5. Denial of Service (Queue Flooding & Resource Exhaustion)

#### Threat D-1: Verification Request Flooding

- **Description**: An attacker submits thousands of verification requests with junk evidence files, overwhelming the review queue and storage backend.
- **Impact**: Legitimate verification requests buried in queue, reviewer capacity exhausted, storage costs spike, potential service degradation.
- **Mitigation**:
  - **Duplicate Request Prevention** (Issue 167): `SubmitVerificationRequest` rejects new requests if the subject already has an open (non-terminal) request of the same `verificationType`. Prevents one user from creating 100 concurrent requests.
  - **Rate Limiting** (Dependency on Phase 15): Verification request submission routes are rate-limited per-user and per-organization. Burst limits prevent mass submission from single actor.
  - **File Size Validation** (Issue 169): Evidence validation pipeline enforces maximum file size (e.g., 10MB per document). Oversized uploads are rejected before storage write occurs.
  - **Queue Pagination** (Issue 177): `ListReviewQueue` uses cursor-based pagination with maximum page size. UI cannot request unbounded result sets that exhaust database or application memory.

#### Threat D-2: Claim Hoarding / Queue Starvation

- **Description**: A malicious or buggy reviewer client claims multiple review cases without deciding them, starving other reviewers of work and stalling the queue.
- **Impact**: Review SLA breaches, backlog growth, uneven workload distribution among reviewers.
- **Mitigation**:
  - **One-at-a-Time Claim Policy** (Issue 174): A reviewer with an active claim cannot claim additional cases. Prevents single reviewer from hoarding 50 cases.
  - **Claim Expiry** (Issue 173): Claims auto-release after configurable timeout (e.g., 30 minutes). Stale claims from crashed sessions or abandoned work automatically return to queue.
  - **Claim Monitoring** (Issue 180, future metric): Observability dashboard tracks claim age distribution. Alerts fire when claims approach expiry without decision, indicating stuck reviewers or system issues.

#### Threat D-3: Malware Scanner DoS via Malicious Uploads

- **Description**: An attacker uploads crafted files (zip bombs, polyglot files, files with excessive compression) designed to exhaust malware scanner resources or trigger scanner crashes.
- **Impact**: Malware scanner becomes unavailable, blocking all evidence submissions. Queue processing halts.
- **Mitigation**:
  - **Pre-Scanner Validation** (Issue 169): File size and MIME type checks occur *before* malware scanning. Zip bombs and excessively large files are rejected by size limit without reaching scanner.
  - **Scanner Timeout** (Issue 169): Malware scanner invocation has strict timeout (e.g., 30 seconds). Files causing scanner hangs are rejected after timeout expires.
  - **Scanner Failure Handling** (Issue 169): Scanner unavailability is treated as fail-closed (evidence rejected), not fail-open. System degrades to "no evidence accepted" rather than "all evidence accepted without scanning."

---

### 6. Elevation of Privilege (Unauthorized Decision Authority)

#### Threat E-1: Non-Reviewer User Accesses Queue

- **Description**: A regular (non-reviewer) user crafts API requests to `/verification/review-queue` endpoints, attempting to view or claim verification cases.
- **Impact**: Unauthorized queue access, potential evidence exposure to non-privileged users.
- **Mitigation**:
  - **RBAC Enforcement** (Issue 178): All review queue routes require `reviewer` role via Phase 04's RBAC middleware. Non-reviewer JWTs are rejected with 403 Forbidden before any use case logic executes.
  - **Role Assignment Audit** (Dependency on Phase 07): Granting `reviewer` role is itself an audited, high-privilege operation. Role escalation attempts are logged and require approval workflow (out of scope for Phase 09 but documented dependency).

#### Threat E-2: Reviewer Modifies Decision After Terminal State

- **Description**: A reviewer attempts to change an `approved` verification back to `rejected` (or vice versa) after decision is recorded, covering up an error or colluding with requester.
- **Impact**: Decision integrity compromised, audit trail inconsistency, potential fraud facilitation.
- **Mitigation**:
  - **Terminal State Immutability** (Issue 162): State machine explicitly forbids transitions from `approved` or `rejected` to any other status. Attempting such transition throws domain error before database write.
  - **No Update Use Cases** (Issue 175): There is no `ModifyVerificationDecision` use case. The only decision use cases are `ApproveVerification` and `RejectVerification`, both of which validate current status is `in_review` before proceeding.
  - **Database Constraints** (Issue 164): Unique partial index or trigger prevents multiple terminal-state records for same request. Second approval/rejection attempt fails uniqueness constraint.

#### Threat E-3: Evidence Uploader Bypasses Validation Pipeline

- **Description**: An attacker directly invokes storage adapter methods, bypassing the validation pipeline (MIME check, size limit, malware scan) to upload prohibited file types or malicious content.
- **Impact**: Malware, executable files, or excessively large files reach storage, potentially compromising evidence integrity or storage availability.
- **Mitigation**:
  - **Storage Adapter Encapsulation** (Issue 166): `EvidenceStorage` port is not exported from package public API. Only `SubmitEvidence` use case has access. Route handlers cannot directly call storage adapter.
  - **Validation in Use Case** (Issue 168, 169): All validation (type, size, malware scan) occurs within `SubmitEvidence` use case before storage adapter is invoked. Storage adapter has no validation logic—it trusts its caller.
  - **Composition Root Wiring** (Issue 179): Storage adapter instances are constructed in composition root and injected into use cases. Application routes never construct adapters directly.

---

## Cross-Cutting Security Controls

### Audit Logging (Dependency: Phase 10)

Every security-relevant operation in the verification workflow emits domain events captured by Phase 10's audit log:

| Event                            | Triggered By                | Audit Fields                                                                 | Compliance Purpose                   |
|:---------------------------------|:----------------------------|:-----------------------------------------------------------------------------|:-------------------------------------|
| `verification.request.submitted` | Issue 167                   | `actorId`, `organizationId`, `verificationType`                              | KYC request initiation timestamp     |
| `verification.evidence.submitted`| Issue 168                   | `actorId`, `evidenceType`, `evidenceCount`, checksum                         | Evidence upload attribution          |
| `verification.check.automated`   | Issue 172                   | `providerName`, `outcome`, `confidenceScore`, `providerRawRef`               | Automated check result provenance    |
| `verification.review.claimed`    | Issue 174                   | `reviewerId`, `claimExpiresAt`                                               | Reviewer accountability              |
| `verification.review.approved`   | Issue 175                   | `reviewerId`, `rationale`, session context (IP, user agent)                  | Approval decision non-repudiation    |
| `verification.review.rejected`   | Issue 175                   | `reviewerId`, `rationale`, session context                                   | Rejection decision non-repudiation   |
| `verification.evidence.accessed` | Issue 166 (signed URL generation) | `actorId`, `evidenceId`, `timestamp`                                  | Evidence access forensics            |

All events include server-side timestamps and are append-only. Retroactive tampering is detectable via Phase 10's hash-chain verification.

### Encryption at Rest

- **Evidence Files** (Issue 166): All evidence artifacts stored via storage adapter are encrypted at rest using S3 SSE-KMS (AWS) or equivalent encryption mechanism in other cloud/on-prem storage backends. Encryption keys are rotated per compliance policy.
- **Database Encryption** (Infrastructure-level): Verification request and evidence metadata tables use database-level transparent encryption (TDE) provided by PostgreSQL or cloud database service.

### Network Security

- **TLS Everywhere**: All HTTP APIs (Issue 178) enforce HTTPS. Provider adapters (Issue 170) use TLS for external vendor communication. Evidence signed URLs use HTTPS schemes only.
- **No CORS for Sensitive Routes**: Evidence retrieval and review decision endpoints do not expose CORS headers. Only same-origin UI can invoke these routes, preventing CSRF and cross-origin data exfiltration.

---

## Accepted Risks & Residual Threats

### AR-1: Insider Threat (Malicious Reviewer)

**Risk**: A legitimate reviewer with valid credentials and `reviewer` role intentionally approves fraudulent verification requests in exchange for payment (bribery/collusion).

**Why Accepted**: Technical controls cannot fully prevent deliberate insider abuse by authorized users. Mitigation relies on:
- Audit logging (Phase 10) making every decision traceable and non-repudiable
- Mandatory rationale fields, increasing effort required for mass collusion
- Operational monitoring: anomaly detection for reviewers with suspiciously high approval rates or abnormal decision speed patterns (Phase 24 - observability)
- Background checks and contractual obligations for reviewer role assignment (out of scope for application code)

**Residual Risk Level**: Medium (requires human process controls beyond software)

### AR-2: Deepfake Sophistication Arms Race

**Risk**: As deepfake technology advances, forged selfies and altered ID documents may become indistinguishable from genuine evidence to both automated providers and human reviewers.

**Why Accepted**: Forgery detection is a specialized domain requiring ongoing research investment by dedicated vendors (Onfido, iProov, etc.). Verixa provides the integration adapter (Issue 170) but does not attempt to build proprietary computer-vision-based forgery detection.

**Mitigation Strategy**: Operational reliance on reputable third-party KYC vendors with R&D budgets for anti-forgery techniques. Vendor selection is deployment-time decision per regulatory requirements and risk appetite.

**Residual Risk Level**: High in zero-trust environments; Medium with high-quality vendor integration

### AR-3: Provider Vendor Compromise

**Risk**: A third-party KYC vendor is breached, and attacker gains access to verification evidence transmitted to vendor APIs or falsifies check results returned to Verixa.

**Why Accepted**: Verixa has no control over vendor security posture beyond TLS enforcement and API signature validation. Risk acceptance is inherent in outsourced verification model.

**Mitigation Strategy**:
- TLS certificate validation (Issue 170) prevents MITM
- Manual review override (Issue 172) ensures human decision even if provider result is forged
- Contractual vendor audit requirements (SOC 2, ISO 27001) and SLA penalties for breaches (procurement-level control, out of scope)

**Residual Risk Level**: Medium to High depending on vendor choice

### AR-4: Phishing for Evidence Access

**Risk**: Attacker phishes reviewer credentials or steals authenticated session token, then accesses evidence queue to exfiltrate government ID images.

**Why Accepted**: Credential phishing is a general authentication threat not unique to verification workflow. Full prevention requires user education, device security, and MFA enforcement.

**Mitigation Strategy**:
- MFA required for reviewer role (dependency on Phase 06)
- Short session TTLs for high-privilege roles
- Audit logging of evidence access for forensic detection post-breach
- IP allowlisting for reviewer access (operational control, Phase 24)

**Residual Risk Level**: Medium (standard phishing risk shared across all privileged roles)

---

## Threat Mitigation Summary Table

| Threat ID | Threat Category       | Severity | Mitigating Issues                     | Residual Risk |
|:----------|:----------------------|:---------|:--------------------------------------|:--------------|
| S-1       | Forged Evidence       | High     | 170, 171, 173-177 (manual review)     | Medium        |
| S-2       | Reviewer Impersonation| High     | 175, 178, Phase 04 (RBAC), Phase 05   | Low           |
| S-3       | Evidence Substitution | Critical | 165, 166, 180, Phase 10               | Low           |
| T-1       | Decision Spoofing     | Critical | 162, 175, Phase 10                    | Low           |
| T-2       | Queue Race Condition  | Medium   | 173, 174                              | Low           |
| T-3       | Evidence Metadata Tampering | Medium | 165, 169                            | Low           |
| R-1       | Reviewer Denies Decision | High  | 175, Phase 06, Phase 10               | Low           |
| R-2       | Evidence Access Gap   | High     | 166, Phase 10                         | Low           |
| R-3       | Provider Result Forgery | Medium | 172, 170 (signature validation)       | Medium        |
| I-1       | Cross-Tenant Leak     | Critical | 164, 177, 052 (RLS)                   | Low           |
| I-2       | URL Leakage           | Medium   | 166, 178, 008 (structured logs)       | Low           |
| I-3       | Provider MITM         | High     | 170, 171 (TLS enforcement)            | Low           |
| D-1       | Request Flooding      | Medium   | 167, 169, Phase 15 (rate limiting)    | Medium        |
| D-2       | Claim Hoarding        | Low      | 173, 174                              | Low           |
| D-3       | Scanner DoS           | Medium   | 169                                   | Low           |
| E-1       | Unauthorized Queue Access | High | 178, Phase 04                         | Low           |
| E-2       | Decision Modification | Critical | 162, 175                              | Low           |
| E-3       | Validation Bypass     | High     | 168, 169, 179 (encapsulation)         | Low           |

---

## Conclusion

Phase 09's identity verification workflow addresses a uniquely sensitive threat surface: government-issued identity documents, biometric images, and high-stakes verification decisions with regulatory and fraud implications.

The architecture's defense-in-depth approach combines:

1. **Cryptographic integrity** (checksums, signed URLs, TLS)
2. **State machine invariants** (Issue 162) preventing illegal transitions
3. **Multi-layered access control** (RBAC, RLS, tenant scoping)
4. **Comprehensive audit logging** (Phase 10 integration)
5. **Fail-closed failure handling** (scanner unavailable → reject, provider timeout → manual review)

Residual threats primarily stem from inherent limitations (insider threat, advanced deepfakes, vendor compromise) that require operational and contractual controls beyond application code.

The threat model will be revisited in Phase 16 when auto-approval workflows are introduced, which escalate risk profiles for provider trust and decision automation.
