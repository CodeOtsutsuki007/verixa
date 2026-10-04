# Threat Model: Policy Engine & ABAC Evaluation

This document presents a **STRIDE-based threat model** for Phase 08 — Authorization: ABAC / Policy Engine (`packages/authorization`).

It analyzes threats across the policy authoring, resolution, caching, evaluation, and composition paths, explicitly mapping each threat to its mitigating implementation issue(s) or documenting accepted risk tradeoffs.

---

## The Core Security Thesis

In traditional application code, authorization vulnerabilities usually take the form of **code bugs**: unhandled null values, missing middleware checks, improper exception catching, or parameter tampering.

In a policy engine and ABAC evaluation architecture, the failure mode is fundamentally distinct:

> **The primary threat is correct engine code faithfully executing an incorrect, over-broad, or contradictory policy.**

While classical code vulnerabilities remain relevant (parser buffer overflows, regex Denial of Service, race conditions in invalidation), the highest-severity security failures stem from logical flaws in policy composition, precedence misconfigurations, attribute resolution tampering, or stale authorization caches.

This distinction dictates how security controls are distributed across Verixa:

| Verification Mechanism        | What It Catches                                                               | What It Cannot Catch                                                      | Mitigating Issue(s)      |
| :---------------------------- | :---------------------------------------------------------------------------- | :------------------------------------------------------------------------ | :----------------------- |
| **Unit & Coverage Tests**     | Engine syntax bugs, parsing errors, short-circuit evaluation logic            | Intended but insecure policies authored by human administrators           | Issue 143, 146, 147, 158 |
| **Static Analysis / Linters** | Shadowed rules, unmatchable conditions, dead policies, logical contradictions | Contextual over-granting where a broad rule was syntactically valid       | Issue 156                |
| **Dry-Run Simulation**        | Runtime evaluation mismatches against test attribute context fixtures         | Unforeseen real-world attribute combinations not present in test fixtures | Issue 155                |
| **RBAC+ABAC Composition**     | Default-deny enforcement when policy engine or attribute resolution fails     | Compromised administrative credentials authoring wildcards                | Issue 148, 152           |

---

## Architectural Boundaries & Failure Stance

Verixa's ABAC evaluation architecture consists of core components spanning authoring, resolution, decision, caching, and storage. Security controls rely on an explicit **fail-closed default stance** across every component boundary.

```
                     +---------------------------------------+
                     |         Policy Authoring / DSL        |
                     | (Parser Issue 143, Linter Issue 156)  |
                     +-------------------+-------------------+
                                         |
                                         v
 +-----------------------+   +-----------+-----------+   +-----------------------+
 |  Attribute Providers  |   |   Policy Decision Point   |   |   Policy Repository   |
 | (Pipeline Issue 145,  |-->|  (AuthorizeAction 153)    |<--| (Prisma Issue 150,    |
 |  Resolvers Issue 151) |   +-----------+-----------+   |  Redis Cache 154)     |
 +-----------------------+               |               +-----------------------+
                                         v
                             +-----------+-----------+
                             |  RBAC/ABAC Composition|
                             | (AuthService Issue 152)
                             +-----------------------+
```

### Dependency Failure Policy

Every external dependency in the evaluation path enforces strict fail-closed behavior:

| Component / Dependency             | Failure Mode                                                                     | Behavior & Security Stance                                                                                                                                                                                        | Mitigating Issue     |
| :--------------------------------- | :------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------- |
| **Attribute Providers / Pipeline** | Provider timeout, external service exception, network failure                    | **Fail Closed.** Missing attributes evaluate to `undefined`. In `Condition` comparisons, `undefined` operands evaluate to `false`. Short-circuit `AND` operations evaluate to `false`. Access is denied (`DENY`). | Issue 144, Issue 145 |
| **Resource Attribute Resolvers**   | Unregistered resource type (`UnknownResourceTypeError`), missing resource entity | **Fail Closed.** Resolver returns `undefined` for all requested attributes. Evaluation tree resolves to `false`.                                                                                                  | Issue 151            |
| **Policy Repository (Prisma/DB)**  | Database connection loss, schema error, missing policy record                    | **Fail Closed.** `AuthorizationService` catches database errors and emits an explicit `DENY` decision with `reason: "Policy repository unavailable"`. No default `PERMIT` is ever rendered.                       | Issue 149, Issue 150 |
| **Policy Cache (Redis)**           | Redis node down, network timeout, deserialization error                          | **Fail Open for Availability, Fail Closed for Access.** Redis errors degrade gracefully to direct database lookup via `PrismaPolicyRepository`. If both cache and DB fail, access is denied.                      | Issue 154            |
| **Condition Evaluator**            | Type mismatch (e.g. comparing string to number), invalid regex pattern           | **Fail Closed.** Operators return `false` on type mismatches instead of coercing types or raising unhandled runtime exceptions.                                                                                   | Issue 146, Issue 147 |

---

## STRIDE Threat Analysis

### 1. Spoofing (Identity & Attribute Context Impersonation)

#### Threat S-1: Client-Side Attribute Forgery

- **Description**: An attacker crafts HTTP headers or request payloads claiming elevated environmental or subject attributes (e.g., `X-Forwarded-For: 127.0.0.1`, `X-User-Role: admin`, or custom claim overrides) to satisfy policy conditions such as `permit if environment.ip in internal_subnets`.
- **Impact**: Unauthorized authorization grant bypassing role and attribute boundary checks.
- **Mitigation**:
  - `AttributeContext` (Issue 144) encapsulates attribute bags as immutable read-only maps.
  - The `AttributeResolutionPipeline` (Issue 145) strictly derives subject attributes from cryptographically verified identity tokens (`packages/identity`, `packages/credentials`), and populates `environment` attributes directly from verified server request properties. Client headers are never trusted directly for authorization context.

#### Threat S-2: Resource Attribute Impersonation

- **Description**: A user supplies a modified `resourceRef` (e.g., substituting another tenant's resource UUID) during a Policy Decision Point evaluation call.
- **Impact**: Access granted to target resources based on mismatched or spoofed resource attributes.
- **Mitigation**:
  - `ResourceAttributeResolver` (Issue 151) verifies that the requested resource ID exists within the corresponding bounded context and belongs to the authenticated organization tenant before returning attributes.

---

### 2. Tampering (Policy DSL & Rule Tree Modification)

#### Threat T-1: Malicious or Erroneous Policy DSL Authoring

- **Description**: A rogue administrator or buggy management UI publishes an over-broad policy DSL string (e.g., `permit if true` or `permit if resource.type == "document"` without subject scoping).
- **Impact**: Mass privilege escalation granting blanket permissions across tenants or resources.
- **Mitigation**:
  - Policy Simulation Tool (Issue 155): Dry-run CLI tool tests candidate policies against fixture contexts in CI/CD pipelines before deployment.
  - Policy Linter (Issue 156): Static analysis checks for broad rules, shadowed rules, and unconstrained permits.
  - Immutable Version History (Issue 150): Policies are append-only. Every update creates a distinct version row, enabling immediate audit traceability and rollback.

#### Threat T-2: Direct Database or Cache Modification

- **Description**: An attacker with direct write access to Redis or Postgres modifies stored policy ASTs or DSL text to inject permit rules.
- **Impact**: Persistent, untracked authorization bypass.
- **Mitigation**:
  - Redis cache keys are namespace-isolated and signed/validated upon retrieval (Issue 154). Cache miss or invalid AST falls back to persistent DB evaluation.
  - Database table `policies` enforces tenant isolation via PostgreSQL Row-Level Security (`docs/security/multi-tenancy.md`).

#### Threat T-3: AST Parser Exploitation / Injection

- **Description**: Malicious DSL text containing deeply nested, syntactically complex, or malformed constructs exploits the parser to execute arbitrary code or corrupt AST memory.
- **Impact**: Parser crash, remote code execution, or corrupted rule evaluation.
- **Mitigation**:
  - Hand-written recursive-descent lexer and parser (Issue 142, Issue 143) with zero `eval()` or dynamic code generation. The parser produces a strictly typed domain AST (`Policy`, `Rule`, `Condition`).
  - Parsing and evaluation are strictly separated: the parser contains no evaluation logic, and the evaluator operates exclusively on validated domain objects.

---

### 3. Repudiation (Unauditable Authorization Decisions & Changes)

#### Threat R-1: Unaudited Policy Modifications

- **Description**: An admin updates or archives an authorization policy, denying or granting access to users, but no historical record exists of what changed or who authorized it.
- **Impact**: Inability to perform security incident forensics or satisfy compliance mandates (SOC 2, ISO 27001).
- **Mitigation**:
  - Append-only policy storage (Issue 150): Publishing a new policy version creates a new immutable record containing the raw DSL source, parsed AST, author ID, and creation timestamp. Published policy versions are never mutated.

#### Threat R-2: Unexplained / Opaque Decision Outcomes

- **Description**: An authorization check fails or succeeds, but log outputs fail to record why the decision was rendered or which policies evaluated to `PERMIT` or `DENY`.
- **Impact**: Inability to troubleshoot security breaches or audit access control enforcement.
- **Mitigation**:
  - Policy Decision Point `AuthorizeAction` (Issue 153) produces a structured `AuthorizationDecision` DTO containing `granted` (boolean), `reason` (human-readable string), `matchedPolicyIds` (array of evaluated policy IDs), and `evaluatedAt` (timestamp), formatted for audit logging (Phase 10).

---

### 4. Information Disclosure (Attribute & Policy Reconnaissance)

#### Threat I-1: Side-Channel Leakage via PDP Error Messages

- **Description**: Detailed error messages returned by the authorization API leak internal attribute values or organization structures (e.g. `DENY: subject.department is 'Finance' but resource requires 'Executive'`).
- **Impact**: Internal network architecture and user profile details exposed to unprivileged callers.
- **Mitigation**:
  - Policy Decision Point (Issue 153) separates internal audit logs from caller-facing responses. API error responses return generic decision reason codes (`AUTHORIZATION_DENIED`), while granular policy evaluation traces are routed exclusively to secure audit logs.

#### Threat I-2: Timing Side Channels in Attribute Resolution

- **Description**: Database query latency during attribute resolution varies depending on whether a subject or resource exists in a specific organization, revealing entity presence via timing measurements.
- **Impact**: Entity enumeration and cross-tenant presence detection.
- **Mitigation**:
  - Deterministic evaluation pipeline (Issue 145) short-circuits early when subject context validation fails before invoking external resource attribute resolvers.

---

### 5. Denial of Service (Algorithmic & Resource Exhaustion)

#### Threat D-1: CPU Exhaustion via Complex AST Condition Trees

- **Description**: An attacker authors or submits requests triggering evaluation of deeply nested `AND`/`OR`/`NOT` condition trees or complex regular expressions (`matches` operator).
- **Impact**: High CPU usage per evaluation, clogging the Node.js event loop and degrading PDP throughput.
- **Mitigation**:
  - `PolicyEvaluationEngine` (Issue 146) implements strict short-circuit logic: `AND` aborts on first `false`, `OR` aborts on first `true`.
  - Condition Operator Library (Issue 147) places strict limits on regex matching operations (e.g., enforcing non-backtracking regex engines or maximum string length limits) to eliminate Regular Expression Denial of Service (ReDoS).
  - Linter (Issue 156) flags AST condition tree depth exceeding recommended thresholds.

#### Threat D-2: Exhaustion of Downstream Attribute Providers

- **Description**: A flood of authorization checks forces the `AttributeResolutionPipeline` to execute expensive database lookups or HTTP calls for every incoming request.
- **Impact**: Database connection pool exhaustion and downstream API throttling.
- **Mitigation**:
  - Fast-path RBAC evaluation (Issue 152): Coarse-grained role checks in `AuthorizationService` execute first. Requests clearly granted or denied by RBAC bypass ABAC attribute resolution entirely.
  - Policy and Decision Caching (Issue 154): Redis caches parsed policy ASTs and short-TTL request-scoped evaluation contexts.

#### Threat D-3: Cache Invalidation Stampede

- **Description**: Invalidating a frequently evaluated policy causes hundreds of concurrent PDP requests to miss cache simultaneously, hammering the persistent policy repository.
- **Impact**: Transient API latency spikes and database load surges.
- **Mitigation**:
  - `PolicyCache` (Issue 154) uses mutex-backed cache reloading (single-flight pattern) to ensure only one process reloads a given policy key on cache miss while concurrent callers await the single result.

---

### 6. Elevation of Privilege (Composition & Precedence Bugs)

#### Threat E-1: RBAC / ABAC Composition Precedence Bug

- **Description**: An application relies on `AuthorizationService` (Issue 152) to combine role-based grants (RBAC) and attribute policies (ABAC). A composition bug causes an RBAC `PERMIT` to override an explicit ABAC `DENY` policy (e.g. an admin user attempting to access a resource outside their working hours when a time-restriction policy applies).
- **Impact**: Severe privilege escalation where coarse role grants bypass fine-grained policy restrictions.
- **Mitigation**:
  - Issue 152 explicitly codifies and tests all four RBAC x ABAC decision combinations. The precedence order mandates that an explicit ABAC `DENY` **always overrides** an RBAC `PERMIT`.
  - Comprehensive integration test matrix in `packages/authorization` asserts this precedence order across all evaluation paths.

#### Threat E-2: Incorrect Combining Algorithm Selection

- **Description**: A policy set containing conflicting rules is evaluated using `permit-overrides` instead of `deny-overrides`, allowing a single permissive rule to grant access despite multiple explicit prohibitions.
- **Impact**: Unintended access grant in high-security contexts.
- **Mitigation**:
  - Issue 148 defines `deny-overrides` as the immutable default strategy for policy combination across Verixa. Any override strategy must be explicitly declared and audited.

#### Threat E-3: Stale Policy Cache Granting Revoked Access

- **Description**: An administrator revokes a policy or modifies a condition to restrict access, but the Redis policy cache (Issue 154) continues serving the old version for the duration of its TTL.
- **Impact**: Revoked permissions remain active during the caching window.
- **Mitigation**:
  - Invalidation-on-Publish (Issue 154): Publishing or archiving a policy version triggers synchronous cache invalidation across Redis clusters before the publish operation completes.
  - Cache entries store the policy version ID; evaluation decisions verify policy version freshness against the active registry version.

---

## Threat Mitigation Matrix

| Threat ID | Threat Category      | Surface                     | Primary Mitigating Issue | Secondary Control            | Residual Risk Stance                                                                     |
| :-------- | :------------------- | :-------------------------- | :----------------------- | :--------------------------- | :--------------------------------------------------------------------------------------- |
| **S-1**   | Spoofing             | Client Request Context      | **Issue 144, 145**       | JWT Claim Verification       | **Eliminated.** Client payloads cannot forge server-verified attributes.                 |
| **S-2**   | Spoofing             | Resource Attribute Resolver | **Issue 151**            | Tenant RLS Isolation         | **Eliminated.** Resolvers validate resource ownership within tenant boundary.            |
| **T-1**   | Tampering            | Policy DSL Authoring        | **Issue 155, 156**       | Versioning (Issue 150)       | **Mitigated.** Dry-run testing and linting catch errors prior to publish.                |
| **T-2**   | Tampering            | Database / Cache Storage    | **Issue 150, 154**       | Postgres RLS                 | **Mitigated.** Relies on database access controls and signed cache entries.              |
| **T-3**   | Tampering            | Parser / Lexer Execution    | **Issue 142, 143**       | Vitest Coverage Gate (158)   | **Eliminated.** Pure hand-written parser with no dynamic code execution (`eval`).        |
| **R-1**   | Repudiation          | Policy Storage              | **Issue 150**            | Audit Logging (Phase 10)     | **Eliminated.** Append-only version history preserves full edit trail.                   |
| **R-2**   | Repudiation          | PDP Decision Output         | **Issue 153**            | Pino Audit Logger            | **Eliminated.** Decision DTO includes detailed evaluation reason and matched policy IDs. |
| **I-1**   | Disclosure           | API Error Responses         | **Issue 153**            | Error Sanitizer              | **Eliminated.** Public API returns generic reason; granular detail stays in audit logs.  |
| **I-2**   | Disclosure           | Resolution Pipeline         | **Issue 145**            | Short-Circuit Evaluation     | **Accepted.** Micro-second timing variances exist; volume limited by rate limiting.      |
| **D-1**   | DoS                  | AST Evaluation Engine       | **Issue 146, 147**       | Static Linter (Issue 156)    | **Mitigated.** Short-circuiting and regex constraints bound CPU cost per check.          |
| **D-2**   | DoS                  | Attribute Resolution DB     | **Issue 152, 154**       | Redis Cache Layer            | **Mitigated.** RBAC fast-path and Redis caching eliminate repetitive DB lookups.         |
| **D-3**   | DoS                  | Cache Invalidation          | **Issue 154**            | Single-Flight Reloading      | **Eliminated.** Single-flight loading prevents database cache stampedes.                 |
| **E-1**   | Privilege Escalation | RBAC+ABAC Composition       | **Issue 152**            | Vitest Integration Matrix    | **Eliminated.** Explicit precedence rule: ABAC `DENY` strictly overrides RBAC `PERMIT`.  |
| **E-2**   | Privilege Escalation | Combining Algorithms        | **Issue 148**            | System Defaults              | **Eliminated.** `deny-overrides` enforced as system default combining strategy.          |
| **E-3**   | Privilege Escalation | Policy Cache                | **Issue 154**            | Sync Invalidation-on-Publish | **Mitigated.** Cache invalidation executed synchronously on publish events.              |

---

## Accepted Risks & Security Tradeoffs

1. **ReDoS in Policy Regular Expressions (`matches` Operator)**
   - _Tradeoff_: Allowing policy authors to express regular expression patterns in the DSL (`resource.path matches "^/api/v1/finance/.*"`) introduces theoretical catastrophic backtracking risks if an administrator authors a flawed regex pattern.
   - _Justification & Stance_: Restricting regex capability entirely would sever key URL/path matching use cases. The threat is accepted for administrative policy authors and mitigated via Issue 147's operator limits and Issue 156's static analysis linter.

2. **Redis Cache Disconnection Fallback Latency**
   - _Tradeoff_: If Redis becomes unavailable, the caching layer degrades to direct Postgres queries (Issue 154). This increases P99 latency for PDP requests during Redis outages.
   - _Justification & Stance_: Security takes priority over performance. Falling back to the database preserves correct, fail-closed authorization enforcement at the cost of higher latency, avoiding system-wide authorization failures during cache incidents.

3. **Attribute Staleness within Single Request Lifecycle**
   - _Tradeoff_: Request-scoped memoization of `AttributeContext` avoids redundant DB queries within a single HTTP request, but will not reflect entity state changes that occur _during_ that exact request handling span.
   - _Justification & Stance_: HTTP requests in Verixa execute within milliseconds. Intra-request staleness is an acceptable tradeoff to avoid recursive database lookups during multi-policy evaluation.

---

## Related Documentation

- [Authentication Flows](authentication-flows.md) — Password authentication, timing disguise, and decoy hashes.
- [Multi-Tenancy & Row-Level Security](multi-tenancy.md) — Database tenant isolation via Postgres RLS.
- [Password Storage](password-storage.md) — Argon2id password hashing parameters and security rationale.
- [Phase 08 Specification](../../planning/issues/phase-08-abac-policy-engine.md) — Roadmap requirements for issues 141 through 160.
