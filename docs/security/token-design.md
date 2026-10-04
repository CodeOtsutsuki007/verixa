# Access Token Design & JWT Implementation

**Issue:** #24 (Roadmap 084) — JWT access token design & signing service  
**Phase:** Phase 05 — Sessions & Tokens

This document covers the design and implementation of short-lived, stateless-verifiable access tokens in Verixa.

## Overview

Access tokens prove a user's identity and session validity to downstream services without requiring a database round trip. Verixa uses short-lived JWTs (15 minutes) signed with RS256 (asymmetric), paired with long-lived, revocable refresh tokens.

The split accomplishes two goals:

1. **Stateless verification:** Any service with the public key can verify an access token without contacting the auth service or a database.
2. **Immediate revocation:** A session revocation is recorded immediately; downstream verifiers check a revocation list (Issue 088) after signature verification succeeds.

## The Claim Set: sub, sid, orgId, iat, exp, kid

```json
{
  "sub": "user-123",
  "sid": "session-456",
  "orgId": "org-789",
  "iat": 1705334400,
  "exp": 1705335300,
  "kid": "2024-01-15-v1"
}
```

| Claim                    | Type           | Purpose                        | Why It's Here                                              |
| ------------------------ | -------------- | ------------------------------ | ---------------------------------------------------------- |
| **sub** (subject)        | UserId         | The user making the request    | Every request is from someone; services need to know who   |
| **sid** (session ID)     | SessionId      | Links the token to its session | Enables session-level revocation without token expiry wait |
| **orgId** (organization) | string         | The tenant/organization        | Multi-tenancy: scope queries without a user lookup         |
| **iat** (issued at)      | Unix timestamp | When the token was signed      | Detect clock skew; validate freshness                      |
| **exp** (expiration)     | Unix timestamp | When the token expires         | Verifiers reject tokens where `exp ≤ now`                  |
| **kid** (key ID)         | string         | Which signing key was used     | Enable zero-downtime key rotation (Issue 085)              |

## Why This Claim Set Is Minimal

The key insight: **access tokens are short-lived and stale.** If we embedded roles, permissions, or other fine-grained authorization data, that data would become stale the moment a permission changed. The user's token would still grant the old permission until it expired or was explicitly refreshed.

Instead, Verixa defers fine-grained authorization to a **policy engine** (Phase 08) that queries fresh data from the database on each request. The token carries only enough to:

1. **Route the request:** Know which user and organization the request is for.
2. **Check revocation:** Know which session the token belongs to, so a revoked session can be checked.

This separation keeps tokens small (smaller HTTP headers, faster serialization), and keeps authorization current (permissions changes take effect immediately at the policy engine, not waiting for token refresh).

### Alternatives Rejected

- **Full permission list in the token:** Stale, breaks on permission changes, and grows with user responsibility. Rejected.
- **Role name only (e.g., `role: "admin"`):** Still stale, still requires a role-to-permission mapping lookup, no real savings. Rejected.
- **No orgId:** Worse UX for multitenant systems (every service does a user lookup to know which org the user belongs to). Rejected.

## RS256 vs. HS256: Asymmetric vs. Symmetric Signing

Verixa uses **RS256 (RSA asymmetric signing)**, not HS256 (HMAC symmetric). This choice has profound architectural consequences.

### Symmetric (HS256)

- **One secret:** Both sign and verify use the same HMAC secret.
- **Distribution:** The secret must be shared with every service that verifies tokens.
- **Compromise:** If any verifier's copy is compromised, an attacker can forge tokens.
- **Key rotation:** Requires all verifiers to be updated in lockstep, or verification breaks. Operationally expensive.
- **JWKS endpoints:** Impossible (you don't publish signing secrets).

### Asymmetric (RS256)

- **Two keys:** A private key signs, a public key verifies.
- **Distribution:** Only the auth service needs the private key. Any other service just needs the public key (which can be published freely at a JWKS endpoint).
- **Compromise:** If a verifier's copy of the public key is compromised, tokens can still be verified but not forged. The attacker can't create new tokens.
- **Key rotation:** Create a new key pair; publish both old and new public keys for a grace period. Tokens issued with the old key are still verified until they expire.
- **JWKS endpoints:** Natural fit. Standard practice in OAuth 2.0 and OpenID Connect.

### Decision Rationale

For a single-service monolith, the difference is moot: HS256 is simpler. But Verixa is designed for growth:

- An API gateway might need to verify tokens before routing.
- Microservices might verify tokens independently.
- Webhooks or third-party integrations might need to verify tokens.
- Desktop or mobile clients might verify tokens locally (for offline UX).

In all these cases, RS256 is the natural choice: the public key is public, so anyone can verify, and the private key stays in the auth service. HS256 would require sharing the secret with every verifier, multiplying the surface area for compromise.

**Decision:** Start with RS256 now (it's what you'd eventually migrate to anyway), avoid a breaking change later.

## Token Lifetime: 15 Minutes for Access, 7 Days for Refresh

### Access Token: 15 Minutes (Stateless, Short-Lived)

- **Why short?** Limits the window an attacker has to use a stolen token. Limits stale authorization data (permissions changes take effect in 15 minutes max).
- **Why not shorter?** More frequent refreshes increase load and attack surface.
- **Why not longer?** Defeats the purpose; might as well use refresh tokens as access tokens.

The 15-minute TTL is a standard in OAuth 2.0 and OpenID Connect. Verixa makes it configurable so deployments can adjust based on their risk profile and load.

### Refresh Token: 7 Days (Stateful, Revocable)

- **Why long?** Avoids frequent re-authentication. Users don't want to log in every 15 minutes.
- **Why stateful?** Can be revoked immediately (logged-out user gets a new token, old one rejected, all on the same day).
- **Why hashed in database?** A stolen database dump doesn't yield usable refresh tokens (only their hashes).

See Issue 086 for the `RefreshToken` entity design and implementation. Issue 089 covers token rotation; Issue 090 covers theft detection.

## The Architecture: Hybrid Stateless + Deny-List

Access tokens are **stateless JWTs**: verification requires only the public key, no database lookup. But "stateless" doesn't mean "unrevocable" — it means the verification step doesn't require state.

### On Logout or Revocation

1. The session is revoked in the database (status = "revoked").
2. The session ID is added to a **deny-list** (Redis, Issue 088) with a TTL equal to the access token lifetime (15 minutes).
3. Downstream services verify the token signature (fast, no DB), then check the deny-list (also fast, local cache or Redis).

If the session is in the deny-list, the token is rejected despite being otherwise valid.

### Why a Deny-List, Not a Full Session Store?

A deny-list bounds memory usage by token TTL (entries expire after 15 minutes). A full session store grows without bound. For a deployment with millions of users, the difference is massive.

### Revocation Latency

Revoking a session is "immediate" in the sense that it's written to the database right away. But verifiers don't instantly see the revocation if they're using a cached copy of the deny-list. This is an accepted tradeoff: a brief window (seconds) where a revoked token might still work, in exchange for avoiding a synchronous write to every verifier across a cluster.

This is standard practice in OAuth 2.0 systems and similar to how browser certificate revocation works (CRLs and OCSP, neither of which guarantee instant knowledge of revocation).

## Key Rotation: Zero-Downtime with kid

Signing keys must eventually be rotated:

1. **Security:** Periodic rotation bounds the damage of key compromise.
2. **Compliance:** Some standards require rotation on a schedule (e.g., annual).
3. **Predictability:** Scheduled rotation is better than emergency rotation after compromise.

### The Problem

When a new key pair is created, tokens issued moments before the rotation are still valid (they have the old key ID in their `kid` header). If the old key is deleted immediately, verification of those tokens fails.

### The Solution (Issue 085)

1. Both the old and new public keys are published simultaneously.
2. Verifiers use the token's `kid` header to look up which key to use.
3. After all tokens issued with the old key have expired (15 minutes for access tokens), the old key is deleted.

This is standard practice (RFC 7517, JWKS) and enables zero-downtime rotation.

## Refresh Tokens: Stateful, Revocable, Opaque (Issue 086)

Refresh tokens are **not JWTs**. They're high-entropy opaque strings, hashed before storage, and revocable.

| Property          | Access Token                | Refresh Token              |
| ----------------- | --------------------------- | -------------------------- |
| Format            | JWT                         | Opaque string              |
| TTL               | 15 minutes                  | 7 days                     |
| Verification      | Stateless (public key only) | Stateful (database lookup) |
| Revocation        | Deny-list                   | Database status            |
| Compromise window | 15 minutes                  | Until refresh (rotating)   |

Refresh tokens live in the database so they can be revoked immediately. Their values are hashed (like passwords) so a stolen database dump doesn't yield usable tokens.

### Why Opaque, Not JWT?

A refresh token is fundamentally different from an access token in its operational role:

**Access tokens** are verified hundreds of times per second across a cluster (on every API request). Stateless JWTs make this possible: verification requires only the public key, no database round-trip.

**Refresh tokens** are used infrequently (every 15 minutes per session, during token refresh requests only). A database round-trip is acceptable and preferable because:

1. **Revocation immediacy:** A compromised refresh token must be revocable instantly. A deny-list (suitable for 15-minute access tokens) doesn't suffice for a 7-day token — the memory cost is prohibitive. Stateful revocation via database status field is immediate and bounded in cost.

2. **Database lookup is operationally cheap:** Refresh requests are rare (one per session per 15 minutes). The database cost of validating a token is negligible compared to the security benefit of immediate revocation.

3. **Opacity prevents information leakage:** A JWT in a database dump reveals its claims (user ID, organization ID, session ID) even if expired or revoked. An opaque token reveals nothing — the token itself is valueless without the stored hash.

4. **Simplifies token rotation:** Refresh token rotation (Issue 089) is simpler without JWT semantics. Issue the new token, invalidate the old one in the database, done. No claim versioning, no signature-related concerns.

### Implementation: Format and Storage

**Generation:**

- High-entropy opaque string: 32 bytes (256 bits) from `crypto.randomBytes()`, base64-encoded
- Byte length (256 bits) chosen for the following reasons:
  - Exceeds OWASP minimum of 128 bits for long-lived bearer tokens (RFC 6819, §5.2.2)
  - Long-lived tokens are higher-value targets; higher entropy is justified
  - Base64-encoded 32 bytes = 44 characters, fits standard HTTP header sizes
  - 16 additional bytes vs. 128-bit alternative costs negligible storage and transport overhead
  - Aligns with OAuth 2.0 and similar standards recommendations for long-lived tokens

**Storage:**

- SHA-256 hash only, never the raw token
- Stored as 64-character hex string
- Raw token exists **only in `RefreshToken.create()`'s return value** — structurally impossible to leak after that point

**Comparison:**

- **Not timing-safe in the domain layer** — that's an implementation detail at the use-case or repository layer
- Repository or use case can expose a `compare(token, refreshToken)` method that uses timing-safe comparison
- Domain entity provides the hash; comparison logic belongs above the domain

### Comparison to Passwords (Issue 061)

Refresh token storage mirrors password storage:

- **Never stored raw:** Always hashed before persistence
- **One-way:** A stolen database dump yields hashes, not credentials
- **Revocable:** Unlike passwords, no expiry timeout; immediate session-level revocation is possible

Unlike passwords, tokens are **ephemeral and automatically rotated:**

- Compromised tokens are rotated (Issue 089) rather than requiring user action
- User is never told "your refresh token was compromised, reset it" — they just refresh transparently and get a new one

## Refresh Token Rotation (Issue 089)

Every time a refresh token is used, a new one is issued and the old one is immediately invalidated. This limits the usefulness of a stolen refresh token to a single request.

## Theft Detection: Reuse Detection (Issue 090)

If a refresh token that has already been rotated (superseded) is presented again, it's evidence of theft:

1. The entire token family (all tokens descended from the stolen one) is revoked.
2. The session is revoked.
3. A security event is emitted.

This turns token rotation from a hygiene measure (limits exposure window) into an **active theft detection mechanism** (notifies the user and operator).

## Threat Model

### Threat: Access Token Theft

**Attack:** Attacker intercepts an access token (network sniffing, XSS, compromised device).

**Mitigation:**

- Token is short-lived (15 minutes). Attacker's window is bounded.
- HTTPS prevents network interception.
- Revocation list allows immediate session revocation if compromise is suspected.

### Threat: Refresh Token Theft

**Attack:** Attacker intercepts a refresh token (network sniffing, compromised device, database breach).

**Mitigation:**

- **Opaque and hashed:** Stored as SHA-256 hash only. A stolen database dump doesn't yield usable tokens — only hashes.
- **High entropy:** 256 bits, making brute-force guessing infeasible even with offline attacks.
- **Rotate-on-use:** Every time a refresh token is used, a new one is issued and the old one is immediately revoked (Issue 089). Attacker's window to use a stolen token is bounded to the time until next refresh.
- **Reuse detection (Issue 090):** If a superseded token is presented again, the entire token family and session are revoked, and a security event is emitted. This detects theft actively and limits damage.

### Threat: Token Forgery

**Attack:** Attacker forges a token (crafts a JWT, signs it with their own key).

**Mitigation:**

- Tokens are signed with RS256. Forging requires the private key (which only the auth service has).
- Verifiers check the signature before accepting any claims. A forged token is rejected immediately.

### Threat: Tampered Token

**Attack:** Attacker modifies an existing token (changes claims, e.g., `sub` to impersonate another user).

**Mitigation:**

- Any modification invalidates the signature.
- Verifiers reject tokens with invalid signatures. Tampering is detected immediately.

### Threat: Revocation Bypass

**Attack:** A user logs out, but their old token continues to work.

**Mitigation:**

- On logout, the session is revoked and added to the deny-list.
- Verifiers check the deny-list. Revoked sessions are rejected despite valid tokens.

### Threat: Token Fixation

**Attack:** Attacker tricks a user into authenticating with a token the attacker chose.

**Mitigation:**

- Tokens are issued by the auth service only, not accepted from clients.
- Session IDs are unpredictable (random UUIDs). An attacker cannot predict a token the auth service would issue.

## Implementation: JwtTokenSigner

The `JwtTokenSigner` class (infrastructure/jwt-token-signer.ts) implements the `TokenSigner` port using Node's native crypto module (via the `jose` library).

### API

```typescript
const signer = new JwtTokenSigner(privateKeyPem, publicKeyPem, keyId);

// Sign: returns Result<SignedAccessToken, SigningError>
const signResult = await signer.sign({
  userId,
  sessionId,
  organizationId,
  expiresAt: new Date(Date.now() + 15 * 60 * 1000),
});

// Verify: throws InvalidSignatureError, ExpiredTokenError, or MalformedTokenError
const claims = await signer.verify(token);
```

### Key Caching

RSA key import (parsing PEM) is expensive. The signer caches both keys after the first import, so subsequent calls reuse them. This is safe: crypto key objects are immutable.

### Thread Safety

The signer is stateless and thread-safe. Multiple concurrent `sign()` and `verify()` calls do not interfere with each other.

## Testing

The test suite covers:

1. **Sign/verify round-trip:** Tokens sign and verify correctly.
2. **Tamper detection:** Modifying the payload or signature causes verification to fail.
3. **Expiry:** Expired tokens are rejected.
4. **Malformed tokens:** Missing claims or invalid structure is caught.
5. **Key caching:** Keys are cached and reused across calls.
6. **Concurrent operations:** Multiple simultaneous sign/verify calls work correctly.
7. **Error types:** Each failure mode throws the expected error type.

All tests are unit tests (no database, no external services) and fail without the implementation (no tautological assertions like "expect(tokenSigner).toBeDefined()").

## Security Checklist

- [ ] All access tokens are transmitted over HTTPS only.
- [ ] Private signing keys are stored in a secure config store (environment variables, HSM, etc.).
- [ ] Public verification keys are available to all services that need to verify tokens.
- [ ] Key rotation procedure is tested (new keys can coexist with old for a grace period).
- [ ] Revocation via deny-list (Issue 088) is implemented.
- [ ] Token reuse detection (Issue 090) is implemented.
- [ ] Tokens are never logged or stored unredacted in audit logs.
- [ ] Access token TTL is appropriate for the deployment's risk profile (15 minutes is a recommendation, not a requirement).

## References

- **RFC 7519:** JWT specification. https://tools.ietf.org/html/rfc7519
- **RFC 7517:** JSON Web Key. https://tools.ietf.org/html/rfc7517
- **OAuth 2.0 RFC 6749:** Authorization Framework. https://tools.ietf.org/html/rfc6749
- **OpenID Connect Core:** https://openid.net/specs/openid-connect-core-1_0.html
- **OWASP Token Security:** https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

## Theft Detection: Reuse Detection (Issue 090)

Refresh tokens carry an optional `familyId` linking them to a rotation chain. When a token is rotated (Issue 089), the new token carries the same family ID. If an old token is presented after it's been superseded, it's evidence of theft:

1. The entire token family (all tokens descended from the stolen one) is revoked.
2. The session is revoked.
3. A security event is emitted.

This turns token rotation from a hygiene measure (limits exposure window) into an **active theft detection mechanism** (notifies the user and operator). See Issue 090 for the detection implementation.

## Next Steps

- **Issue 085:** Implement `SigningKeyProvider` for multi-key support and rotation.
- **Issue 087:** Implement `IssueSession` use case (creates a Session + issues token pair).
- **Issue 088:** Implement Redis-backed deny-list for revocation.
- **Issue 089:** Implement `RefreshAccessToken` use case (token rotation).
- **Issue 090:** Implement reuse detection for stolen refresh tokens.

# Token Design

How Verixa's session tokens are shaped, signed, rotated, and revoked, and — as
much as the mechanics — _why_ each decision was made and what was rejected.

This document grows with Phase 05 (`packages/sessions`). Today it covers the
pieces that have landed: the access-token format and signer, signing-key
rotation (Issue 085), and the revocation deny-list (Issue 088). The session
aggregate, refresh tokens, and the issue/refresh/logout use cases are described
in their own issues as they arrive.

For how bearer secrets are _stored_ (hash-only, never plaintext), see
[token-storage.md](./token-storage.md). For the login flows that mint these
tokens, see [authentication-flows.md](./authentication-flows.md).

For how multi-factor authentication gates session issuance via short-lived, single-use `MfaChallenge` tokens, see [mfa-design.md](./mfa-design.md).

## Two token types, on purpose

A session is backed by two tokens with deliberately opposite designs:

- The **access token** is short-lived and **stateless**. It is a signed JWT
  that any service can verify from the token and a public key alone — no
  database round trip. That is what makes it cheap enough to check on every
  request. The price is that it cannot be individually un-issued before it
  expires.
- The **refresh token** (Issue 086) is long-lived and **stateful**. It is an
  opaque, hashed, revocable value used only to obtain new access tokens.

The split exists so the token checked constantly is the cheap one, and the token
that must be revocable is the one checked rarely. Collapsing them — a stateful
access token checked against the database every request, or a stateless refresh
token that cannot be revoked — sacrifices exactly the property that mattered.

The gap the stateless access token leaves ("it stays valid until it expires even
if the session should die sooner") is closed by two things working together:
**short lifetimes** (the worst-case window) and the **revocation deny-list**
below (immediate shutdown within that window).

## Access token format

Claims are kept minimal. An access token carries the subject (`sub`, the user
id), the session id (`sid`), the active organization (`orgId`) when scoped to
one, and coarse role _hints_ (`roles`) — plus the registered `iat`/`exp`.

The role hints are a hint, never the source of truth: the authoritative
authorization check runs against the RBAC/ABAC engines in later phases. They are
deliberately coarse because an access token is a bearer credential that travels
widely and is only as fresh as its `exp`. Stuffing a full permission set into it
would bloat every request and make a revoked grant linger until the token
expired — the token would be asserting an authorization decision that may no
longer hold.

Signing is **asymmetric** (RS256 by default; the code accepts the RSA, ECDSA,
and EdDSA families). A symmetric algorithm (HS256) signs and verifies with the
same secret, so every service that needs to _verify_ a token would also hold the
power to _mint_ one. That is tolerable in a single process and a liability the
moment a second service — or a public JWKS endpoint — verifies tokens it must
never be able to forge. Asymmetric signing keeps the private key in one place
and hands out only the public half.

The verifier pins its accepted-algorithm list to exactly the algorithms its keys
use. This closes the algorithm-substitution class of attack: a forged token
declaring `alg: none`, or one that swaps an RS256 public key into an HS256 verify
where the "signature" is just an HMAC of that public key. An open-ended verifier
is the classic JWT footgun; the fix is to never let the token choose the
algorithm.

## Key management & rotation (Issue 085)

**Goal: rotate the signing key without invalidating tokens issued moments
before the rotation, and without logging anyone out.**

Every access token names, in its JWS header, the `kid` (key id) of the key that
signed it. Verification therefore never guesses which key to use — it reads the
`kid` and asks for exactly that key. The consequence is the whole trick: **the
set of keys a verifier holds, not the single key it currently signs with,
decides which tokens still verify.**

The `SigningKeyProvider` (`packages/sessions/infrastructure/signing-key-provider.ts`)
holds that set, built from configuration (`TOKEN_SIGNING_KEYS`, loaded and
validated by `@verixa/config`'s `loadSigningKeys`). It distinguishes:

- exactly **one current key** — carries a private half, signs all new tokens;
- zero or more **retired keys** — public half only, verify old tokens but can no
  longer sign anything.

Keeping a leaked config file for a retired key useless is why retired keys carry
no private material at all.

### The rotation procedure

1. Generate a new key pair with a fresh, unique `kid`.
2. Add it to `TOKEN_SIGNING_KEYS` marked `current`; demote the previously current
   key to a retired (public-only) entry. Deploy.
   - New tokens are now signed with the new `kid`.
   - Tokens signed seconds earlier still name the old `kid`; the provider still
     holds that key, so they keep verifying until they expire on their own.
     Nothing 401s mid-flight, no session is dropped by the key change.
3. Wait at least one access-token TTL, so every token bearing the old `kid` has
   expired.
4. Remove the retired key from `TOKEN_SIGNING_KEYS`. Deploy.
   - From here, any token still naming the old `kid` (only forgeries and
     long-expired stragglers remain) is rejected as an unknown key.

The two acceptance guarantees fall straight out of this: a token signed by a
retired-**but-still-held** key verifies; a token whose `kid` is unknown — removed
after step 4, or simply forged — is rejected (`TokenVerificationError` with
reason `unknown_key`). Both are pinned by tests in `jwt-token-signer.spec.ts`.

### Rejected alternatives

- **A single key, rotated by swapping it out.** The simplest thing, and wrong:
  at the instant of the swap, every already-issued token becomes unverifiable,
  so every active user is logged out and every in-flight request 401s. Rotation
  becomes an outage, so in practice it never happens — which is how signing keys
  end up years old.
- **A key with no `kid`, disambiguated by trying every key.** Works, but the
  verifier must attempt each key until one succeeds, turning verification into a
  loop and muddying "this signature is invalid" with "this was a different key."
  The `kid` header exists precisely to make the lookup O(1) and unambiguous.
- **Overlapping dual _current_ keys.** Rejected at the config layer (exactly one
  key may be `current`). Two keys both minting tokens raises "which one signs the
  next token?" with no good answer; rotation is "promote one, demote the other,"
  not "run two."

The `kid` pattern is also what a JWKS endpoint publishes, so this design extends
directly to multi-service verification later without rework.

## Revocation deny-list (Issue 088)

**Goal: make a revoked session's still-unexpired access tokens stop working
immediately, without giving up the stateless-verification property that made
access tokens cheap.**

This is the textbook stateless-JWT question: _how do you revoke something you
never stored?_ Deleting the session row does nothing, because access-token
verification never reads that row — a token already in an attacker's hands keeps
verifying until its `exp`.

The answer is **not** "make access tokens stateful" (that throws away the reason
they exist). It is a small, short-lived **deny-list**:

- On revocation, the `sessionId` goes on the list with a TTL equal to the
  revoked token's _remaining_ lifetime.
- On every access-token verification, the list is checked; a listed session is
  refused.
- Each entry expires exactly when the last access token that could reference that
  session would have anyway.

Because entries self-expire, the list's size is bounded by the access-token TTL,
not by the all-time count of revocations. That bound is what keeps a
per-request check affordable — the deny-list stays small no matter how many
sessions have ever been revoked.

The port is `RevocationList` (`revoke(sessionId, ttl)` / `isRevoked(sessionId)`);
the adapter is `RedisRevocationList`, one Redis key per revoked session with a
Redis `EX` expiry. The caller supplies the TTL because only it knows the
access-token lifetime in force when the token was issued; when rounding is
needed, round **up**, since an entry that expires too early re-opens the window
while one that expires too late only wastes a little memory.

### Fail-closed on Redis unavailability (accepted tradeoff)

When Redis is unreachable, `isRevoked` has two options:

- **Fail open** — "can't check, assume not revoked." Logins keep working during
  an outage, but every revoked (possibly stolen) session silently regains access
  for its duration.
- **Fail closed** — "can't check, assume revoked." Those tokens are refused, but
  a Redis outage becomes an auth outage.

**Verixa fails closed.** The deny-list exists specifically to shut down sessions
believed compromised; an implementation that quietly stops enforcing it the
moment its datastore hiccups defeats the reason it was built. An auth outage is
loud, bounded, and pages someone; a revocation-bypass window is silent and is
precisely the state an attacker holding a revoked token is waiting for.
Availability is recoverable; a re-admitted stolen session may not be.

This is a real, deliberately accepted tradeoff. It raises the stakes on Redis
availability (replication, health checks) — which is the correct place to spend
that effort. A specific lower-stakes path that genuinely needs fail-open can wrap
the adapter and catch, but the safe default is not any single caller's to
forget.

`revoke`, by contrast, lets errors propagate rather than failing silently: a
revocation that did not persist has not happened, and the caller (a logout, a
password reset) must know that and retry or surface it — reporting success for a
session that is still live would be the worse lie.

### Rejected alternatives

- **A full server-side session store checked on every request.** Makes access
  tokens de-facto stateful and puts a database (or Redis) read on the hot path
  for _every_ request, not just revoked ones — the cost the stateless design
  existed to avoid. The deny-list only pays for the sessions actually revoked.
- **A revocation list with no TTL (permanent entries).** Correct, but it grows
  without bound and forever, when an entry is only meaningful until the last
  token it denies has expired. TTLs make the store self-cleaning and its size
  predictable.
- **Fail-open for availability.** Rejected above: it converts a datastore
  hiccup into a silent security regression, which is the one failure mode a
  revocation mechanism must not have.
