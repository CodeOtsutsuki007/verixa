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
