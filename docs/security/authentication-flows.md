# Authentication Flows

How Verixa verifies a password, and — more importantly — what it refuses to
tell you when that fails.

Implementation:
`packages/credentials/application/use-cases/authenticate-with-password.ts`.
The HTTP surface is `POST /auth/login` in `apps/api/src/routes/auth.ts`.

## The rule

**Every failed login returns the same error, in the same time, whatever went
wrong.**

There are six ways authentication can fail:

1. No account with that email address.
2. The email address was not even well-formed.
3. The account exists but has no password credential (SSO-only, passkey-only).
4. The password was wrong.
5. The account is suspended.
6. The credential is locked after repeated failures.

A caller can distinguish none of them. All six produce
`AUTHENTICATION_FAILED`, HTTP 401, message `Invalid email or password.`, with
no field errors.

## Why: user enumeration

An endpoint that distinguishes "no such user" from "wrong password" is an
**account enumeration oracle**. OWASP lists it directly, and the Web Security
Testing Guide gives it its own test (WSTG-IDNT-04).

The attack is cheap. Post a list of email addresses; read which ones come back
"wrong password"; you now hold a list of addresses that have accounts. Two
things follow, and the second is usually the worse one:

- **Credential stuffing gets much cheaper.** The expensive half of that attack
  is finding valid usernames. Handed a verified list, an attacker only has to
  guess passwords for accounts already known to be real.
- **Membership leaks.** For an identity, verification and compliance platform,
  _who has an account here_ is frequently more sensitive than any individual
  password. "Is this person a customer of yours" is a question the login
  endpoint should not answer to anyone who asks.

### The cost, stated plainly

The error message is genuinely worse. Someone who mistypes their email address
is told exactly what someone who mistypes their password is told, and neither
is told which. That is a real usability cost and it is accepted deliberately,
not overlooked.

The place it gets resolved is password reset (Issue 069), which has the same
property for the same reason: it always reports "if that address has an
account, we've sent a link", and the actual answer arrives over a channel that
has already proven the recipient controls the address.

## Why timing is handled explicitly

Matching the message is not sufficient. If a missing user returns in 2ms while
a wrong password takes 60ms because it ran a real argon2 verification, the
**response time** answers the question the message declines to. That gap is
large, consistent, and measurable over a local network — and it is invisible to
any test that only inspects the response body.

So when there is no credential to verify against, the use case verifies the
submitted password against a **decoy hash** instead, and discards the result.
The decoy is a genuine argon2 hash of a password nobody holds, produced by the
same hasher at the same cost parameters. Both paths perform exactly one hash
verification.

The decoy is cached per hasher instance rather than globally. A decoy built at
one set of cost parameters is worthless for disguising a hasher configured with
different ones — it would look like it worked, cost the wrong amount, and leave
the channel open.

### What this does not claim

**Not constant time.** Argon2 verification is not constant-time with respect to
the parameters encoded in the stored hash; a database miss is faster than a
hit; and JIT warm-up, allocation and network jitter add noise that dwarfs both.
The first failed login in a process is also slower than later ones, because
that is when the decoy is computed.

Getting to "indistinguishable under statistical analysis" requires a fixed
response deadline — hold every response until a constant wall-clock budget has
elapsed — which is a heavier mechanism with its own failure modes, and more
than this threat warrants at this stage.

The claim made here is narrower and true: **the obvious order-of-magnitude
difference is gone.** The attacks that scale against the remainder are
addressed from the other side, by account lockout (Issue 067) and rate limiting
(Phase 15), which make the volume of attempts an enumeration attack needs
impractical regardless of what each one leaks.

## Ordering: password first, status second

The status check runs **after** the password is verified. This looks
backwards — why do expensive work for a suspended account? — and is
deliberate.

Checking status first means a suspended account can be identified without
knowing its password. "This account is suspended" answers "does this account
exist" to anyone who asks. Verifying first means a suspended account fails
exactly like a wrong password does.

`pending` users **can** authenticate. Registration leaves a user pending until
their email is verified (Issue 068), so refusing them would mean nobody could
sign in after signing up. Email verification gates what an account may _do_,
not whether its owner may prove who they are; conflating the two produces a
product that cannot tell an unverified user why they are stuck. Authorization
for unverified accounts is Phase 07's concern, and it can see the status.

The set of authenticable statuses is written as an allowlist rather than as
`status !== "suspended"`, so adding a state to `UserStatus` fails closed: a new
status is not authenticable until someone decides it is.

## Account lockout

After five consecutive failures a credential locks for a minute, and each
further attempt doubles that up to an hour. A successful login resets the
counter; so does a password change.

Implementation: `packages/credentials/domain/value-objects/lockout-policy.ts`
and the lockout fields on `Credential`.

### Why exponential, and why capped

A fixed window is close to useless against a patient attacker. Locking for
fifteen minutes after five attempts still permits roughly 480 guesses a day,
forever. Doubling makes a sustained campaign collapse into impracticality
within a handful of rounds, while costing a user who mistypes twice nothing at
all.

The cap matters as much as the growth. Unbounded backoff is a denial of
service handed to attackers: anyone who knows an address could lock its owner
out for years by failing enough times. With a ceiling, lockout stays a speed
bump for the attacker rather than a weapon against the user — and account
recovery (Issue 069) is the escape hatch that makes even the ceiling
survivable.

### The tension with enumeration resistance, and how it is resolved

Issue 067 asks for a "distinct (but still enumeration-safe) error". Those two
requirements pull against each other, and it is worth being explicit about how
far each is honoured.

Lockout state exists **only for accounts that exist**. So any difference a
client can observe — a 423, a `Retry-After` header, a different error code —
converts "fail five times against this address and watch what changes" into an
account enumeration oracle, undoing the property the rest of this document is
about.

The resolution: the error is distinct **as a type** and identical **on the
wire**. `AccountLockedError` is a separate class, so the application layer,
audit log and Phase 18 metrics can tell a lockout from an ordinary bad
password — genuinely different operational signals, and collapsing them would
make a credential-stuffing campaign look like user error. Its `code`,
`httpStatusHint` and `message` are deliberately identical to
`AuthenticationError`, so the HTTP response is byte-for-byte the same.

**What is not solved:** a fully enumeration-safe _visible_ lockout would
require tracking attempts for addresses that have no account, so that unknown
addresses lock too. That is a different shape — it needs a store keyed by
submitted address rather than by credential, with its own storage and
denial-of-service tradeoffs — and it belongs with Phase 15's rate limiting
rather than here.

### Ordering: lockout before the password check

The lock is the one thing checked _ahead_ of hashing, unlike account status.
Refusing to spend the CPU is most of the defence — verifying first would hand
an attacker exactly the expensive operation they were being denied.

That makes the locked path the fastest in the use case, which would announce
"this address has an account and someone is attacking it" through response
time alone. So the decoy verification runs on this path too.

### Why an expiry rather than a flag

`locked_until` is a timestamp, not a `locked` boolean. A flag needs something
to come along and clear it, and the failure mode of that scheduled job not
running is an account locked out permanently, with nothing in the request path
able to notice. An expiry releases itself: the comparison that decides whether
a credential is locked is the same one that decides it no longer is.

The failure counter also keeps climbing _during_ a lock rather than freezing at
the threshold. That is what makes the backoff exponential — each further
attempt earns a longer next lock.

## Rate Limiting

All abuse-sensitive endpoints consult the `RateLimiter` port before executing:

| Flow | Action Key | Identifier |
|------|-----------|------------|
| Login | `login` | email address |
| Register | `register` | email address |
| Password Reset Request | `password-reset` | email address |
| Password Reset Confirmation | `password-reset` | reset token |
| Email Verification | `email-verification` | email address |

### Current Implementation

A no-op adapter is wired until Phase 15 implements the real rate limiter.
The no-op always allows requests — no actual limiting occurs yet.

### Failure Behavior

When the rate limit is exceeded, the use case throws an error containing
`resetAt` (when the limit resets) and `limit` (the maximum allowed).
The transport layer (HTTP controller) maps this to 429 Too Many Requests.

### Adding Real Implementation (Phase 15)

Implement the `RateLimiter` port and inject via DI container.
No changes to use cases required — the seam is already wired.

Follow existing patterns in this repo for ports, adapters,
use cases, dependency injection, and testing.

## Transparent rehashing

A successful login is the only moment the plaintext password exists in memory,
which makes it the only moment an existing hash can be upgraded.

Cost parameters must rise over time as hardware gets faster. Without this,
raising them would mean every existing hash stays at its old strength forever,
or a mass password reset. Instead, on each successful login the stored hash is
checked against current parameters and re-hashed if it falls short. Passwords
migrate gradually as people sign in. Nobody is emailed and nothing is visible.

Two properties worth knowing:

- **It happens outside the authentication transaction.** Partly because
  hashing is slow and holds a connection for no reason, but mainly for
  correctness: the upgrade is best-effort, and a `try`/`catch` _inside_ a
  transaction cannot deliver that. A failed write has already marked the
  transaction for rollback, so swallowing the error only defers the failure to
  the commit, where nothing remains to catch it.
- **Its failure never fails the login.** The user supplied correct
  credentials. Refusing them because a background optimisation did not work
  would turn a cosmetic problem into an outage, and the upgrade is retried on
  their next login anyway.

## Email verification and password reset

Both issue a **single-use, expiring, hashed** token. Implementation:
`packages/credentials/domain/entities/email-verification-token.ts` and
`password-reset-token.ts`.

|                | Verification                    | Reset          |
| -------------- | ------------------------------- | -------------- |
| Lifetime       | 24 hours                        | 1 hour         |
| Grants         | Activation of a pending account | A new password |
| Failure detail | Reported                        | Withheld       |

### Why tokens are hashed, but not with argon2

Only a SHA-256 digest is stored. A leaked table therefore yields nothing
usable — the raw value exists exactly once, in the email that was sent.

The difference from password storage looks like an inconsistency and is not.
Password hashing is slow _on purpose_ because passwords are low-entropy and
human-chosen: without a deliberate cost, `Summer2026!` falls in microseconds.
These tokens are 256 random bits from a CSPRNG. There is no dictionary to try
and no guess worth making, so slowness would buy nothing while costing real
latency on a link a user just clicked.

Comparison is still constant-time. `===` on hex strings returns faster the
earlier the first difference appears, which is enough to reconstruct a value
character by character given samples. It compares _digests_ rather than raw
tokens, so this is belt-and-braces — the right place for a two-line function.

### Why single-use matters more than it looks

A link travels through channels nobody controls: a mail provider, a corporate
scanner that follows links, a forwarded message, a shared inbox, browser
history on a borrowed laptop. A reusable link is a permanent credential
scattered across all of them.

For reset this is sharper still. A reusable reset link in an old email is a
backdoor that **survives every subsequent password change** — the user picks a
new password, believes they are safe, and the link still works.

Issuing a new token retires every outstanding one, for the same reason.

### Where the enumeration rule applies, and where it does not

Both _request_ endpoints return success unconditionally — unknown address,
already-verified account, an SSO-only account with no password. A reset
endpoint that says "no account with that address" is a **better** oracle than
the login form, because it needs no password guess at all: one request per
address and you have the answer.

Whether anything happened is observable only internally. That is what `issued`
on the result object is for, and it must never reach a client — it exists so
tests and audit can verify the behaviour, since the response carries no
difference to assert on.

**Confirmation is where the rule stops.** `ConfirmEmailVerification`
distinguishes "expired" from "already used", and that is deliberate. Reaching
it requires already holding a 256-bit token, which only arrives by controlling
the mailbox — there is nothing left to enumerate, and the two cases lead to
different actions ("request another" versus "you are already verified, just
sign in"). Copying the login rule here would make the product worse for no
security gain, which is the failure mode of applying a principle without its
reason.

`ConfirmPasswordReset` does **not** make that concession, because the stakes
differ: an attacker holding a used reset token learns from "already used" that
it was real and that the account exists. Expired leaks the same. One message
for all three.

An unknown token is always reported identically to an expired one. That one
_is_ a guess.

### Why a reset must revoke sessions

The most commonly missed step in the flow, and the reason it exists.

The scenario a reset is for is "someone else has my account". If they got in,
they are holding a **session**. Replacing the password revokes their knowledge
of the credential and does nothing at all about the session they already have.
They stay signed in, indefinitely, while the user believes they have just
locked them out.

The danger is not that the reset is insecure — it is that it is _believed to
have worked_. A user who knows they are still compromised takes further action;
one who thinks they are safe does not.

`@verixa/sessions` now has a real `LogoutEverywhere` use case (see
"Sessions" below), but `apps/api/src/composition-root.ts` still wires
`NoSessionsRevoker` rather than an adapter over it. That is not an oversight:
`SessionRevoker` is defined here, in `@verixa/credentials`, and adapting it to
`LogoutEverywhere` needs a real `SessionRepository`/`RevocationList` pair —
Prisma- and Redis-backed, respectively — which do not exist yet. Wiring the
adapter without them would compile but silently do nothing at runtime, which
is worse than the explicit, honest no-op `NoSessionsRevoker` already is.
`NoSessionsRevoker` remains correct until that infrastructure lands, and the
call site exists now so that "remember to revoke sessions" never has to be
remembered.

When revocation fails, the error says so rather than reporting success: the
password _did_ change, and the user needs to know their old sessions survived.
That is the one place in these flows where a failure is surfaced rather than
swallowed, and the asymmetry is the point — a failed notification costs an
email nobody received, a failed revocation costs a false sense of safety.

### Deliberately not solved

Nothing rate-limits the request endpoints. Anyone can trigger verification or
reset emails to any address as fast as they can post, which is both a
mail-bombing vector and a way to repeatedly invalidate a real user's
outstanding link. That is Phase 15's job, and a real gap until then.

Delivery is also not implemented — `NullCredentialNotifier` sends nothing until
Phase 14. It is silent rather than logging "would have sent: &lt;token&gt;",
because that version is the one that survives in production for a fortnight
while every reset token in the system lands in a log aggregator.

## Change Password (Credential Rotation)

An authenticated user can change their own password by providing their current
password for re-authentication. Distinct from password reset (Issue 070), which
addresses account compromise.

### Flow

1. User (authenticated) submits current password + new password
2. System re-authenticates with current password (step-up auth)
3. If valid: hashes new password, updates credential, emits `PasswordChanged` event
4. If invalid: returns generic error (`ValidationError` with no field details)

### Step-Up Authentication Pattern

This use case previews Phase 06 MFA step-up authentication: re-verifying
identity before sensitive actions. Here, the `currentPassword` field is the
step-up credential. The pattern is: "prove you are who you say you are _right
now_, before we let you change something important."

### Differences from Password Reset

| Aspect         | Change Password   | Password Reset             |
| -------------- | ----------------- | -------------------------- |
| User state     | Authenticated     | Compromised (or forgot)    |
| Credential     | Current password  | Email verification link    |
| Friction       | Low (no email)    | Higher (token flow)        |
| Lockout impact | Clears on success | Clears on success          |
| Session impact | Stays active      | Revoked (security measure) |

Change password is the owner deciding to rotate their credential voluntarily.
Reset is an emergency that assumes the credential is compromised, so sessions
must be invalidated.

### Domain Event

`PasswordChanged` — emitted after successful credential rotation.

Consumed by: audit log (Phase 10), future session invalidation triggers
(Phase 15+), MFA re-verification requirements (Phase 06+).

### Error Handling

Both of these return the same `ValidationError`:

- Wrong current password
- User not found (should be unreachable; authenticated requests have valid userId)

The identical error prevents enumeration: a caller cannot tell whether the user
exists or the password is wrong.

**New password policy violations** also return `ValidationError`, but before any
database work:

- Too short (policy minimum)
- Empty
- Other policy-defined rejections

### Security Properties

**Current password must be provided.** Re-authentication is required. Unlike
password reset (which proves email ownership), this proves knowledge of the
current credential.

**New password hash is independent.** A fresh salt is generated, so the new
hash is different from the old even if the plaintext is unchanged (which is bad
practice, but not cryptographically broken).

**Plaintext passwords never stored or logged.** The plaintext exists only in
memory during verification and hashing, and is never serialized.

**Error messages are deliberately generic.** The difference between "current
password is wrong" and "user not found" is not exposed.

**Lockout is cleared on success.** A user who successfully changes their
password has proved control of the account. Any lockout from repeated failed
login attempts is cleared. They cannot be locked out of a credential they just
set.

### Implementation

Implementation: `packages/credentials/application/use-cases/change-password.ts`

Tests: `packages/credentials/application/use-cases/change-password.spec.ts`

See `docs/guides/domain-modeling.md` for the structure: uses a `Result<T, E>`
discriminated union, `CredentialsUnitOfWork` for transactions, ports for
`PasswordHasher` and credential persistence.

## What login does not yet do

`POST /auth/login` returns the authenticated user and **no session or token**.
Wiring session issuance into the login route is still open work — see
"Sessions" below for what the package underneath it now does.

Until the route is wired up, it is deliberately not enough to stay logged in
with. Returning a placeholder token would be worse than returning none:
clients would store it, and replacing it with a real one later would be a
breaking change to a field that never worked.

## Sessions

Implementation: `packages/sessions/`. Nothing in `apps/api` calls into this
package yet — `POST /auth/login` does not issue a session, so everything
below is exercised by the package's own tests, not by an HTTP request. It is
documented here anyway, in the same file as login, because a session's
lifecycle is inseparable from the login flow that will eventually create one.

### Metadata is a history, not a snapshot

`Session` records the device/IP/user-agent seen at issuance, and appends a
new observation on `RefreshAccessToken` only when what the client presents
has changed since the last one. It is a history rather than an overwritten
field for exactly the reason `AuditLogEntry` chains rather than timestamps:
overwriting the previous value would make "did this session's location ever
change" unanswerable from stored data. A future impossible-travel check
(Phase 06+) needs the _sequence_ of observations, not just the latest one —
capturing it now, before any consumer of it exists, is the same call
`AuditLogEntry`'s hash chain and the credential lockout counter both made:
build the primitive before the feature that reads it, because retrofitting
history onto data that was only ever overwritten is not possible after the
fact.

Refresh token rotation and reuse detection (the `RefreshToken` entity and
`RefreshTokenReuseDetected` event already sitting, unused, in this package)
are deliberately **not** part of this — `RefreshAccessToken` re-signs the
access token against the session's _existing_ refresh token hash rather than
rotating it. Building rotation was a bigger change than the metadata-capture
issue asked for, and folding it in here would have coupled two independent
pieces of work behind one pull request. It can be layered on top later
without touching the metadata-capture behavior.

### Logout and LogoutEverywhere both revoke two things, not one

Verixa's access tokens are stateless JWTs, verified without a database round
trip. That is what makes them fast, and it is also what makes "revoke a
session" harder than it sounds: revoking the _refresh_ token (so no further
`RefreshAccessToken` call succeeds) does nothing about an access token
already issued, which keeps authenticating requests until its own `exp`
regardless. `Logout` and `LogoutEverywhere` therefore both do two things —
revoke the session (or every session) and denylist its `currentAccessToken`
through a `RevocationList` — because doing only one would leave a live
credential behind. See the class docs on `Logout` for the full reasoning, and
`docs/guides/database.md`/the `RevocationList` port for why this is a
separate mechanism from the session store rather than a column on it.

`LogoutEverywhere` only touches sessions that existed at the moment it reads
them — a login racing immediately after is a different, later row it never
saw, and is unaffected by design. See the class docs for why that is the
right behavior rather than a gap.

### Concurrent session limits evict, they do not refuse

`IssueSession` takes an optional `maxConcurrentSessions` (surfaced as
`SESSION_MAX_CONCURRENT_SESSIONS` in `@verixa/config`, default `0` /
disabled). Reaching the limit does not reject the new login — it evicts the
least-recently-active existing session first, denylists that session's access
token the same way `Logout` does, and logs the eviction via
`SessionAuditLogger`. Refusing the new login instead was the alternative
considered and rejected: a user who has genuinely forgotten about an old
signed-in device should not be locked out of a brand-new one, and eviction
gets the same security property (bounding how many sessions can be alive at
once) without that cost.

The limit is a constructor parameter on `IssueSession`, not a value baked
into the domain, for the same reason `AuthenticateWithPassword` takes an
injectable `LockoutPolicy`: it is a per-deployment product decision (a
banking app and a consumer SaaS product reasonably disagree on it), and the
composition root — not this package — is where environment configuration
belongs.

## Related

- `docs/security/password-storage.md` — argon2id parameters, the PHC format,
  and why the hash is self-describing.
- `docs/security/token-storage.md` — how tokens are stored once they exist.
