# Tutorial: Building Secure Authentication (Issues 061–079)

This walkthrough traces how to design and implement credential verification
from first principles — registration, login, password reset — making every
security decision explicit and linking it to real code in this repository.
It's written for anyone comfortable with hashing and cryptography concepts,
who wants to understand not just what Verixa does, but _why it makes the
choices it does_.

If you want to know how to build auth correctly, read this. If you want to
know why the error message is the same whether the account doesn't exist or
the password is wrong, read this first, then the code.

## The map

Everything below lives under `packages/credentials/`, which separates
credential mechanics from identity (user profiles, organizations — that's
`packages/identity/`). The structure follows the same shape as every
bounded-context package:

```
packages/credentials/
├── domain/             # Password hashes, tokens, lockout policies
├── application/         # Use cases for registration, login, reset
├── infrastructure/      # Argon2 hasher, JWT builder (later phases)
└── index.ts             # public surface — use cases and ports
```

The HTTP routes live at `apps/api/src/routes/auth.ts` and orchestrate these
use cases into flows.

## Stop 1 — Why not bcrypt: hashing mechanics

Start at `packages/credentials/infrastructure/argon2-password-hasher.ts`.

```ts
const hasher = new Argon2PasswordHasher({
  memoryCost: 19, // 19 MiB
  timeCost: 2,
  parallelism: 1,
});
const hash = hasher.hash("user's password");
// Result: "$argon2id$v=19$m=19456,t=2,p=1$<base64 salt>$<base64 hash>"
```

The hash is a **PHC string** — a standardized format that includes not just
the hash itself, but the algorithm name, version, and cost parameters. Why
does that matter?

### The bcrypt problem

Bcrypt looks simpler at first glance — it produces a shorter string and has
been battle-tested for twenty years. Verixa deliberately chooses Argon2id
instead, for two reasons:

1. **Fixed working set, cannot be upgraded.** Bcrypt uses roughly 4 MiB of
   RAM per hash regardless of the parameters you pass. When it was designed
   that was expensive. In 2026, it is not. GPU crackers can parallelize
   across thousands of cores, each one doing a bcrypt hash in its small
   fixed footprint. Argon2 uses configurable memory — the same code can
   go from 8 MiB to 128 MiB to 256 MiB as hardware scales, which prevents
   attacks from scaling at the same rate. The working set is named `m` in
   the PHC string: `m=19456` means 19 MiB.

2. **Silent truncation at 72 bytes.** Bcrypt silently ignores any password
   longer than 72 bytes. A 100-character passphrase and a 72-character
   substring get the same hash. Worse, if you hash a long passphrase, then
   later someone learns the first 72 bytes were "MyPassword2026!xyz", they
   already have the plaintext to authenticate as — the truncation made the
   "secure" passphrase weaker than its prefix. See
   `argon2-password-hasher.spec.ts`, line 86–91, which proves argon2
   accepts a 1500-character input without truncation.

### What the parameters mean

The hasher is constructed with `memoryCost: 19, timeCost: 2, parallelism: 1`:

- **memoryCost: 19** — use 19 MiB per hash (19456 KiB, in the standard
  encoding). This is the OWASP Argon2 recommendation as of 2024. More memory
  means more data for GPU crackers to shuttle around; less means they can
  run more instances in parallel. This number should rise over time as
  servers get more RAM (Phase 17 can explore this). The default here is
  defensible for a modest API server in 2026.

- **timeCost: 2** — iterate twice. Each iteration applies the hash function
  to all the memory, so this costs roughly 2x more CPU than timeCost: 1. The
  OWASP minimum is 2; more is fine if the server can tolerate the latency.
  Registration can afford a higher cost; login cannot, without becoming
  unbearably slow. See `apps/api/src/routes/auth.ts`, line 100, which shows
  no alternative `RegisterHasher` — registration uses the same cost as login,
  prioritizing consistency over register-time mitigation.

- **parallelism: 1** — use one thread. In a server that processes requests
  concurrently, parallelism > 1 is often pointless — other requests will
  saturate the core anyway. Set it higher only if you benchmark and find
  single-request throughput improved.

The hasher validates these at construction time (lines 160–175), rejecting
`memoryCost < 8` or `timeCost < 1` or `parallelism < 1`. Misconfiguration
is a realistic failure — someone running in a memory-constrained
environment might lower `memoryCost` to 4 MiB "temporarily" and then forget.
Rejecting it at boot beats shipping with weak hashing.

### Salt generation: once per hash, never reused

Look at line 73–84: every call to `hash()` generates a fresh 16-byte salt
using `crypto.randomBytes()`. Never reuse a salt, never take one from user
input, never accept one as a parameter. Per the PHC spec, the salt is
base64-encoded into the hash string itself (`m=19456,t=2,p=1$<salt here>`),
so everything you need to verify is self-contained.

### The PHC format: self-describing hashes

The output `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>` means:

- Algorithm: argon2id
- Version: 19 (RFC 9106 standard)
- Parameters: 19 MiB memory, 2 iterations, 1 parallel thread
- Salt: the base64-encoded random value
- Hash digest: the base64-encoded result

In five years, if the parameters should be 256 MiB / 4 iterations, you can
upgrade new passwords to the higher cost. Old passwords with their stored
parameters intact can still be verified — the verifier reads the parameters
from the hash, not from configuration. This is why a self-describing format
is worth the extra bytes: upgrading is survivable without a mass password
reset.

### Transparent rehashing on login

After successful authentication (the password verified correctly), the hasher
checks `needsRehash(storedHash)` (lines 138–153). If the stored hash was
built with weaker parameters than current settings, `needsRehash` returns
true. Then the use case re-hashes the plaintext at the new cost and updates
the stored value.

**Key design:** `needsRehash` only reports upgrades, never downgrades (line
150). Suppose someone misconfigures the hasher to 8 MiB to cut latency, then
realizes that was a mistake. If `needsRehash` reported "different
parameters," every login would re-hash the password DOWN to the weaker
setting, silently degrading security while looking like routine maintenance.
Preventing downgrades means parameters only rise and never fall.

The upgrade happens outside the authentication transaction (lines 225–231),
and its failure is swallowed (line 229–231). Why? Holding a database
connection during a 60ms hash is wasteful, but the correctness reason is
sharper: a failed update inside a transaction has already marked it for
rollback, so catching the error only defers failure to the commit. Outside,
the failure is genuinely best-effort — the user is authenticated, the upgrade
is retried on next login, and the operator has a signal to investigate.

## Stop 2 — Enumeration resistance: the same error for different failures

Jump to `docs/security/authentication-flows.md`. Read the section "The
rule" and "Why: user enumeration". This document explains the threat; now
let's see how the code embeds it.

Open `packages/credentials/application/use-cases/authenticate-with-password.ts`.

### The six failures that look identical

Lines 260–276 return a single error shape for all six authentication failure
modes:

```ts
throw new AuthenticationError(
  "AUTHENTICATION_FAILED",
  "Invalid email or password.",
);
```

What are the six? Let's trace the use case:

1. **Malformed email** (line 179–181): `Email.create(command.email)` rejects
   a badly-formed address. Caller gets `AuthenticationError`.
2. **No account exists** (line 186–197): Query returns nothing. Caller gets
   `AuthenticationError`.
3. **Account has no password** (line 168–178): User exists but has no
   `Credential`. Caller gets `AuthenticationError`.
4. **Wrong password** (line 200–203): Hash verification failed. Caller gets
   `AuthenticationError`.
5. **Account is suspended** (line 206–210): Status check fails. Caller gets
   `AuthenticationError`.
6. **Account is locked after repeated failures** (line 184–195): Lockout
   still active. Caller gets `AuthenticationError`.

An attacker calling this endpoint 10,000 times learns nothing about which
addresses have accounts. The response is byte-identical whether they
misconfigured their email client or the account doesn't exist at all.

### Why this is not marketing theater

Enumeration resistance seems theoretical until you sit with the cost of
failure. Verixa targets credential verification — a space where "who has an
account" is a commercial asset worth protecting. Leaking membership is not
theoretical.

More broadly, it is asymmetric. The legitimate user cost is real and accepted
deliberately: someone who mistyped their email is told "wrong email or
password" instead of a hint. The operator cost is zero — the same error path
handles all six cases, so supporting enumeration-safe responses costs nothing
compared to the complexity of distinguishing them.

### The timing attack: decoy hashing

The hard part of enumeration resistance is not the message; it is
**time**. If no credential exists, the code path is:

```ts
throw new AuthenticationError(...);
```

This completes in microseconds. But if a credential exists and the password
is wrong:

```ts
await passwordHasher.verify(hash, password);  // 60ms
throw new AuthenticationError(...);
```

The response time difference is an enumeration oracle more precise than the
message. Someone probing the endpoint notices "unknown addresses come back
in 2ms, real addresses come back in 60ms" and now they have confirmed
accounts.

The fix is to make both paths do exactly the same work. Lines 235–239
implement it:

```ts
const hasherWithoutCredential =
  this.passwordHasher.hashAgainstDecoy(command.password);

if (!credential) {
  // Can't verify against a real credential, so verify against a decoy
  // hash to maintain identical timing vs. wrong password
  await hasherWithoutCredential;
}
```

The `Argon2PasswordHasher` maintains a **decoy hash** — a cached, genuine
argon2 hash of a password that nobody knows (line 24–50). On first use, it
is computed once and cached. Then for every "no credential found" case, the
verifier runs against the decoy instead of returning immediately.

Both paths now:

1. Call `verify()` exactly once.
2. Wait ~60ms for that verify() call.
3. Return the same error.

An attacker cannot distinguish which by response time.

**Why per-hasher, not global:** If you had one global decoy hash, and
someone redeployed with different parameters (8 MiB instead of 19 MiB), the
decoy would still cost 19 MiB of computation while the real hasher does 8
MiB. The mismatch announces "something is different here." A decoy built at
one cost is only useful for disguising a hasher with identical parameters.

**What this does NOT claim:** Constant-time in the cryptographic sense.
Argon2 is not constant-time across all inputs; JIT warmup and allocation
noise add jitter; a database miss is faster than a hit. The claim is
narrower: **the obvious order-of-magnitude difference is gone.** A 58x
timing gap becomes noise. Attacks that get stronger against the remaining
jitter (statistical analysis over thousands of requests) are addressed by
account lockout (Stop 3) and rate limiting (Phase 15 — future).

### Test validation

Open `authenticate-with-password.spec.ts` line 152–186. The test does not
measure wall-clock time — that is fragile, depends on hardware, and fails
under load. Instead it counts how many times `verify()` was called:

```ts
expect(verifyCallCount).toBe(1);  // no account path
expect(verifyCallCount).toBe(1);  // wrong password path — same
```

Both paths call verify exactly once, proving they do identical work even if
the wall-clock duration varies.

## Stop 3 — Lockout: exponential backoff and self-releasing expiry

Now jump to `packages/credentials/domain/value-objects/lockout-policy.ts`.

The policy is:

- Threshold: 5 consecutive failures
- Base duration: 60 seconds
- Backoff factor: 2 (exponential)
- Max duration: 1 hour

### The formula

After 5+ failures, duration = `base * (2 ^ (failureCount - threshold))`,
capped at max.

So:

- Failure 1–4: not locked
- Failure 5: locked for 60s
- Failure 6: locked for 120s (1 min * 2^1)
- Failure 7: locked for 240s (1 min * 2^2)
- Failure 8: locked for 480s (1 min * 2^3)
- Failure 9: locked for 960s (1 min * 2^4)
- Failure 10: locked for 1 hour (capped)

### Why exponential, not fixed

A fixed 15-minute lockout is close to useless against a patient attacker. At
1 guess per second (easily faster with pipelining), an attacker gets ~96,000
guesses between lockouts: roughly 480 per day forever. Exponential backoff
collapses that.

After failure 10, the attacker is at 3840 seconds = 64 minutes. The
next attempt:

- Locked until attempt 11 can be made.
- Attempt 11: 1 hour cap.
- Attempt 12: 1 hour cap.

The campaign stops scaling. An attacker determined to crack one account at
1 guess/second burns through ~2500 guesses in a day, then hits the 1-hour
cap and cannot do better. Over a year, maybe 30,000 guesses against one
address — not nothing, but combined with Phase 15's rate limiting, it becomes
impractical.

### Why the cap matters

Without a ceiling, unbounded backoff is a denial-of-service weapon. After 50
failures, the lockout would be ~35 years. An attacker knowing an address can
lock its owner out for decades, turning a defensive mechanism into an attack.

The cap keeps lockout what it is: a speed bump for attackers, not a weapon
against users. After one hour, the account releases automatically.

### Checking BEFORE hashing

Lockout is checked before the password is verified (lines 184–195 in
authenticate-with-password.ts). This makes sense operationally — refusing to
spend 60ms of CPU on a locked account — but it creates a timing leak: locked
accounts return instantly, wrong-password accounts take 60ms.

The code addresses this the same way it addresses "no credential found":
lines 189 show a decoy hash verify on the locked path too. Locked credentials
also incur the full hash computation cost, so the timing is identical to a
wrong password.

### Failure counter during lockout

During a lock, the counter keeps climbing, not freezing (lines 191–193).
Each new attempt extends the lock:

- Attempt 5: 60s lock
- Attempt 6 (30s after first failure): 120s lock
- Attempt 7 (at 61s from first failure): 240s lock

This is what makes the backoff exponential — the lock grows on each attempt,
not resets. Without it, waiting 65 seconds and trying again would reset the
counter, and a patient attacker could retry indefinitely at intervals.

### Clearing on success

A correct password clears the counter and any active lock (lines 204–212).
This makes the threshold count CONSECUTIVE failures — if an attacker pokes an
account, someone legitimate logs in the next day, and then the attacker
resumes, the counter resets. Lockout is meant to stop active attacks, not
punish failed logins from years ago.

### Self-releasing expiry, not a flag

The `Credential` entity has a `lockedUntil` timestamp, not a `locked`
boolean (packages/credentials/domain/entities/credential.ts, lines 30–60).

Why? A boolean needs something to come along and clear it — a scheduled job.
The failure mode of that job not running is an account locked out forever.
Nobody notices until a user complaints. A timestamp instead releases itself:

```ts
isLockedAt(now: Date): boolean {
  if (!this.lockedUntil) return false;
  return now < this.lockedUntil;
}
```

On next login, the check automatically passes if enough time has elapsed.
Self-releasing is more robust than a job that must be remembered,
configured, and monitored.

### Test coverage

Look at
`packages/credentials/application/use-cases/authenticate-with-password-lockout.spec.ts`.
It validates:

- Threshold: 5 failures lock the account
- Exponential backoff: each further attempt doubles the duration
- Cap: lockout never exceeds 1 hour
- Reset: a correct password clears the counter
- Self-release: advancing time without retry allows re-entry

Notice these tests verify behavior, not internal counter values. The test
doesn't assert that `failureCount === 5`; it asserts that the account is
locked, then waits, then asserts that it is not. Behavior, not implementation.

## Stop 4 — Status checking AFTER verification

Back in `authenticate-with-password.ts`, lines 206–210:

```ts
if (!credential.canAuthenticateWithStatus(user.status)) {
  throw new AuthenticationError(/* ... */);
}
```

The status check runs AFTER the password is verified, not before. This looks
backwards: why spend 60ms hashing a password for a suspended account? It is
deliberate.

### Why backwards is right

If you checked status first, the flow would be:

```ts
if (user.status === "suspended") {
  throw new Error("This account is suspended.");  // Leaks existence!
}

await verify(password);  // expensive, only if status is OK
```

Now "this account is suspended" answers the enumeration question: does this
account exist? An attacker can identify real addresses without knowing any
password.

By checking after, a suspended account fails exactly like a wrong password:

```ts
await verify(password);
if (!canAuthenticateWithStatus(status)) {
  throw AuthenticationError("Invalid email or password.");
}
```

To identify a suspended account, an attacker would have to guess its password
first — which requires already knowing the address AND being willing to spend
a guess on it.

### Pending accounts CAN authenticate

Look at line 112–113:

```ts
private static readonly CAN_AUTHENTICATE = new Set(["pending", "active"]);
```

A user pending email verification is allowed to authenticate. Registration
leaves users pending (packages/identity/domain/entities/user.ts), so refusing
them would mean nobody could sign in after signing up until they verify their
email.

The distinction matters: email verification gates authorization (what the
account may do in Phase 07), not authentication (proving who you are). These
are separate concerns. If the endpoint refused pending users, they would be
stuck — unable to complete the signup flow because they cannot authenticate
to request a verification email retry.

### Allowlist, not exclusion

Status is checked against an allowlist (`CAN_AUTHENTICATE = new Set([...])`)
rather than as `status !== "suspended"`. Why?

When a new status is added to `UserStatus` (say, "flagged_for_review"), it is
not automatically authenticable. The code fails closed — a new state is
explicitly denied until someone decides it should be allowed. An exclusion
pattern would accidentally allow new states immediately, which is riskier.

## Stop 5 — Token design: short-lived, hashed, single-use

Now look at `packages/credentials/domain/entities/email-verification-token.ts`
and `password-reset-token.ts`.

### Token generation: 256-bit CSPRNG, not UUID

Line 18–29 of `packages/credentials/domain/value-objects/token-digest.ts`:

```ts
generateToken(): string {
  const buffer = crypto.randomBytes(32);  // 256 bits
  return buffer.toString("base64url");
}
```

UUIDs carry 122 bits of entropy; these tokens carry 256 bits. For a token
transmitted over email, through mail providers, logged in systems you do not
control, the extra entropy is non-negotiable.

### Hashing: SHA-256, but NOT argon2

Only the SHA-256 digest is stored in the database:

```ts
private readonly digest: string;  // hex-encoded SHA-256

tokenMatchesDigest(plaintext: string): boolean {
  return timingSafeEqual(
    crypto.createHash("sha256").update(plaintext).digest("hex"),
    this.digest,
  );
}
```

A leaked database therefore yields only hashes, not the raw tokens. The raw
token exists exactly once — in the email that was sent.

### Why SHA-256, not argon2?

This is a subtle distinction from password storage:

- **Passwords are low-entropy, human-chosen:** Attackers have dictionaries.
  Without deliberate cost, "Summer2026!" falls in microseconds. Argon2 is
  slow on purpose.

- **These tokens are 256-bit CSPRNG:** Attackers have no dictionary. The
  search space is ~10^77. Brute force is not a threat. Slowness would:
  1. Cost real latency on a user-facing path (email verification link).
  2. Buy nothing.

Decision rule: **argon2 for secrets humans chose, fast hashes for secrets a
CSPRNG generated.**

### Timing-safe comparison

Comparison happens via `timingSafeEqual` on digests (lines 54–70 of
token-digest.ts), not `===` on plaintext. Why?

`===` on strings returns faster the earlier the first difference appears. If
you compare two 256-bit base64 strings, the comparison time leaks the position
of the first difference. With enough samples, an attacker can reconstruct the
token character by character — not a practical threat here because they would
need multiple verification attempts for the same token, and tokens are
single-use, but defense in depth is free.

Comparing digests instead (after hashing both) is belt-and-braces — the right
thing anyway since only the digest is stored.

### Single-use is critical

Lines 130–150 of `password-reset-token.ts` implement single-use:

```ts
if (this.used) {
  throw new UsedPasswordResetTokenError();
}

this.markAsUsed();  // Sets used: true
```

Why does this matter?

**Email is a broadcast medium.** A link travels through Gmail servers, a
corporate mail scanner, possibly a forwarded message, maybe a shared inbox on
a borrowed laptop. A reusable token is a credential scattered across all those
systems.

**For password reset, reusable is catastrophic:** An old reset link in archive
email is a backdoor that survives every password change. The user changes
their password believing they are safe, and that link still works.

Issuing a new token on each request retires all outstanding ones (verified in
confirm-password-reset.spec.ts), so old emails automatically expire.

### Token lifecycle differences

|                | Email Verification | Password Reset |
| -------------- | ------------------- | -------------- |
| Lifetime       | 24 hours            | 1 hour         |
| What it grants | Activation          | Password change |
| Error detail   | Reported            | Withheld       |

The reset token is shorter-lived because reset is higher-risk. It is also
more guarded about failure detail — see Stop 6 below.

## Stop 6 — The request endpoints: enumeration-safe throughout

Look at `apps/api/src/routes/auth.ts` line 130–146 (`RequestPasswordReset`)
and the corresponding use case.

### Success response is identical regardless of what happened

```ts
throw new Error("no account with that email");
// Returns same response as:
throw new Error("account already verified");
// Returns same response as:
return { issued: true };
```

All three return HTTP 200, `{ issued: true }`. An attacker calling this
1,000 times learns nothing about which addresses have accounts.

The `issued` field is there for tests and audit logging to verify behavior
internally, but **it must never reach a client.** See comments in
confirm-password-reset.spec.ts around line 40–60.

### Why both endpoints need this

Many projects skip enumeration resistance on password reset, assuming that
because passwords are not involved, enumeration is fine. It is not.

For a credential verification service, "does this person have an account"
is commercial information worth protecting. Worse, many users reuse account
addresses across services, so leaking membership here can leak membership
elsewhere.

An endpoint saying "no account with that address" is an even better oracle
than login — it requires zero password guesses, just HTTP requests. One
request per address and you have the full roster.

## Stop 7 — Registration: hashing outside the transaction

Look at `packages/credentials/application/use-cases/register-user-with-password.ts`.

### Input validation before hashing

Lines 35–45:

```ts
const email = Email.create(command.email);
const displayName = DisplayName.create(command.displayName);
const rawPassword = RawPassword.create(command.password);

// All throw if invalid. Only now, after validation, do we hash:
const passwordHash = await this.passwordHasher.hash(rawPassword.value);
```

Hashing is expensive (50–100ms by design). Validating first prevents attackers
from burning CPU with garbage input — 500 requests with random strings each
trigger one hash, wasting 50 seconds of server time.

Validating value objects first means if an email is malformed, the request
fails in microseconds before any computational cost.

### Hashing outside the transaction

Line 49–67 hash the password before the database transaction opens:

```ts
const passwordHash = await this.passwordHasher.hash(password);
// This is outside the transaction

const result = await this.unitOfWork.run(async () => {
  // Hashing is already done by the time we get here
  const credential = Credential.create(..., passwordHash);
  // ...
});
```

Why? Two reasons:

1. **Performance:** Holding a database connection during a 60ms hash is
   wasteful. Free the connection, do the expensive work, then reconnect.

2. **Correctness:** If hashing failed with a permission error or OOM,
   aborting would still be inside the transaction, which marks it for
   rollback. The error handling becomes messy. Outside, a hash failure is a
   genuine failure to report.

This pattern applies everywhere hashing is involved — registration and
password reset.

### Password policy: NIST 800-63B, no complexity rules

Look at `packages/credentials/domain/value-objects/raw-password.ts`:

- Minimum: 12 characters
- Maximum: 256 characters
- **No requirement for uppercase + digit + special character**

Why reject complexity rules? NIST 800-63B section 5.1.1.2 explains: they do
not increase security (users either choose predictable sequences like
"Password123!" or write them down), and they break usability and accessibility.

The long minimum (12 characters) and large maximum (256) instead encourages
passphrases: "my dog ate my homework in 2026" is stronger than "P@ssw0rd!" and
easier to remember.

### Secret redaction

All password-related classes override `toString()`, `toJSON()`, and
`Symbol.for("nodejs.util.inspect.custom")` to return `[REDACTED]`:

```ts
toString(): string {
  return "[REDACTED]";
}
```

This prevents accidental disclosure in logs. If a `RawPassword` or `Credential`
is logged, the plaintext or hash never appears — all you see is `[REDACTED]`.

See `raw-password.ts` lines 112–125 and `credential.ts` lines 107–118.

## Stop 8 — Separation of concerns: Identity vs. Credentials

Why is `Credential` a separate aggregate from `User`
(packages/credentials/domain/entities/credential.ts)?

### The design

A `User` (in identity context) has an email, display name, status, and
profile. A `Credential` (in credentials context) has a password hash, lockout
state, and failure counter. They are separate aggregates, separately persisted.

### Why separate?

1. **SSO-only accounts:** A user can exist with no password (`Credential`).
   They sign in via OAuth only. No nullable password column, no "is this
   account password-protected" guard needed everywhere.

2. **Passkey-only accounts (Phase 09):** In the future, a user might have a
   passkey but no password. The same structure works: `Credential` is not
   created.

3. **Organizational boundaries:** Password management (hashing, lockout,
   reset) is separate from user management (profile, status). A future
   integration can revoke the password credential and replace it with SSO
   without touching the user.

4. **Auditing:** Credential creation, password change, and lockout are
   recorded in the audit log separately from user registration and profile
   updates. The timeline is clearer when concerns are separated.

Separation is not always right — Verixa uses guidelines from
`docs/guides/domain-modeling.md`. This case justifies it because the lifecycle
is genuinely different (password changes exist; users do not "change" in the
same way) and the access patterns diverge (password is never returned in
responses; user profile is).

## Stop 9 — Test structure: behavior over implementation

Open `authenticate-with-password.spec.ts`.

### What this test suite verifies

- **Success cases:** Correct credentials, pending users, case-insensitive
  email normalization.
- **Failure enumeration:** All six failure modes return identical responses.
- **Timing:** Both the "no credential" and "wrong password" paths call verify()
  the same number of times, proving they do identical work.
- **Lockout:** Threshold, exponential backoff, cap, reset on success.
- **Rehashing:** Upgrade on weaker parameters, no-op on current parameters,
  upgrade failure does not fail login.
- **Audit logging:** Success and failures record appropriate events.

### What this test suite does NOT verify

- **Wall-clock timing:** That would be fragile and flaky. The test counts
  verify() calls instead, which is deterministic.
- **Exact failure message wording:** The message is tested once in a test
  called "returns enumeration-safe error", then other tests just assert
  `expectError(result, "AUTHENTICATION_FAILED")`. Wording is not the security
  property; the property is that all failures look identical.

This pattern of testing behavior over implementation is throughout the
credentials package. See `docs/guides/testing.md` for the reasoning.

## Stop 10 — Related reading

- `docs/security/password-storage.md` — parameters, PHC format, upgrading
  hashes over time, a security checklist.
- `docs/security/authentication-flows.md` — enumeration resistance, timing
  attacks, lockout mechanics, email verification, password reset.
- `docs/security/token-storage.md` — why CSPRNG tokens use fast hashes,
  timing-safe comparison, single-use requirements.
- `docs/guides/use-cases.md` — the command-and-Result pattern all use cases
  follow.
- `docs/guides/testing.md` — contract testing and why the
  `authenticate-with-password.spec.ts` structure is the way it is.

## Security properties checklist

Before shipping authentication, verify:

- [ ] Hashing is **outside transactions** — no connection held during the
      expensive operation.
- [ ] Password policy is **enforced in a value object** — RawPassword or
      equivalent — before any database access.
- [ ] Hashing is **transparent on successful login** — old hashes upgrade
      automatically without requiring a password reset.
- [ ] All login failures return **identical error, message, HTTP status** —
      no enumeration oracle through the response.
- [ ] Response time is **identical for all failures** — decoy hashing
      prevents timing analysis.
- [ ] Lockout uses **exponential backoff with a cap** — fast attacks
      collapse; users escape after one hour max.
- [ ] Lockout is checked **before hashing** (performance optimization),
      **with decoy hashing to prevent timing leaks** (security).
- [ ] Account status is checked **after password verification** — suspended
      accounts fail like wrong passwords.
- [ ] Email verification tokens are **256-bit CSPRNG, SHA-256 hashed,
      single-use** — the leaked database yields nothing usable.
- [ ] Password reset tokens are **shorter-lived (1 hour vs. 24 hours)** and
      **single-use** — old emails cannot backdoor an account forever.
- [ ] Password reset **revokes sessions** (even if the revocation fails and
      is surfaced as a warning) — the user is not left believing they are safe
      when they are not.
- [ ] All secrets in logs are **redacted** — `[REDACTED]` for passwords,
      tokens, and hashes.
- [ ] Test coverage is **comprehensive and verifies behavior** — timing
      through verify() calls, not wall-clock; enumeration through identical
      error responses, not timing.

## Exercise

Pick one:

1. **Implement password reset.** It should request a reset token (returning
   success always), then confirm it by hashing a new password, updating the
   credential, and revoking sessions. Use `password-reset-token.ts` as the
   token model and follow the enumeration-safe patterns from Stop 6. Write
   tests against an in-memory credential repository.

2. **Upgrade the lockout threshold.** Modify lockout-policy.ts to use 10
   failures instead of 5, and verify that all lockout tests still pass. Then
   add a test that specifically verifies the exponential backoff formula is
   correct for your new threshold (attempt 15 should lock for ~16 minutes,
   capped at 1 hour).

3. **Add a "breached password" check.** Create a `BreachedPasswordChecker`
   port (interface) that takes a plaintext password and returns whether it
   appears in a known-compromised list. Wire it into `RegisterUserWithPassword`
   so that registration rejects passwords that have appeared in public
   breaches. Implement a fake adapter for testing and write tests that verify
   registration is rejected for breached passwords. (Real implementation —
   querying a service like haveibeenpwned.com — is Phase 14, but the domain
   and port can exist now.)

Either exercise deepens your understanding of one critical piece: the
properties that make login secure, the policies that make lockout effective
without becoming a DoS, or the reasoning behind rejecting weak passwords before
they are hashed. Pick one and do it.

