# Threat Model: Credential Flows

A STRIDE-based threat model for Verixa's registration, login, password reset,
and email verification flows. This document describes what threats each phase
of the credential system is designed to defend against, how each attack is
mitigated, and where accepted risks remain.

## Overview: the flows

The credential system consists of four user-initiated flows:

- **Registration** (Phase 06): Creating an account with an email and password.
- **Email verification** (Phase 06): Proving control of the registered email.
- **Login** (Phase 04): Authenticating by email and password.
- **Password reset** (Phase 08): Recovering an account by email, issuing a new
  password.

All flows use expiring, single-use, hashed tokens. Login and reset issue
tokens that are themselves bearer credentials. All flows are designed to
prevent user enumeration — they leak nothing about whether a given email has
an account.

## STRIDE model

STRIDE is six categories of threat (Spoofing, Tampering, Repudiation, Information
Disclosure, Denial of Service, Elevation of Privilege). Not all categories apply
equally to credential flows; the ones that do are:

| Threat | Applies | Mitigation |
| --- | --- | --- |
| **Spoofing** | Yes | Verify the user is who they claim: password verification, token verification |
| **Tampering** | Yes | Hashing prevents alteration of stored passwords and tokens |
| **Repudiation** | No | Audit logging is out of scope for Phase 04 |
| **Information Disclosure** | Yes | The main category: token theft, credential stuffing, user enumeration |
| **Denial of Service** | Yes | Account lockout, rate limiting (partial, Phase 15) |
| **Elevation of Privilege** | No | Authorization (who can do what) is Phase 07 |

The following sections walk through the threats in each category relevant to
these flows, the attack vector, the mitigation, and cross-references to which
issues or design decisions address each one.

---

## Spoofing: Verifying the user is who they claim

### S-1: Password guessing

**Threat:** An attacker who does not know the password can guess it, trying
many candidates per second.

**Why it matters:** Passwords are human-chosen and relatively low-entropy.
Against a simple iteration count or no hashing, a modern GPU can try billions
of guesses per second. Against a deliberately slow KDF, an attacker is limited
to thousands per second; across a large user base, billions of attempts still
carve through some accounts over time.

**Attacker profile:** Offline attacker (has acquired the password database,
e.g. via SQL injection or a data breach), or online attacker with access to
the login endpoint.

**Mitigation:**

- **Argon2id with OWASP minimum parameters** (Issue 061): Password hashing
  uses Argon2id at 19 MiB memory, 2 time costs, 1 parallelism — OWASP's
  recommended floor. This raises the cost per guess from microseconds to
  50–250 milliseconds, reducing a GPU with 10,000 cores from "billions of
  guesses per second" to "thousands per second." Over a database of
  100,000 users, an attack that would have taken 30 seconds now takes a
  year.
- **Transparent rehashing on login** (Issue 061): As hardware improves and
  parameters rise, existing hashes are upgraded when their owner logs in.
  Passwords migrate gradually rather than staying at old strength forever.
- **Account lockout with exponential backoff** (Issue 067): After 5
  consecutive failures, lockout starts at 1 minute and doubles (capped at 1
  hour). A patient offline attack doesn't exist — the database is already
  compromised. An online attack of 5 guesses per account per day becomes
  0 guesses per account after the first day (locked for 1 hour) and
  meaningless within a week.
- **Rate limiting** (Phase 15, not yet complete): The login endpoint itself
  will rate-limit by source IP and email address, making high-volume online
  attacks impractical without also mitigating network reconnaissance.

**Residual risk:** An attacker with 10,000 GPU cores and a stolen database
containing 1,000,000 users _eventually_ cracks a small percentage of passwords
(most users choose weak ones). This is accepted — password strength policy
(Issue 062) mitigates this further but cannot eliminate it. The most practical
defense remains account lockout for online attacks and not leaking databases
for offline attacks.

---

### S-2: Token forgery and guessing

**Threat:** An attacker fabricates or guesses an email-verification token,
password-reset token, or other bearer token to impersonate a user or reset
their password.

**Why it matters:** Unlike passwords (which an attacker tries to guess), a
token only needs to be guessed once per attack. Email-verification tokens
grant the ability to activate any pending account. Reset tokens grant the
ability to set a new password for any account. If tokens are weak or forgeable,
the cost of an attack is close to zero.

**Attacker profile:** Online attacker with access to the token-issue endpoint
or someone who intercepted a token in transit.

**Mitigation:**

- **256-bit CSPRNG tokens** (Issues 068, 069): Email verification and password
  reset tokens are generated as 128-bit UUIDs, providing 128 bits of entropy
  (not the full UUID's structure, but close). The probability of guessing a
  valid token is roughly 1 in 3.4 × 10³⁸ — cryptographically equivalent to
  impossible.
- **Hashing tokens before storage** (Issue 068, 069): Only the SHA-256 hash is
  stored. A leaked database yields nothing usable; the raw token exists only
  once, in the email that was sent.
- **Single-use enforcement** (Issue 068, 069): Each token can be used exactly
  once. After use, it is marked as consumed and cannot be used again. An
  attacker who obtains a used token has no value.
- **Expiry enforcement** (Issue 068, 069): Email verification tokens expire
  after 24 hours; reset tokens after 1 hour. Expiry is checked against the
  database record, not a client claim, so it cannot be bypassed.
- **Token revocation on new issue** (Issue 068, 069): Issuing a new token
  revokes all outstanding ones. If a user requests a reset email twice, the
  first reset link stops working, limiting the window an attacker has if they
  intercepted one.

**Residual risk:** A token transmitted over unencrypted email (if the mail
provider does not enforce TLS) can be intercepted in transit. This is accepted
— mail transport is not under the application's control. The application
cannot force TLS-only mail; users must trust their mail providers. Long-form
password reset is considered more trustworthy (the user initiates it) and
happens over a channel they already trust (email), which is not the same as
the password being transmitted at all.

---

## Tampering: Preventing alteration of credentials

### T-1: Password modification by unauthorized party

**Threat:** An attacker who gains access to the password database can modify
or replace a stored hash, making the password something they chose.

**Why it matters:** If password hashes are stored in plaintext or encrypted,
an attacker with database access can set the hash of any account to one they
know the password for and immediately log in.

**Attacker profile:** Insider with database read/write access, or an external
attacker who achieved database compromise via SQL injection or similar.

**Mitigation:**

- **Hashing instead of encryption** (Issue 061): Passwords are hashed, not
  encrypted. A hash is one-way; you cannot reverse or modify it to produce a
  known plaintext. An attacker who modifies a hash has corrupted it, not
  replaced it with something useful.
- **Self-describing hash format** (Issue 061): The PHC format
  `$argon2id$v=19$m=19456,t=2,p=1$...` includes the algorithm and parameters.
  If an attacker replaces a hash with one computed at weaker parameters, the
  next login will reject it (the hash cannot be verified with the wrong
  parameters).

**Residual risk:** An attacker who gains write access can delete a hash
entirely, locking the user out. This is accepted — database write access
implies compromise of the application's security model entirely, and there is
no mitigation short of not storing passwords at all.

---

### T-2: Token modification or substitution

**Threat:** An attacker modifies a token (changing the email it unlocks, the
password it resets, etc.) or substitutes a different token to perform a
different action.

**Why it matters:** If tokens are unprotected, an attacker could take a
legitimate token, modify it, and use the modified version for unauthorized
purposes.

**Attacker profile:** Online attacker with access to tokens in transit (proxy,
network tap) or at rest (email forwarding, browser history).

**Mitigation:**

- **Hashing and lookup** (Issues 068, 069): Tokens are hashed before storage,
  and verification is a database lookup by hash. Modifying a token changes its
  hash, which will not match any stored value, so the modified token is
  rejected with no hint of what was wrong.
- **Expiry and single-use** (Issues 068, 069): Tokens are marked as consumed
  after first use. Replaying a token (even unmodified) fails. If a token
  expires before use, it is also rejected.

**Residual risk:** None identified within the scope of database and
application integrity. The residual risks are in token transit (section S-2)
and token revocation completeness (see S-3).

---

### T-3: Session hijacking (out of scope for Phase 04)

**Threat:** An attacker obtains a valid session token and uses it to act as
the user.

**Why it matters:** Sessions are the main way users stay logged in without
re-entering passwords on every request. If a session token is compromised, the
attacker gains full access to the user's account until the session expires or
the user logs out.

**Current state:** Sessions are Phase 05; Phase 04 does not issue sessions or
tokens that persist beyond the login response. The login endpoint returns a
user object but no session token or refresh token.

**Mitigation (Phase 05):** To be addressed in token-storage and session-management work.

---

## Information Disclosure: Preventing unauthorized revelation of secrets

This is the largest category for credential flows. It covers user enumeration,
token theft, and credential stuffing — attacks that succeed by learning
information they should not have.

### I-1: User enumeration via login endpoint

**Threat:** An attacker can distinguish "no account with that email" from
"account exists but wrong password" by observing the response, response time,
or both.

**Why it matters:** Enumeration tells an attacker which email addresses have
accounts. This enables credential stuffing (the attacker now knows valid
usernames and only has to guess passwords) and membership leaks (the attacker
learns who is a customer or member of the platform).

**Attacker profile:** Unauthenticated online attacker with access to the login
endpoint.

**Attack variations:**
- Response message: Some endpoints return "no such user" vs. "wrong password".
- Response time: Missing-user lookups are faster than password verification,
  revealing the answer through latency.
- HTTP status code: Returning 404 for "no user" vs. 401 for "wrong password".

**Mitigation:**

- **Identical error message and HTTP status for all failures** (Issue 064):
  All six failure modes (no account, malformed email, no password credential,
  wrong password, suspended account, locked credential) return HTTP 401,
  code `AUTHENTICATION_FAILED`, message `Invalid email or password.`, with
  no field-level errors. The message is identical regardless of which failure
  occurred.
- **Decoy hash verification for missing users** (Issue 064): When no credential
  is found for the email, the system verifies the submitted password against a
  **decoy hash** instead of returning immediately. The decoy is a genuine
  Argon2id hash of a password nobody holds, computed by the same hasher at the
  same cost parameters. Both code paths (real user, wrong password vs. missing
  user, decoy hash) perform exactly one hash verification.
- **Lockout check before password verification** (Issue 067): The one place
  where a timing difference is unavoidable is the lockout check, which happens
  before hashing. Locked credentials are rejected immediately (fast path).
  However, a decoy hash verification also runs on the locked path, so the fast
  path does not announce an account is under attack.

**Residual risk:** Statistically significant timing differences remain when
averaging across large samples: database lookups, JIT warm-up, garbage
collection, and network jitter add noise that reduces the precision of a
timing attack. However, none of this is "indistinguishable under statistical
analysis." The claim made here is narrower: **the obvious order-of-magnitude
difference (2ms lookup vs. 60ms hash) is gone.** An attacker trying to
distinguish the two with a local network tap or local process will see a
noisy signal rather than a clear gap. Attacks that remain are addressed from
the other side: account lockout (5-attempt threshold) and rate limiting
(Phase 15) make the volume of login attempts an enumeration attack needs
impractical regardless of what each one leaks.

---

### I-2: User enumeration via password reset endpoint

**Threat:** An attacker can determine whether an email address has an account
by submitting it to the password reset endpoint and observing whether a reset
email was sent (or not sent, or sent with different timing).

**Why it matters:** Password reset is often a better enumeration vector than
login — it requires no password guess, just valid email addresses.

**Attacker profile:** Unauthenticated online attacker with access to the
password-reset-request endpoint and (usually) the ability to monitor the
recipient's inbox, or to time the request against typical mail delivery.

**Mitigation:**

- **Unconditional success response** (Issue 069): The password reset endpoint
  always returns "If an account with that email exists, we've sent a reset
  link" regardless of whether the account actually exists. A client cannot
  distinguish success from failure.
- **No timing-based detection** (Issue 069): The response is fast regardless;
  it does not block on sending mail. (Actual mail delivery is Phase 14 and
  uses a queue, so it is not on the request path.)
- **Verification moves to email channel** (Issue 069): Confirming which address
  has an account happens over email, not HTTP. Only someone who controls the
  mailbox learns the actual answer.

**Residual risk:** If the attacker controls the mailbox or the mail provider
(or a mail provider's employee), they can verify which addresses have accounts
by observing incoming reset emails. This is accepted — the mail channel is
outside the application's control.

---

### I-3: Credential stuffing

**Threat:** An attacker who has obtained passwords from a breach of another
service tests those passwords against user accounts here (common passwords
include the user's email, reused passwords, and variations).

**Why it matters:** Credential stuffing is one of the most common and
successful attacks against internet services. Users reuse passwords across
services; the attacker simply tries them here.

**Attacker profile:** Online attacker with access to the login endpoint and a
list of known (email, password) pairs from another service's database.

**Mitigation:**

- **Account lockout with exponential backoff** (Issue 067): After 5 consecutive
  failed attempts, the credential locks for 1 minute. Each subsequent attempt
  doubles the lockout (capped at 1 hour). An attacker can make 5 guesses per
  account per day (at 1 minute lockout), which is impractical for testing
  thousands of passwords against thousands of accounts. The attack volume
  collapses within a few days.
- **Rate limiting by source IP** (Phase 15, not yet complete): The login
  endpoint will rate-limit by source IP, making it hard for an attacker to
  distribute attacks across the internet. A single IP that attempts thousands
  of logins will be throttled.
- **Password strength and breach-list checking** (Issue 062): Passwords are
  checked against a breach list (e.g., HIBP) and must meet minimum length
  requirements. Common passwords are rejected at registration time, so there
  is a smaller target surface for stuffing attacks. (Not a direct defense
  against already-compromised passwords, but it prevents the most obvious
  guesses from working.)

**Residual risk:** An attacker with access to many source IPs (botnets, cloud
instances, proxies) can distribute the attack and bypass IP-based rate
limiting. This requires Phase 15 to address properly through additional
mitigation layers (velocity checks, CAPTCHA, etc.).

---

### I-4: Token theft via email

**Threat:** An attacker obtains a valid email-verification or password-reset
token by intercepting or accessing the email that contains it.

**Why it matters:** A stolen token grants the attacker the same capability as
the legitimate recipient: the ability to verify an email address, reset a
password, or accept an invitation. Unlike a password, a token is typically a
one-time use, so the attacker's window is limited but real.

**Attacker profile:** Attacker with access to email in transit (mail provider
employee, network tap, compromised mail server), or at rest (shared inbox,
forwarded email, Gmail forwarded to corporate email, account compromise).

**Mitigation:**

- **Single-use tokens** (Issues 068, 069): Each token can only be used once.
  If an attacker obtains a token but the legitimate user uses it first, the
  attacker's copy is invalid. If the attacker uses it first, the legitimate
  user's attempt fails with a clear message ("this link was already used").
- **Expiry windows** (Issues 068, 069): Email verification tokens expire after
  24 hours; password reset tokens after 1 hour. An attacker who obtains a
  token after expiry cannot use it.
- **Hashed storage** (Issues 068, 069): The token hash is stored, not the raw
  token. An attacker who compromises the database cannot derive the raw token
  from the hash, so they cannot use a token they never saw.
- **Token revocation on new issue** (Issues 068, 069): If a user requests a
  reset email twice, the first token is invalidated. An attacker who obtained
  the first token cannot use it after the legitimate user has requested a
  second one.
- **No logging of raw tokens** (Issues 068, 069): The raw token never appears
  in application logs (not even as debug output). Accessing a log file does
  not yield the token.

**Residual risk:** Email itself is not encrypted or signed by the application.
If a mail provider does not enforce TLS, a token can be intercepted in transit.
This is accepted — the application cannot control mail transport, only choose
to send tokens over the mail channel the user registered with (implying they
consider it trustworthy). A 1-hour reset window mitigates the risk of old
tokens; single-use mitigates the risk of a token being used after the user has
acted on it.

---

### I-5: Privilege escalation via token reuse after change

**Threat:** An attacker who obtained a password-reset token can continue using
it after the user changes their password, gaining access to an account they
have been locked out of (because the password changed).

**Why it matters:** A password reset is supposed to invalidate all sessions and
prevent further access by someone who compromised the account. If old reset
tokens remain valid, the attacker's access is not actually revoked.

**Attacker profile:** Attacker who obtained a reset token (via intercepted
email, leaked backup, database breach) and is attempting to regain access
after the user has already used the reset.

**Mitigation:**

- **Single-use tokens** (Issue 069): Each token can be used once. After use,
  it is marked consumed and cannot be used again. An attacker cannot replay
  the same token.
- **Revoke outstanding tokens on new issue** (Issue 069): Issuing a new reset
  token revokes all existing ones. If the user requests reset twice, the
  attacker cannot use the first token.

**Residual risk:** None identified, provided single-use and revocation are
correctly implemented.

---

### I-6: Session fixation (out of scope for Phase 04)

**Threat:** An attacker tricks a user into using a session token the attacker
supplied or controls, so the attacker can later hijack the session or observe
what the user does within it.

**Current state:** Not applicable; Phase 04 does not issue sessions.

**Mitigation (Phase 05):** To be addressed in session-management work.

---

## Denial of Service: Preventing or limiting account lockout

### D-1: Brute-force account lockout (attacker locks out legitimate user)

**Threat:** An attacker repeatedly submits wrong passwords for a target
account, triggering the account lockout mechanism and locking the legitimate
user out of their own account.

**Why it matters:** If lockout is permanent or requires manual intervention,
this is a denial-of-service attack that costs the attacker only network
bandwidth.

**Attacker profile:** Unauthenticated online attacker with access to the login
endpoint and a target email address.

**Mitigation:**

- **Exponential backoff with a ceiling** (Issue 067): After 5 consecutive
  failures, lockout starts at 1 minute, then doubles (2 min, 4 min, 8 min,
  etc.) up to a 1-hour ceiling. Crucially, the lockout **expires
  automatically** — it is a timestamp field, not a flag that needs clearing.
  An attacker cannot lock an account indefinitely; after 1 hour, the account
  is available again.
- **Successful login resets the counter** (Issue 067): A correct password
  entry clears the failure counter and resets lockout. A user who knows their
  password and succeeds (or waits for the hour to expire) can always regain
  access.
- **Password reset as recovery** (Issue 069): A user who is locked out and
  cannot remember their password can use the reset endpoint to set a new one,
  bypassing the lockout entirely. This is the escape hatch.

**Residual risk:** Between the attacker's first attempt and the account being
locked (5 attempts), the legitimate user cannot log in. This window is bounded
at 5 failed attempts (roughly 100 seconds if the attacker is network-local
with immediate retry). After the first minute of lockout, the user can also
use password reset to recover. This is accepted as a reasonable tradeoff
between defending against credential stuffing and not permanently locking
legitimate users out.

---

### D-2: Mail bombing (attacker floods a user's inbox)

**Threat:** An attacker repeatedly requests password-reset or
email-verification emails to a target address, flooding the user's inbox and
potentially overflowing their mail quota or making it hard to find legitimate
emails.

**Why it matters:** An inbox full of reset emails is both a usability problem
(user cannot find the legitimate one) and a potential vector for phishing
(attacker includes a phishing link in a spoofed reset email alongside the real
ones).

**Attacker profile:** Unauthenticated online attacker with knowledge of the
target email address and access to the reset/verify endpoints.

**Mitigation (Partial — Phase 15):**

- **Token revocation on new issue** (Issue 069): Requesting a new reset email
  invalidates the previous one. If the attacker has sent 10 emails, only the
  latest token is useful. This doesn't stop the flooding, but it limits the
  attacker's benefit.
- **Rate limiting** (Phase 15, not yet complete): The reset and verify request
  endpoints will rate-limit by email address and source IP. An attacker who
  attempts to request 100 emails per second will be throttled. This is the
  main defense.

**Residual risk:** Until rate limiting is implemented, an attacker can send an
unlimited number of reset emails. This is accepted as a gap to be closed in
Phase 15.

---

### D-3: System resource exhaustion (hashing CPU)

**Threat:** An attacker submits many login attempts, each requiring an
expensive Argon2 hash verification, exhausting the server's CPU and slowing
down legitimate traffic.

**Why it matters:** Argon2 is deliberately slow (good for defending against
password cracking). But that slowness means each login attempt is expensive. A
distributed attack with many source IPs could exhaust the server's ability to
serve legitimate users.

**Attacker profile:** Distributed online attacker with access to many IP
addresses and the login endpoint.

**Mitigation:**

- **Lockout check before hashing** (Issue 067): The credential's lockout state
  is checked before performing hash verification. A locked credential is
  rejected immediately (microseconds) without spending CPU on hashing. An
  attacker who hits the same account repeatedly will fall into lockout and
  their attempts will be fast (costing less resources) rather than expensive.
  This converts a CPU exhaustion attack into a storage and memory exhaustion
  attack, which is more defensible.
- **Decoy hash on fast path** (Issue 064): Missing users still run a hash
  verification. An attacker cannot reduce CPU load by targeting non-existent
  emails. Every request pays the cost.
- **Rate limiting** (Phase 15, not yet complete): IP-based and email-based
  rate limiting will limit the number of login attempts an attacker can make
  per second, reducing the total CPU load.

**Residual risk:** Until rate limiting is in place, a well-resourced attacker
with many source IPs can still exhaust CPU by distributing attempts. This is a
known limitation until Phase 15.

---

## Elevation of Privilege

Elevation of privilege (using credentials to do something you should not be
able to do) is primarily handled in Phase 07 (Authorization). Phase 04
establishes who the user is; Phase 07 decides what they are allowed to do.

One exception: password reset should revoke existing sessions to prevent an
attacker who compromised the account (and has a session) from staying in.

### E-1: Session persistence after password reset

**Threat:** An attacker compromises a user's password and logs in, establishing
a session. The user resets the password, but the attacker's session remains
valid, so the attacker can continue acting as the user indefinitely.

**Why it matters:** A password reset is supposed to be a comprehensive lock-out
mechanism — it tells the platform "I believe I was compromised, please lock
out all other sessions." If sessions survive the reset, the reset failed.

**Current state:** Phase 04 does not implement session management. The call site
exists (`ConfirmPasswordReset` calls `sessionRevoker.revoke()`) but the
implementation is `NoSessionsRevoker`, which does nothing.

**Mitigation (Phase 05):** Actual session revocation will be implemented when
sessions are introduced. The call site is in place so session revocation can be
plugged in without changing the credential flow.

**Residual risk:** Until Phase 05, password resets do not revoke sessions
because no sessions exist. This is not a security issue today; it is a gap that
will be filled when sessions are introduced.

---

## Cross-reference: threats to mitigating issues

This table maps each threat to the issue(s) that mitigate it:

| Threat ID | Threat | Mitigating Issues |
| --- | --- | --- |
| S-1 | Password guessing | 061, 067, 062, Phase 15 |
| S-2 | Token forgery and guessing | 068, 069 |
| T-1 | Password modification | 061 |
| T-2 | Token modification | 068, 069 |
| T-3 | Session hijacking | Phase 05 (out of scope) |
| I-1 | User enumeration (login) | 064, 067 |
| I-2 | User enumeration (reset) | 069 |
| I-3 | Credential stuffing | 067, 062, Phase 15 |
| I-4 | Token theft via email | 068, 069 |
| I-5 | Token reuse after change | 069 |
| I-6 | Session fixation | Phase 05 (out of scope) |
| D-1 | Lockout denial of service | 067, 069 |
| D-2 | Mail bombing | 069, Phase 15 |
| D-3 | Resource exhaustion (CPU) | 064, 067, Phase 15 |
| E-1 | Session persistence | Phase 05 (out of scope) |

---

## Summary: the design as a coherent whole

The credential system is built around three interlocking principles:

### 1. **Passwords are expensive, everything else is cheap.**

Argon2id hashing is deliberately slow (50–250ms per attempt). That cost is
paid exactly once per login. Every other defense — user enumeration,
enumeration resistance, credential stuffing — is built to make the attacks
that would bypass the expensive part impractical at scale.

Sending identical errors and verifying decoy hashes against missing users costs
negligible CPU but neutralizes enumeration attacks that would otherwise turn
login into an oracle. Account lockout (itself a very fast check) makes
credential stuffing expensive — not in CPU, but in time (an attacker waiting
out exponential backoff).

The tradeoff is that the system cannot detect enumeration timing attacks under
statistical analysis. That's accepted because the _obvious_ attacks (local
network, same process) are neutered, and the statistical attacks require rate
limiting to defeat anyway (Phase 15).

### 2. **Tokens are secrets, treated like passwords.**

Tokens (for reset, verification) are generated from a CSPRNG, stored as hashes,
compared safely, marked single-use, and revoked when a new one is issued.

They are not treated like passwords for _hashing_: SHA-256 not Argon2,
because there is no dictionary attack against a CSPRNG-generated token. But
they are treated like passwords for _respect_: they are secrets, and the only
place a secret should live is where it was sent to.

This simple rule prevents the most common token-misuse patterns: logging tokens,
re-hashing them uselessly, storing them in plaintext, allowing replay.

### 3. **Failures are indistinguishable, success is rich.**

All authentication failures return the same HTTP response. This is genuinely
worse for legitimate users who typo their email — they get no help. It is
accepted because the alternative (an enumeration oracle) is worse.

Success, by contrast, is rich. Confirming a token tells the client exactly why
it failed (expired vs. used vs. invalid token) because if you made it this far,
you control the mailbox and there is nothing left to enumerate. Authorization
failures (Phase 07) will be similarly rich because those are the privilege
boundaries the system intends to be explicit.

The rule is simple: a boundary where the attacker cannot legitimately prove
they should cross it gets no hints. Everywhere else, as much information as
possible.

---

## Assumptions and limitations

This threat model assumes:

- **Network transport is TLS.** Tokens and credentials in transit are
  protected by TLS. If TLS is not used, tokens and passwords are transmitted
  in plaintext and this model is invalidated. This is not negotiable.
- **Email is a trusted channel.** Users trust their email providers. If a user's
  email is compromised, the attacker has access to reset tokens and
  verification links. This is a risk the user must mitigate by securing their
  email.
- **The database is not publicly readable.** If the database is compromised but
  not written to, passwords are still hashed and tokens are still hashed, so
  the breach yields limited information. If the database is also writable, the
  attacker can modify records and this model is invalidated.
- **Argon2 implementation is correct.** Verixa uses the reference implementation
  via the `argon2` Node.js binding. Bugs in the library would bypass these
  defenses.
- **The system will eventually implement rate limiting (Phase 15).** Several
  mitigations — especially for credential stuffing and mail bombing —
  rely on Phase 15's rate limiting to be fully effective. Until then, there
  are known gaps (bounded by account lockout and token expiry, but incomplete).

---

## Related documentation

- `docs/security/authentication-flows.md` — detailed explanation of why each
  choice was made in the login and reset flows.
- `docs/security/password-storage.md` — argon2 parameters and why they were chosen.
- `docs/security/token-storage.md` — why tokens are hashed and how.
- `docs/guides/error-handling.md` — error propagation and the `Result` type
  used throughout the application.

---

## How to use this model

**For code review:** When reviewing changes to authentication, check that they
do not violate the assumptions listed above or introduce a new threat not
addressed here. Common mistakes include:

- Returning different status codes or messages for different failures.
- Logging or exposing tokens or passwords.
- Accepting plaintext parameters in query strings or URLs.
- Storing tokens in plaintext or encrypting them (one-way hash only).
- Skipping expiry checks or allowing tokens to be reused.
- Changing error messages after success to be different from failure messages,
  converting success into an enumeration oracle.

**For future threat modeling:** This model covers Phase 04 (login, registration,
reset, verification). When Phase 05 (sessions) is added, extend this model to
cover session tokens and refresh tokens. When Phase 15 (rate limiting) is
added, revisit the D-2 and D-3 sections. When Phase 18 (metrics and monitoring)
is added, consider how to alert on brute-force patterns without converting
success/failure logs into enumeration oracles.

