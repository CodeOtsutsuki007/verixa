# Multi-Factor Authentication (MFA) Architecture & Security Design

This document details Verixa's multi-factor authentication architecture, security invariants, threat model, and ceremony protocols.

---

## 1. Core Model & Method Decoupling

Verixa models second factors through an abstract aggregate family (`MfaMethod` in `packages/mfa/domain/entities/mfa-method.ts`) rather than discrete, uncoordinated tables. This ensures that the enforcement engine, step-up prompts, and session gates remain factor-agnostic: whether a challenge is satisfied via TOTP, WebAuthn/FIDO2, or backup recovery codes, the lifecycle rules (`pending`, `active`, `disabled`) remain uniform.

---

## 2. WebAuthn Registration Ceremony (`RegisterWebAuthnCredential`)

WebAuthn (FIDO2) provides hardware-backed, phishing-resistant credentials. Unlike shared secrets (such as passwords or TOTP seeds), the server **never** receives or stores a private key: the private key remains locked within the authenticator hardware (Secure Enclave, YubiKey, TPM), and only an asymmetric public key is registered with the Relying Party (RP).

### Registration Protocol Flow

```
User Agent (Browser)                  Verixa API                      Authenticator
         |                                |                                 |
         | --- 1. issueChallenge(userId) ->|                                |
         |                                | (generate 32-byte CSPRNG token) |
         | <- 2. { challenge, expiresAt } -|                                |
         |                                |                                 |
         | --- 3. navigator.credentials.create({ challenge, rp, user }) --->|
         |                                |                                 |
         |                                |    [Verify User Presence (UP)]  |
         |                                |    [Generate Keypair]           |
         |                                |    [Sign / Bind Origin & RP ID] |
         |                                |                                 |
         | <- 4. PublicKeyCredential ---------------------------------------|
         |    (clientDataJSON, attestationObject)                           |
         |                                |                                 |
         | --- 5. execute(registration) ->|                                 |
         |                                | 6. Verify Challenge & Consume   |
         |                                | 7. Verify ClientData Origin     |
         |                                | 8. Verify RP ID Hash & Flags    |
         |                                | 9. Extract Credential & PubKey  |
         |                                | 10. Persist active MfaMethod    |
         | <- 11. Ok({ mfaMethod, cred }) -|                                 |
```

### Phishing Resistance: Origin & RP-ID Protocol Binding

Origin and RP-ID binding is what makes WebAuthn phishing-resistant:

- A user tricked into navigating to a look-alike phishing domain (e.g. `https://verixa-login.phishing.example`) will have their browser populate `clientDataJSON.origin` with `https://verixa-login.phishing.example`.
- The browser queries the authenticator strictly for the origin shown in the browser address bar. The authenticator computes `rpIdHash = SHA256("verixa-login.phishing.example")`.
- When Verixa's `AttestationVerifier` verifies the attestation against the real RP ID (`verixa.example`) and real expected origin (`https://verixa.example`), the origin and RP ID hash checks mechanically fail.
- Unlike a TOTP code or SMS code—which a user can be deceived into relaying to an adversary—WebAuthn binding is enforced by client cryptographic hardware and browser security boundaries, rendering credential-forwarding attacks impossible.

### Single-Use and Time-Bounded Challenge Lifecycle

To protect against replay attacks and pre-computed registration responses:

1. **Single-Use Invariant:** Every challenge is stored in `WebAuthnChallengeRepository` and marked consumed immediately upon receipt in `RegisterWebAuthnCredential.execute()`. Any subsequent submission with the same challenge string is rejected with a validation error.
2. **Time-To-Live (TTL):** Challenges expire after 5 minutes (300,000 ms). Expired challenges are discarded, preventing stale challenges from lingering or being harvested.
3. **User Binding:** Challenges are strictly bound to the requesting `userId`. An attestation generated for User A cannot be redeemed by User B.

### Immediate Activation Invariant

In contrast to TOTP (which creates a `pending` method requiring an explicit `ConfirmTotpEnrollment` code verification step before activation), WebAuthn credentials are created directly as `active`.
_Design Decision & Alternatives Rejected:_

- **Rejected alternative (Two-step pending/activate ceremony for WebAuthn):** We rejected requiring an extra assertion step after registration. In TOTP, a user might scan a QR code incorrectly or fail to save the secret, so proof of code generation is required to prevent self-lockout. In WebAuthn, completing `navigator.credentials.create()` _is_ cryptographic proof of device possession, authenticator presence, and key generation. Adding a secondary confirmation step adds friction without increasing security.

### Storage: Public Key Only

`WebAuthnCredential` persists:

- `credentialId`: The unique identifier generated by the authenticator for key retrieval.
- `publicKey`: The public key bytes (COSE / base64url format).
- `signCounter`: The authenticator sign count (initialized at registration, used for clone detection in Issue 113).
- `transports`: Transport hints (`internal`, `usb`, `nfc`, `ble`, `hybrid`).
- `attestationType`: Attestation format (e.g. `none`, `packed`).

Even in the event of an arbitrary database compromise, no private key material exists on the server, eliminating offline credential cracking.

---

## 3. WebAuthn Authentication Ceremony (`VerifyWebAuthnAssertion`)

The authentication ceremony verifies that a user attempting to authenticate or step-up possesses the physical security key or platform passkey enrolled during registration.

### Authentication Protocol Flow

```
User Agent (Browser)                  Verixa API                      Authenticator
         |                                |                                 |
         | --- 1. issueChallenge(userId) ->|                                |
         |                                | (generate 32-byte CSPRNG token) |
         | <- 2. { challenge, expiresAt } -|                                |
         |                                |                                 |
         | --- 3. navigator.credentials.get({ challenge, rpId, allowCreds })>|
         |                                |                                 |
         |                                |    [Verify User Presence (UP)]  |
         |                                |    [Increment Signature Counter]|
         |                                |    [Sign AuthData || DataHash]  |
         |                                |                                 |
         | <- 4. PublicKeyCredential ---------------------------------------|
         |    (clientDataJSON, authenticatorData, signature)                |
         |                                |                                 |
         | --- 5. execute(assertion) ---->|                                 |
         |                                | 6. Verify Challenge & Consume   |
         |                                | 7. Verify ClientData Origin     |
         |                                | 8. Verify RP ID Hash & UP Flag  |
         |                                | 9. Verify Signature w/ PubKey   |
         |                                | 10. Check SignCounter (Clone)   |
         |                                | 11. Advance Counter & Touch TS  |
         | <- 12. Ok({ credential, mfa }) -|                                 |
```

### Signature Verification over `authenticatorData || clientDataHash`

The authenticator asserts possession by signing the concatenation of:

1. `authenticatorData` (containing RP ID hash, flags including User Presence `UP`, and the 32-bit big-endian signature counter).
2. `SHA-256(clientDataJSON)` (binding the challenge and origin).

`WebAuthnAssertionVerifier` loads the registered public key (COSE or PEM format) and cryptographically verifies the signature over this payload.

### Clone Detection via Signature Counter

FIDO2 authenticators maintain an internal monotonic counter (`signCount`) that increments with every assertion.

- **Legitimate usage:** Every assertion yields a `signCounter` strictly greater than the previously recorded counter (`newCounter > storedCounter`).
- **Clone detection:** If a physical authenticator's internal state or private key is cloned or copied to a second device, assertions from the cloned authenticator will produce counter values that collide with or lag behind the genuine authenticator (`newCounter <= storedCounter`).
- **Security Escalation:** When a non-increasing counter is observed (and counter tracking is active with `storedCounter > 0`), Verixa flags this as suspected credential duplication:
  1. Immediately emits a `WebAuthnCloneSuspected` domain event (`mfa.webauthn.clone_suspected`).
  2. Records an authentication failure attempt on the associated `MfaMethod` (triggering automatic lockout if repeated).
  3. Rejects the assertion ceremony with a validation error.

# Multi-Factor Authentication (MFA) Design

Verixa implements a flexible, policy-driven multi-factor authentication system. This document outlines the design decisions and security properties of the supported MFA methods.

## Time-Based One-Time Passwords (TOTP)

The TOTP implementation in Verixa strictly follows [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238).

### Algorithm and Parameters

We use the standard parameters supported by nearly all authenticator apps (Google Authenticator, Authy, Bitwarden, etc.):

- **Algorithm:** HMAC-SHA1
- **Time step (`period`):** 30 seconds
- **Code length (`digits`):** 6

While RFC 6238 supports SHA-256 and SHA-512, adoption among authenticator apps remains inconsistent. HMAC-SHA1 provides more than adequate security for TOTP, as the security bottleneck is the short, fast-expiring 6-digit code rather than the hash collision resistance.

### Secret Generation and Storage

The TOTP secret is a 20-byte value generated using a Cryptographically Secure Pseudorandom Number Generator (CSPRNG), yielding 160 bits of entropy. It is stored and communicated in Base32 encoding to remain compatible with standard `otpauth://` provisioning URIs and manual entry by users.

**Security invariants:**

- The secret is treated as highly sensitive. Like passwords, it is redacted across all serialization boundaries (`toJSON`, `toString`) to prevent accidental leaks in application logs.
- The secret is only displayed to the user once, during initial enrollment.

### Interoperability and Testing

Because TOTP's security relies on a shared secret and synchronized clocks, not algorithm secrecy, proving that the implementation exactly matches the RFC is critical.

The `TotpAlgorithm` domain service is explicitly tested against the standard test vectors provided in the RFC 6238 appendix. This guarantees that codes generated by standard authenticator apps will be correctly verified by our backend.

### Validation Time Window

Network latency, clock drift on the user's device, and the time it takes a user to type a code can cause a TOTP code to arrive just after its 30-second window expires.

To handle this gracefully, the verification algorithm accepts codes within a small sliding window (`Â±1` step, i.e., 30 seconds before or after the current server time). This provides a 90-second overall acceptance window, minimizing false rejections without significantly degrading security.

## TOTP Enrollment

When a user begins the TOTP enrollment process, we generate a CSPRNG base32 secret and an \otpauth://\ provisioning URI.

**Why we persist a \pending\ method immediately:**
We persist the \MfaMethod\ immediately in a \pending\ state, rather than waiting for the first successful verification to persist anything.
_Alternative considered:_ Hold the secret in a session or client-side, and only write to the database once confirmed (Issue 104).
_Reason rejected:_ Storing the secret in a session requires distributed session state and complicates cross-device enrollment. Persisting as \pending\ is stateless for the API servers, avoids session bloat, and crucially ensures that we can strictly rate-limit confirmation attempts against a stable database record.

**Why the secret is returned exactly once:**
The enrollment use case returns the plaintext secret and provisioning URI exactly once to the caller.
_Alternative considered:_ Store the secret in plaintext or allow re-retrieval.
_Reason rejected:_ TOTP secrets cannot be one-way hashed because the server needs the plaintext to compute expected codes during login. However, storing them in plaintext is a severe risk in a database breach. We rely on symmetric encryption-at-rest at the storage layer (Issue 107). The plaintext is returned once to the caller solely to generate the QR code, minimizing its exposure. If a user fails to scan the QR code, they must generate a new pending method rather than retrieve the old secret.

### Confirming Enrollment

To transition a \pending\ method to \ctive\, the user must provide a valid 6-digit TOTP code generated by their device using the secret.

**Why we rate-limit enrollment confirmation:**
Even though the method is not yet gating a session, guessing attempts against the \pending\ method are rate-limited.
_Alternative considered:_ Only rate-limit authentication challenges, since an unconfirmed secret doesn't gate access yet.
_Reason rejected:_ A 6-digit code has only 1,000,000 possibilities. Unthrottled guessing within the 30-second window is computationally trivial for an attacker. If an attacker guesses the code for a pending method (e.g. they know the user is currently enrolling), they can activate it on behalf of the user, locking the user out or establishing a persistent backdoor. Rate-limiting the \pending\ state is as important as the \ctive\ state.

## TOTP Verification & Replay Protection

During login or step-up authentication, the server verifies a submitted TOTP code against an \ctive\ method, allowing a minor configurable clock drift (e.g., ±1 time step).

**Why we track the \lastUsedStep\:**
Clock-drift tolerance is a usability necessity (phones and servers rarely agree to the second), but each extra step widens the window in which a single 6-digit code is valid.
_Alternative considered:_ Accept any code that mathematically validates within the current or adjacent time step without persistent state.
_Reason rejected:_ Accepting a code unconditionally enables immediate replay attacks within the 30-90 second validity window. If a user enters their code on a compromised network or phishing proxy, the attacker could reuse the same code milliseconds later. By persisting the \lastUsedStep\ on the \MfaMethod\ and strictly rejecting any authentication attempt that maps to a step less than or equal to it, we completely neutralize replay attacks within the drift window.

# MFA Design & Security Properties

## Step-up Authentication

Sensitive actions (such as changing an email address, disabling MFA, or performing administrative operations) require re-verification of an active multi-factor authentication method even if the user already holds a valid session.

### Short-Lived Claims and Scoped Enforcement

Rather than issuing a full new session token or requiring complete re-authentication, Verixa issues a short-lived `stepUpVerifiedAt` assertion scoped narrowly in time (e.g., maximum age of 5 minutes).

**Why we implement step-up authentication instead of full re-login or raw session reuse:**

- _Session possession alone is insufficient:_ A long-lived session token can be vulnerable to theft or unauthorized access if a user leaves a device unlocked (e.g., at a shared workstation or unattended laptop). High-risk operations like changing account credentials or disabling security boundaries require explicit, fresh proof of user presence rather than passive session possession.
- _Avoiding full re-login friction:_ Forcing a user to re-enter their primary password and complete a full credential login flow for minor administrative tasks degrades UX unnecessarily. Step-up auth re-verifies only the second factor or backup code challenge, confirming active presence without invalidating or re-issuing the broader session token.

**Alternative rejected:** Full re-login or issuing an entirely new session on high-risk actions.
_Reason rejected:_ Full re-login tears down client state, forces refresh token rotation prematurely, and complicates single-page app token management. Scoping a `stepUpVerifiedAt` timestamp directly onto the existing active `Session` aggregate provides a precise, audit-logged guarantee without disrupting overall session continuity.

### Reuse of Verification Use Cases

Step-up authentication reuses the core verification logic for TOTP and backup codes rather than duplicating cryptographic or validation code across multiple endpoints. The step-up use case validates the submitted factor against the active method repository, records rate-limiting / failure counters on incorrect attempts, and stamps the verified timestamp upon success.

### Staleness Rejection and Expiry Policy

Any step-up assertion whose age exceeds the configured maximum age threshold (checked via `isStepUpFresh(maxAgeMs, now)`) is strictly rejected by the enforcement policy. This ensures that a step-up verification performed for one sensitive action cannot be chained indefinitely across subsequent high-risk requests without re-assertion.

## Backup Codes

Backup codes provide a critical recovery path for users who lose access to their primary second factors (like a TOTP device or passkey).

### Storage Strategy: Hashed, Never Encrypted

Unlike TOTP secrets—which must be symmetrically encrypted at rest because the server requires the plaintext to compute the expected HMAC during login—backup codes are **hashed** using a slow key derivation function (Argon2), identical to the strategy we use for passwords in Issue 061.

**Why?**
Backup codes are effectively low-entropy, system-generated passwords. They are used exactly once and presented in plaintext by the user.
If we encrypted them at rest (like TOTP secrets), an attacker with database read access and the application's encryption key could decrypt the backup codes and bypass MFA on any account. By hashing them instead, we ensure that even a full compromise of the database and the environment variables (including the encryption key) does not reveal the backup codes. The server only needs to verify the hash when a user submits a code, meaning it never needs to recover the plaintext.

### Single-Use Enforcement

Each backup code is single-use. Once a code is successfully verified, its corresponding hash must be immediately removed from the database to prevent replay attacks. Because they are hashed, removing a single code's hash does not compromise the security of the remaining unused codes in the set.

### Regeneration and Atomic Invalidation

When a user requests a new set of backup codes, the new set completely replaces any previously issued codes for that account. This is implemented via an atomic invalidation-and-reissue in the GenerateBackupCodes use case: any existing MfaMethod of type ackup_codes is deleted before the new one is persisted.

**Why?**
We deliberately rejected the alternative of "appending" new codes to an ever-growing pool of valid backup codes. While an additive pool might seem more forgiving if a user finds an old printout, it is insecure: it means a compromised set of codes remains permanently valid unless explicitly revoked by the user, and an attacker who gains temporary access could generate a second set for themselves without alerting the user by breaking the first set. Full-set replacement guarantees that the user always has exactly one authoritative, finite set of codes at any time, and that generating a new set acts as an implicit revocation of any previously compromised or lost sets.

## Admin-Assisted MFA Recovery

When a user loses all enrolled MFA methods and exhausts backup codes, an administrator can restore access via the `RecoverMfaAccess` use case.

### What the flow does

1. Validates that a distinct, authenticated admin actor (`actorAdminId`) and a human-readable `reason` are present.
2. Emits an `mfa.recovery.initiated` audit entry **before** any mutation, so the record is durable even if the process dies mid-execution.
3. Loads all active **and** pending MFA methods for the target user and disables each one via `MfaMethod.disable()`. Pending methods are cleared too — a pending TOTP secret is still a phishable secret.
4. Revokes all active sessions for the target user via the `SessionRevoker` port, preventing an attacker who engineered the recovery from riding an existing session.
5. Emits an `mfa.recovery.completed` audit entry with `methodsCleared` and `sessionsRevoked` counts.

### Why methods are disabled, not deleted

Disabling preserves the audit trail. A later investigation can see which methods existed, when they were created, and when they were disabled. Hard-deleting would destroy that evidence.

### Why the flow cannot be self-triggered

An MFA recovery that a user can initiate themselves is an MFA bypass: knowing the password is sufficient to skip the second factor. Requiring a distinct authenticated admin actor — whose own authentication is separately gated — closes that hole. The use case enforces this at the contract level by rejecting an empty `actorAdminId`.

### Re-enrollment on next login

This use case only disables old methods and revokes sessions. On next login the enforcement policy (Issue 114) detects no active methods under a `required` policy and gates on re-enrollment. The recovery use case does not need to know about that flow.

### Port design: SessionRevoker

`SessionRevoker` is defined as a port interface in `packages/mfa/application/ports/session-revoker.ts` rather than importing directly from `@verixa/sessions`. This keeps `@verixa/mfa` free of a session-layer dependency and lets the application host wire in any adapter without creating a circular package dependency.

## MFA Enforcement Policy (Issue 114)

### What the policy resolves

For any user, in any organization, the policy engine (`MfaEnforcementPolicy`
in `packages/mfa/domain/services/mfa-enforcement-policy.ts`) resolves two
things:

1. **`level`**: `required | optional | disabled`
2. **`allowedMethods`**: the subset of `["totp", "webauthn", "backup-codes"]`
   the user may enroll or use

The two fields are resolved independently so an org can say "TOTP only"
without also mandating MFA for every user — or can mandate MFA while still
allowing all method types.

### Precedence (highest → lowest)

```
user override
  ↓
role overrides (strictest level wins; intersection of allowed methods wins)
  ↓
org override
  ↓
global default (env var MFA_ENFORCEMENT_LEVEL / MFA_ALLOWED_METHODS)
```

The first scope that explicitly sets `level` wins for `level`; the first scope
that explicitly sets `allowedMethods` wins for `allowedMethods`.

### Why "strictest role wins"

The alternative — letting any role relax enforcement — is insecure. An admin
could attach a permissive role to themselves to bypass the org's MFA mandate.
Strictest-wins means adding a role never reduces security; it can only add
constraints.

### Why intersection for role `allowedMethods`

Same reasoning: union would let a permissive role undo the restrictions of a
stricter one. Intersection ensures a method must be permitted by _every_
restricting role to remain allowed.

### `required` with no enrolled methods blocks login

A `required` policy with zero enrolled methods (or with all enrolled methods
outside `allowedMethods`) causes `isEnrollmentRequired()` to return `true`.
The login flow (Issue 116) gates on enrollment in that case; it does not
issue a session. This is what makes the policy non-decorative.

**Alternative considered:** accept the `required` level but silently skip the
MFA challenge when the user has no enrolled methods, treating it as optional
in practice.

**Reason rejected:** that makes `required` a best-effort hint rather than a
security control. If the goal is mandatory MFA for admin roles, a newly
created admin who has not yet enrolled would bypass the policy on every login
until they happen to enroll. Blocking and gating on enrollment is the only
interpretation that makes "required" mean what it says.

### Global defaults live in environment variables

Per-user and per-org config belongs in the database (it is per-tenant and
there can be millions of rows). The global default, however, is
deployment-wide and operator-set, so it lives in `MFA_ENFORCEMENT_LEVEL` and
`MFA_ALLOWED_METHODS` environment variables validated by the typed config
loader (`packages/config`).

**Alternative considered:** store the global default in the database too,
as a single "system settings" row.

**Reason rejected:** the config loader validates all settings at startup and
fails fast with a descriptive error before the process accepts requests. A
database-stored global default would not be validated until the first request
that triggered a policy lookup, turning a misconfigured deployment into a
runtime failure rather than a startup failure. Environment variables are also
the idiomatic place for operator-supplied deployment configuration in
twelve-factor applications.
