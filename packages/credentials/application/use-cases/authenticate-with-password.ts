import { Email, type User, type UserStatus } from "@verixa/identity";
import { AccountLockedError, AuthenticationError, Result } from "@verixa/shared-kernel";
import type { RateLimiter, RateLimitKey } from "@verixa/shared-kernel";

import type { Credential } from "../../domain/entities/credential.js";
import {
  DEFAULT_LOCKOUT_POLICY,
  type LockoutPolicy,
} from "../../domain/value-objects/lockout-policy.js";
import type { CredentialsUnitOfWork } from "../ports/credentials-unit-of-work.js";
import type { PasswordHasher } from "../ports/password-hasher.js";

export interface AuthenticateWithPasswordCommand {
  readonly email: string;
  readonly password: string;
}

export interface AuthenticateWithPasswordResult {
  readonly user: User;
  /** True when the stored hash was upgraded during this login. Diagnostic only. */
  readonly rehashed: boolean;
}

export type AuthenticateWithPasswordError = AuthenticationError | AccountLockedError;

/**
 * Decoy hashes, one per hasher, used to burn time when there is no real
 * credential to check.
 *
 * Each is a genuine argon2 hash of a password nobody has, produced by the
 * same hasher that would have verified the real one — so it costs what the
 * real comparison costs. The string is never compared against anything
 * meaningful; only its *cost* matters.
 *
 * Keyed by hasher rather than held in a single module-level variable,
 * because a decoy made at one set of cost parameters is worthless for
 * disguising a hasher configured with different ones. That is not
 * hypothetical: the test suite deliberately runs a cheap hasher alongside a
 * production-parameter one, and a shared decoy would silently make the
 * timing assertions measure the wrong hasher.
 *
 * A `WeakMap` so a discarded hasher does not pin its decoy in memory, and
 * computed lazily so a process that never sees a failed login never pays for
 * one. The first failure is therefore slower than later ones — a hash plus a
 * verify rather than a verify. That is a once-per-process artefact, in the
 * opposite direction from the leak being closed, and not worth pre-warming
 * for.
 */
const decoyHashes = new WeakMap<PasswordHasher, Promise<string>>();

function decoy(hasher: PasswordHasher): Promise<string> {
  let pending = decoyHashes.get(hasher);
  if (pending === undefined) {
    pending = hasher.hash("verixa-timing-decoy");
    decoyHashes.set(hasher, pending);
  }
  return pending;
}

/**
 * What the authentication transaction concluded.
 *
 * A discriminated union rather than `Credential | undefined`, because
 * "locked" and "failed" have to be distinguishable to the caller (they are
 * different operational signals) while being indistinguishable to the client.
 * Collapsing them here would make the second property impossible to state and
 * the first impossible to measure.
 */
type Outcome =
  | { readonly kind: "ok"; readonly user: User; readonly credential: Credential }
  | { readonly kind: "failed" }
  | { readonly kind: "locked" };

/**
 * Account statuses whose owner may still prove who they are.
 *
 * A set rather than a `!== "suspended"` check so adding a status to
 * `UserStatus` fails closed: a new state is not authenticable until someone
 * decides it is. The inverse test would silently admit it.
 */
const CAN_AUTHENTICATE = new Set<UserStatus>(["pending", "active"]);

/**
 * Verifies an email and password, and says as little as possible when it
 * fails.
 *
 * ## Why every failure returns the same error
 *
 * There are three ways this can fail — no account with that email, an account
 * with no password credential, and a wrong password — and a caller cannot
 * tell them apart. That is the entire security design of this use case, not a
 * missed opportunity to be helpful.
 *
 * A login that distinguishes "no such user" from "wrong password" is an
 * account enumeration oracle (OWASP calls this out directly, and it appears
 * in the WSTG as WSTG-IDNT-04). An attacker posts a list of addresses, reads
 * which ones come back "wrong password", and now has a list of accounts that
 * exist. Two things follow. The expensive part of credential stuffing —
 * finding valid usernames — becomes free, so the remaining work is only
 * guessing passwords for accounts already known to be real. And the
 * membership list leaks: for a verification and compliance product, "who has
 * an account here" is often more sensitive than any individual password.
 *
 * The cost of hiding it is a genuinely worse error message, and that trade is
 * made deliberately. A user who mistypes their address is told the same thing
 * as one who mistypes their password. Password reset is where that gets
 * resolved, and it has the same property for the same reason (Issue 069).
 *
 * ## Why timing is handled explicitly
 *
 * Returning an identical message is not enough on its own. If a missing user
 * returns immediately while a wrong password takes ~60ms to verify, the
 * response *time* answers the question the message refuses to. That is a
 * real, practical side channel over a local network, and it is invisible in
 * every test that only asserts on the response body.
 *
 * So when there is no credential to check, this verifies the candidate
 * password against {@link decoy} instead — a real argon2 hash, at the same
 * parameters — and discards the result. Both paths do one hash verification.
 *
 * What this deliberately does *not* claim: constant time. Argon2 verification
 * is not constant-time with respect to the stored parameters, a database miss
 * is faster than a hit, and the JIT, the allocator and the network add noise
 * that dwarfs both. Closing the gap to "indistinguishable under statistical
 * attack" would need a fixed response deadline, which is a heavier mechanism
 * than this threat warrants. The claim here is narrower and honest: the
 * obvious order-of-magnitude difference is gone. See Issue 067's lockout work
 * and Phase 15's rate limiting, which attack the same problem from the side
 * that actually scales.
 *
 * See `docs/security/authentication-flows.md`.
 */
export class AuthenticateWithPassword {
  constructor(
    private readonly unitOfWork: CredentialsUnitOfWork,
    private readonly passwordHasher: PasswordHasher,
    private readonly rateLimiter: RateLimiter,
    private readonly lockoutPolicy: LockoutPolicy = DEFAULT_LOCKOUT_POLICY,
  ) {}

  async execute(
    command: AuthenticateWithPasswordCommand,
  ): Promise<Result<AuthenticateWithPasswordResult, AuthenticateWithPasswordError>> {
    // 1. Check rate limit BEFORE any other logic
    const rateLimitKey: RateLimitKey = {
      action: "login",
      identifier: command.email,
    };

    const limitResult = await this.rateLimiter.check(rateLimitKey);
    if (!limitResult.allowed) {
      throw new Error(
        `Rate limit exceeded for ${rateLimitKey.action} on ${rateLimitKey.identifier}. ` +
          `Resets at ${new Date(limitResult.resetAt).toISOString()}`,
      );
    }

    // A malformed address is not a validation error here, unlike everywhere
    // else in the codebase. `Email.create` rejecting "not-an-email" is a
    // perfectly good 400 during registration; on a login endpoint it tells an
    // attacker their input never reached the credential lookup, which is one
    // more bit than a failed login should give away. It fails like any other
    // bad login.
    const emailResult = Email.create(command.email);
    if (Result.isErr(emailResult)) {
      await this.burnTime(command.password);
      return Result.err(new AuthenticationError());
    }

    const now = new Date();

    const outcome = await this.unitOfWork.run<Outcome>(async (repositories) => {
      // Excludes soft-deleted users, which is the behaviour wanted here: a
      // deleted account must not be loggable into, and `findByEmail` already
      // encodes that. Worth noting rather than assuming, because the choice
      // between this and `findByIdIncludingDeleted` is a security decision
      // wearing the clothes of a method name.
      const user = await repositories.users.findByEmail(emailResult.value);
      if (user === undefined) {
        await this.burnTime(command.password);
        return { kind: "failed" };
      }

      const credential = await repositories.credentials.findByUserId(user.id);
      if (credential === undefined) {
        // An SSO-only or passkey-only account. Legitimately has no password,
        // and must not reveal that by failing faster or differently than a
        // wrong password would.
        await this.burnTime(command.password);
        return { kind: "failed" };
      }

      // Checked before the password is verified, which is the one place this
      // use case deliberately short-circuits ahead of the hash. That is the
      // entire point of lockout — refusing to spend the CPU is most of the
      // defence against credential stuffing, and verifying first would hand
      // an attacker the expensive operation they were being denied.
      //
      // It does mean the fast path is now observably faster, so the decoy
      // runs here too. Without it a locked account would return in
      // microseconds while every other failure paid for an argon2
      // verification, and the response time would announce "this address has
      // an account, and someone has been attacking it".
      if (credential.isLockedAt(now)) {
        await this.burnTime(command.password);
        // The counter keeps climbing during a lock rather than freezing at
        // the threshold. That is what makes the backoff exponential: each
        // further attempt earns a longer next lock, so a sustained campaign
        // collapses into impracticality within a few rounds.
        await repositories.credentials.save(
          credential.recordFailedAttempt(this.lockoutPolicy, now),
        );
        return { kind: "locked" };
      }

      const matches = await this.passwordHasher.verify(command.password, credential.passwordHash);
      if (!matches) {
        await repositories.credentials.save(
          credential.recordFailedAttempt(this.lockoutPolicy, now),
        );
        // Record failed login attempt for rate limiting
        await this.rateLimiter.recordFailure(rateLimitKey);
        return { kind: "failed" };
      }

      // Only *after* the password is confirmed. Checking account status
      // first would leak: "this account is suspended" answers "does this
      // account exist" to someone who never knew the password. A suspended
      // account fails exactly like a wrong password does.
      //
      // The cost is that a suspended user gets an unhelpful message, which is
      // the same trade made above and resolved the same way — out of band,
      // through a channel that has already proven who they are.
      //
      // `pending` is allowed through, and that is the deliberate part.
      // Registration leaves a user pending until their email is verified
      // (Issue 068), so refusing pending here would mean nobody who just
      // registered could ever sign in. Email verification gates what an
      // account may *do*, not whether its owner may prove who they are;
      // conflating the two is how a product ends up unable to tell an
      // unverified user why they are stuck. Authorization for unverified
      // accounts belongs to Phase 07's RBAC work, which can see the status.
      //
      // No failure is recorded here: the password was correct, so counting it
      // against the lockout threshold would punish the account holder for the
      // administrative state of their own account.
      if (!CAN_AUTHENTICATE.has(user.status)) {
        return { kind: "failed" };
      }

      // Clearing the counter is what makes the threshold count *consecutive*
      // failures. Without it, five mistyped passwords spread over a year —
      // each followed by a successful login — would lock the account on the
      // fifth, which is indistinguishable from an attack only if you never
      // look at the gaps between them.
      //
      // Returns the same instance when there is nothing to clear, so the
      // common case does not write a row on every login.
      const cleared = credential.recordSuccessfulAttempt(now);
      if (cleared !== credential) {
        await repositories.credentials.save(cleared);
      }

      return { kind: "ok", user, credential: cleared };
    });

    if (outcome.kind === "locked") {
      return Result.err(new AccountLockedError());
    }
    if (outcome.kind === "failed") {
      return Result.err(new AuthenticationError());
    }
    const verified = { user: outcome.user, credential: outcome.credential };

    // Reset rate limit counter on successful authentication
    await this.rateLimiter.reset(rateLimitKey);

    // Deliberately outside the transaction above.
    //
    // Re-hashing is the slowest thing this use case does and needs no
    // transactional relationship to the read that preceded it — the same
    // reasoning `RegisterUserWithPassword` applies to its hash. Holding a
    // connection open across it would be waste.
    //
    // It also has to be outside for correctness, which is the less obvious
    // half. The upgrade is best-effort and its failure must not fail a login
    // that already succeeded, but a `try`/`catch` *inside* the transaction
    // cannot deliver that: a failed write has already marked the transaction
    // for rollback, so swallowing the error only defers the failure to the
    // commit, where nothing is left to catch it. Out here, a failed upgrade
    // is genuinely inert.
    const rehashed = await this.upgradeHashIfStale(verified.credential, command.password);

    return Result.ok({ user: verified.user, rehashed });
  }

  /**
   * Verifies the candidate against a decoy hash and throws the answer away.
   *
   * The work is the point. See the class comment on timing.
   */
  private async burnTime(candidate: string): Promise<void> {
    await this.passwordHasher.verify(candidate, await decoy(this.passwordHasher));
  }

  /**
   * Re-hashes at current parameters when the stored hash was made with weaker
   * ones.
   *
   * A successful login is the only moment the plaintext exists, so it is the
   * only moment an existing hash can be upgraded — the alternative is a mass
   * password reset every time cost parameters rise. Passwords migrate
   * gradually as people sign in, and nobody is asked to do anything.
   *
   * A failure here must not fail the login. The user supplied correct
   * credentials; refusing them because a background optimisation did not work
   * would convert a cosmetic problem into an outage. The upgrade is retried
   * on their next login anyway.
   */
  private async upgradeHashIfStale(credential: Credential, plaintext: string): Promise<boolean> {
    if (!this.passwordHasher.needsRehash(credential.passwordHash)) {
      return false;
    }

    try {
      const upgraded = credential.withPasswordHash(await this.passwordHasher.hash(plaintext));
      await this.unitOfWork.run(async (repositories) => {
        await repositories.credentials.save(upgraded);
      });
      return true;
    } catch {
      return false;
    }
  }
}
