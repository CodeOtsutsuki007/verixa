import { DisplayName, Email, PersonName, User } from "@verixa/identity";
import { ConflictError, NotFoundError, Result, ValidationError } from "@verixa/shared-kernel";
import type { RateLimiter, RateLimitKey } from "@verixa/shared-kernel";

import { Credential } from "../../domain/entities/credential.js";
import { type PasswordPolicy, RawPassword } from "../../domain/value-objects/raw-password.js";
import type { CredentialsUnitOfWork } from "../ports/credentials-unit-of-work.js";
import type { PasswordHasher } from "../ports/password-hasher.js";

export interface RegisterUserWithPasswordCommand {
  readonly email: string;
  readonly displayName: string;
  readonly password: string;
  readonly givenName?: string;
  readonly familyName?: string;
}

export interface RegisterUserWithPasswordResult {
  readonly user: User;
  readonly credential: Credential;
}

export type RegisterUserWithPasswordError = ValidationError | ConflictError | NotFoundError;

/**
 * Registers a user and their password together, atomically.
 *
 * The first use case spanning two bounded contexts, and a worked example of
 * doing that without either context knowing the other's internals: everything
 * from identity arrives through `@verixa/identity`'s public API, and identity
 * has no idea this package exists.
 *
 * Rate limiting is consulted at the start via the {@link RateLimiter} port,
 * and reset on successful registration to prevent registration abuse.
 *
 * See `docs/guides/use-cases.md`.
 */
export class RegisterUserWithPassword {
  constructor(
    private readonly unitOfWork: CredentialsUnitOfWork,
    private readonly passwordHasher: PasswordHasher,
    private readonly rateLimiter: RateLimiter,
    private readonly passwordPolicy?: PasswordPolicy,
  ) {}

  async execute(
    command: RegisterUserWithPasswordCommand,
  ): Promise<Result<RegisterUserWithPasswordResult, RegisterUserWithPasswordError>> {
    // 1. Check rate limit BEFORE any other logic
    const rateLimitKey: RateLimitKey = {
      action: "register",
      identifier: command.email,
    };

    const limitResult = await this.rateLimiter.check(rateLimitKey);
    if (!limitResult.allowed) {
      throw new Error(
        `Rate limit exceeded for ${rateLimitKey.action} on ${rateLimitKey.identifier}. ` +
          `Resets at ${new Date(limitResult.resetAt).toISOString()}`,
      );
    }

    // Every input is validated before the transaction opens, and before the
    // password is hashed. Two reasons, in order of importance:
    //
    // 1. Hashing is deliberately expensive (~50-100ms). Doing it for input
    //    that was never going to be accepted hands an attacker a cheap way to
    //    burn server CPU: post rubbish with a huge password field and make
    //    the server pay for it every time.
    // 2. A transaction held open across a slow hash is a connection held out
    //    of the pool for no reason.
    const emailResult = Email.create(command.email);
    if (Result.isErr(emailResult)) {
      return emailResult;
    }

    const displayNameResult = DisplayName.create(command.displayName);
    if (Result.isErr(displayNameResult)) {
      return displayNameResult;
    }

    const passwordResult = RawPassword.create(command.password, this.passwordPolicy);
    if (Result.isErr(passwordResult)) {
      return passwordResult;
    }

    let personName: PersonName | undefined;
    if (command.givenName !== undefined) {
      const personNameResult = PersonName.create(command.givenName, command.familyName);
      if (Result.isErr(personNameResult)) {
        return personNameResult;
      }
      personName = personNameResult.value;
    }

    // Hashed outside the transaction, for the same reason: this is the slowest
    // thing the request does, and it needs no database.
    const passwordHash = await this.passwordHasher.hash(passwordResult.value.reveal());

    const result = await this.unitOfWork.run(async (repositories) => {
      // Re-checked inside the transaction rather than before it. Checking
      // outside would leave a window where two concurrent registrations for
      // the same address both see "available" and both proceed — the second
      // then failing on the unique index as an unhandled constraint error
      // rather than a clean conflict. The index is still the real guarantee;
      // this turns the common case into a typed error.
      const alreadyRegistered = await repositories.users.existsByEmail(emailResult.value);
      if (alreadyRegistered) {
        return Result.err(
          new ConflictError(`A user with email "${emailResult.value.value}" already exists.`),
        );
      }

      const user = User.register({
        email: emailResult.value,
        displayName: displayNameResult.value,
        personName,
      });

      const credential = Credential.create({ userId: user.id, passwordHash });

      await repositories.users.save(user);
      await repositories.credentials.save(credential);

      return Result.ok({ user, credential });
    });

    // Reset rate limit counter on successful registration
    if (Result.isOk(result)) {
      await this.rateLimiter.reset(rateLimitKey);
    }

    return result;
  }
}