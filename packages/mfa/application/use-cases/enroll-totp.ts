import { Result, type Id, asId } from "@verixa/shared-kernel";

import { MfaMethod } from "../../domain/entities/mfa-method.js";
import type { TotpAlgorithm } from "../../domain/services/totp-algorithm.js";
import type { MfaMethodRepository } from "../ports/mfa-method-repository.js";

export interface EnrollTotpCommand {
  readonly userId: string;
  readonly accountName: string;
}

export interface EnrollTotpResult {
  readonly methodId: string;
  readonly secret: string;
  readonly provisioningUri: string;
}

/**
 * Initiates TOTP enrollment for a user.
 *
 * Generates a new TOTP secret, stores a pending MfaMethod, and returns the
 * secret and provisioning URI exactly once. The method cannot be used for
 * authentication until it is confirmed (Issue 104).
 */
export class EnrollTotp {
  constructor(
    private readonly mfaMethodRepository: MfaMethodRepository,
    private readonly totpAlgorithm: TotpAlgorithm,
  ) {}

  async execute(command: EnrollTotpCommand): Promise<Result<EnrollTotpResult, Error>> {
    const userId = asId<"UserId">(command.userId);

    // Generate the CSPRNG secret and URI for the user
    const totpSecret = await this.totpAlgorithm.generateSecret(command.accountName);

    // Create the method in a 'pending' state
    const method = MfaMethod.createPendingTotp(userId, totpSecret);

    // Persist it
    await this.mfaMethodRepository.save(method);

    // Return the secret exactly once. It is never retrievable again in plaintext
    // by the application once it leaves this scope, as the repository will
    // persist it using encryption-at-rest (Issue 107).
    return Result.ok({
      methodId: method.id,
      secret: totpSecret.value,
      provisioningUri: totpSecret.provisioningUri,
    });
  }
}
