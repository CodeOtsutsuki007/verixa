import { Result, ValidationError } from "@verixa/shared-kernel";
import type { VerificationRequest } from "../../domain/entities/verification-request.js";
import type { ProviderCheckResult, VerificationProvider } from "../ports/verification-provider.js";
import type { VerificationRequestRepository } from "../ports/verification-request-repository.js";

export interface RunAutomatedCheckCommand {
  readonly requestId: string;
}

export interface RunAutomatedCheckResult {
  readonly request: VerificationRequest;
  readonly providerResult: ProviderCheckResult;
}

export type RunAutomatedCheckError = ValidationError;

/**
 * Invokes the configured VerificationProvider for a submitted request's evidence,
 * records the ProviderCheckResult against the request, and transitions status
 * to in_review regardless of outcome (pass, fail, inconclusive, or error/timeout).
 */
export class RunAutomatedCheck {
  constructor(
    private readonly requestRepository: VerificationRequestRepository,
    private readonly verificationProvider: VerificationProvider,
  ) {}

  async execute(
    command: RunAutomatedCheckCommand,
  ): Promise<Result<RunAutomatedCheckResult, RunAutomatedCheckError>> {
    const request = await this.requestRepository.findById(command.requestId);
    if (!request) {
      return Result.err(
        new ValidationError(`Verification request with id "${command.requestId}" not found.`),
      );
    }

    let providerResult: ProviderCheckResult;
    try {
      providerResult = await this.verificationProvider.check(request);
    } catch (error) {
      providerResult = {
        outcome: "inconclusive",
        score: 0,
        details: {
          error: error instanceof Error ? error.message : "Unknown provider error",
        },
      };
    }

    request.recordProviderResult(providerResult);
    const transitionResult = request.transitionTo("in_review");
    if (Result.isErr(transitionResult)) {
      return transitionResult;
    }

    await this.requestRepository.save(request);

    return Result.ok({ request, providerResult });
  }
}
