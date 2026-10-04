import { Result, type AppError } from "@verixa/shared-kernel";
import type { IssueSession, IssueSessionCommand, IssueSessionResult } from "packages/sessions/application/use-cases/issue-session.js";
import type { MfaChallenge, MfaChallengeId } from "../../domain/entities/mfa-challenge.js";

export interface MfaChallengeRepository {
  findById(id: MfaChallengeId): Promise<MfaChallenge | null>;
  save(challenge: MfaChallenge): Promise<void>;
}

export interface ConsumeMfaChallengeCommand {
  readonly challengeId: string;
  readonly issueSessionCommand: IssueSessionCommand;
  readonly now?: Date;
}

export class ConsumeMfaChallenge {
  constructor(
    private readonly challengeRepository: MfaChallengeRepository,
    private readonly issueSessionUseCase: IssueSession,
  ) {}

  async execute(
    command: ConsumeMfaChallengeCommand,
  ):
    | Promise<Result<IssueSessionResult, AppError | "CHALLENGE_NOT_FOUND" | "CHALLENGE_EXPIRED" | "CHALLENGE_ALREADY_CONSUMED">>
    | any {
    const now = command.now ?? new Date();
    const challenge = await this.challengeRepository.findById(command.challengeId as any);
    if (!challenge) {
      return Result.err("CHALLENGE_NOT_FOUND");
    }
    if (challenge.isExpired(now)) {
      return Result.err("CHALLENGE_EXPIRED");
    }
    if (challenge.isConsumed) {
      return Result.err("CHALLENGE_ALREADY_CONSUMED");
    }

    const consumed = challenge.consume(now);
    await this.challengeRepository.save(consumed);

    return await this.issueSessionUseCase.execute(command.issueSessionCommand);
  }
}
