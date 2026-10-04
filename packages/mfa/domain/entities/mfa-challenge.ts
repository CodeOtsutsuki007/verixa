import { createId, type Id } from "@verixa/shared-kernel";

export type MfaChallengeId = Id<"MfaChallengeId">;
export type MfaChallengeUserId = Id<"UserId">;

export interface MfaChallengeProps {
  readonly id: MfaChallengeId;
  readonly userId: MfaChallengeUserId;
  readonly expiresAt: Date;
  readonly consumedAt?: Date;
  readonly createdAt: Date;
}

export class MfaChallenge {
  private constructor(private readonly props: MfaChallengeProps) {}

  static create(params: {
    userId: MfaChallengeUserId;
    expiresAt?: Date;
    now?: Date;
  }): MfaChallenge {
    const now = params.now ?? new Date();
    const expiresAt = params.expiresAt ?? new Date(now.getTime() + 5 * 60 * 1000); // 5 minutes default
    return new MfaChallenge({
      id: createId<"MfaChallengeId">(),
      userId: params.userId,
      expiresAt,
      createdAt: now,
    });
  }

  static reconstitute(props: MfaChallengeProps): MfaChallenge {
    return new MfaChallenge(props);
  }

  get id(): MfaChallengeId {
    return this.props.id;
  }

  get userId(): MfaChallengeUserId {
    return this.props.userId;
  }

  get expiresAt(): Date {
    return this.props.expiresAt;
  }

  get consumedAt(): Date | undefined {
    return this.props.consumedAt;
  }

  get createdAt(): Date {
    return this.props.createdAt;
  }

  isExpired(now: Date = new Date()): boolean {
    return now.getTime() >= this.props.expiresAt.getTime();
  }

  get isConsumed(): boolean {
    return this.props.consumedAt !== undefined;
  }

  isValid(now: Date = new Date()): boolean {
    return !this.isConsumed && !this.isExpired(now);
  }

  consume(now: Date = new Date()): MfaChallenge {
    if (this.isConsumed) {
      throw new Error("MfaChallenge has already been consumed.");
    }
    if (this.isExpired(now)) {
      throw new Error("MfaChallenge has expired.");
    }
    return new MfaChallenge({
      ...this.props,
      consumedAt: now,
    });
  }
}
