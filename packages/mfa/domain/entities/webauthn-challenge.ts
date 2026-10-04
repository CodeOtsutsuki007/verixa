import { createId, type Id } from "@verixa/shared-kernel";

export type WebAuthnChallengeId = Id<"WebAuthnChallengeId">;
export type WebAuthnCeremonyType = "registration" | "authentication";

export interface WebAuthnChallengeProps {
  readonly id: WebAuthnChallengeId;
  readonly userId: Id<"UserId">;
  readonly challenge: string;
  readonly ceremonyType: WebAuthnCeremonyType;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly used: boolean;
}

export class WebAuthnChallenge {
  private constructor(public readonly props: WebAuthnChallengeProps) {}

  get id(): WebAuthnChallengeId {
    return this.props.id;
  }

  get userId(): Id<"UserId"> {
    return this.props.userId;
  }

  get challenge(): string {
    return this.props.challenge;
  }

  get ceremonyType(): WebAuthnCeremonyType {
    return this.props.ceremonyType;
  }

  get createdAt(): Date {
    return this.props.createdAt;
  }

  get expiresAt(): Date {
    return this.props.expiresAt;
  }

  get used(): boolean {
    return this.props.used;
  }

  static create(props: {
    readonly userId: Id<"UserId">;
    readonly challenge: string;
    readonly ceremonyType: WebAuthnCeremonyType;
    readonly ttlMs?: number | undefined;
    readonly now?: Date | undefined;
  }): WebAuthnChallenge {
    const now = props.now ?? new Date();
    const ttlMs = props.ttlMs ?? 5 * 60 * 1000;
    return new WebAuthnChallenge({
      id: createId<"WebAuthnChallengeId">(),
      userId: props.userId,
      challenge: props.challenge,
      ceremonyType: props.ceremonyType,
      createdAt: now,
      expiresAt: new Date(now.getTime() + ttlMs),
      used: false,
    });
  }

  static reconstitute(props: WebAuthnChallengeProps): WebAuthnChallenge {
    return new WebAuthnChallenge(props);
  }

  isExpired(now: Date = new Date()): boolean {
    return now.getTime() > this.props.expiresAt.getTime();
  }

  consume(): WebAuthnChallenge {
    if (this.props.used) {
      throw new Error("Challenge has already been consumed.");
    }
    return new WebAuthnChallenge({
      ...this.props,
      used: true,
    });
  }
}
