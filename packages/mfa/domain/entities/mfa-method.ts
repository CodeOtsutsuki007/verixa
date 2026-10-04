import { createId, type Id } from "@verixa/shared-kernel";
import { createId, type Id, Result, ValidationError } from "@verixa/shared-kernel";

import type { MfaMethodType } from "../value-objects/mfa-method-type.js";

import type { MfaMethodType } from "../value-objects/mfa-method-type.js";

export type MfaMethodId = Id<"MfaMethodId">;
export type MfaMethodStatus = "pending" | "active" | "disabled";

export interface MfaMethodProps {
  readonly id: MfaMethodId;
  readonly userId: Id<"UserId">;
  readonly type: MfaMethodType;
  readonly status: MfaMethodStatus;
  readonly createdAt: Date;
  readonly lastUsedAt?: Date | undefined;
  readonly failedAttempts: number;
  readonly lockedUntil?: Date | undefined;
}

export class MfaMethod {
  private constructor(public readonly props: MfaMethodProps) {}

  get id(): MfaMethodId {
    return this.props.id;
  }

  get userId(): Id<"UserId"> {
    return this.props.userId;
  }

  get type(): MfaMethodType {
    return this.props.type;
  }

  get status(): MfaMethodStatus {
    return this.props.status;
  }

  get createdAt(): Date {
    return this.props.createdAt;
  }

  get lastUsedAt(): Date | undefined {
    return this.props.lastUsedAt;
  }

  get failedAttempts(): number {
    return this.props.failedAttempts;
  }

  get lockedUntil(): Date | undefined {
    return this.props.lockedUntil;
  }

  static createPending(
    userId: Id<"UserId">,
    type: MfaMethodType,
export type MfaMethodId = Id<"MfaMethodId">;
export type MfaMethodStatus = "pending" | "active" | "disabled";

export interface MfaMethodProps {
  readonly id: MfaMethodId;
  readonly userId: Id<"UserId">;
export type UserId = Id<"UserId">;
export type MfaMethodType = "totp" | "webauthn" | "backup_codes";
export type MfaMethodStatus = "pending" | "active" | "disabled";

/** Minimal shape of a generated TOTP secret; structural so a plain object is assignable. */
export interface TotpSecretLike {
  readonly value: string;
}

export interface MfaMethodProps {
  readonly id: MfaMethodId;
  readonly userId: UserId;
  readonly type: MfaMethodType;
  readonly status: MfaMethodStatus;
  readonly secret: string | null;
  readonly lastUsedAt: Date | null;
  readonly createdAt: Date;
  readonly lastUsedAt?: Date | undefined;
  readonly failedAttempts: number;
  readonly lockedUntil?: Date | undefined;
}

export class MfaMethod {
  private constructor(public readonly props: MfaMethodProps) {}

  get id(): MfaMethodId {
    return this.props.id;
  }

  get userId(): Id<"UserId"> {
    return this.props.userId;
  }

  get type(): MfaMethodType {
    return this.props.type;
  }

  get status(): MfaMethodStatus {
    return this.props.status;
  }

  get createdAt(): Date {
    return this.props.createdAt;
  }

  get lastUsedAt(): Date | undefined {
    return this.props.lastUsedAt;
  }

  get failedAttempts(): number {
    return this.props.failedAttempts;
  }

  get lockedUntil(): Date | undefined {
    return this.props.lockedUntil;
  }

  static createPending(
    userId: Id<"UserId">,
    type: MfaMethodType,
    now: Date = new Date(),
  ): MfaMethod {
    return new MfaMethod({
      id: createId<"MfaMethodId">(),
      userId,
      type,
      status: "pending",
      createdAt: now,
      failedAttempts: 0,
      lockedUntil: undefined,
      lastUsedAt: undefined,
    });
  }

  static createActive(
    userId: Id<"UserId">,
    type: MfaMethodType,
    now: Date = new Date(),
  ): MfaMethod {
    return new MfaMethod({
      id: createId<"MfaMethodId">(),
      userId,
      type,
      status: "active",
      createdAt: now,
      failedAttempts: 0,
      lockedUntil: undefined,
      lastUsedAt: undefined,
    });
  }

  static reconstitute(props: MfaMethodProps): MfaMethod {
    return new MfaMethod(props);
  }

  activate(): MfaMethod {
    if (this.props.status !== "pending") {
      throw new Error("Only pending methods can be activated.");
    }
    return new MfaMethod({
      ...this.props,
      status: "active",
      failedAttempts: 0,
      lockedUntil: undefined,
    });
  }

  disable(): MfaMethod {
    return new MfaMethod({
      ...this.props,
      status: "disabled",
    });
  }

  recordUse(now: Date = new Date()): MfaMethod {
    if (this.props.status !== "active") {
      throw new Error("Only active methods can satisfy an MFA challenge.");
    }
    return new MfaMethod({
      ...this.props,
      lastUsedAt: now,
      failedAttempts: 0,
      lockedUntil: undefined,
    });
  }

  recordFailedAttempt(now: Date = new Date()): MfaMethod {
    const attempts = this.props.failedAttempts + 1;
    const lockDurationMs = attempts >= 5 ? 60 * 1000 * Math.pow(2, attempts - 5) : 0;
    const lockedUntil =
      lockDurationMs > 0
        ? new Date(now.getTime() + Math.min(lockDurationMs, 60 * 60 * 1000))
        : undefined;

    return new MfaMethod({
      ...this.props,
      failedAttempts: attempts,
      lockedUntil,
    });
  }

  isLockedAt(now: Date = new Date()): boolean {
    if (!this.props.lockedUntil) return false;
    return now.getTime() < this.props.lockedUntil.getTime();
  }
}
  readonly updatedAt: Date;
  readonly failedAttempts: number;
  readonly lockedUntil: Date | null;
  readonly lastUsedStep: number | null;
}

/** Consecutive failed challenges tolerated before an exponential lockout begins. */
const LOCKOUT_THRESHOLD = 5;
/** Floor for the exponential backoff, and its ceiling (see `recordFailedAttempt`). */
const LOCKOUT_BASE_MS = 60 * 1_000;
const MAX_LOCKOUT_MS = 60 * 60 * 1_000;

/**
 * A second factor enrolled by a user.
 *
 * This aggregate was reconciled from three independently-developed branches
 * (TOTP enrollment, MFA persistence, and a domain value-object attempt) that
 * each defined their own version of this class. The union of their behaviour is
 * preserved here: the mutable, well-behaved transitions the TOTP use cases
 * need (rate limiting and replay protection) and the load/create/updateSecret
 * helpers the persistence adapter needs.
 *
 * Transitions mutate the instance and return `this` so callers may either chain
 * (`method.activate().recordUse(step)`) or ignore the return value — the two
 * call styles the surviving call sites use.
 */
export class MfaMethod {
  private props: MfaMethodProps;

  private constructor(props: MfaMethodProps) {
    this.props = props;
  }

  public get id(): MfaMethodId {
    return this.props.id;
  }
  public get userId(): UserId {
    return this.props.userId;
  }
  public get type(): MfaMethodType {
    return this.props.type;
  }
  public get status(): MfaMethodStatus {
    return this.props.status;
  }
  public get secret(): string | null {
    return this.props.secret;
  }
  public get lastUsedAt(): Date | null {
    return this.props.lastUsedAt;
  }
  public get createdAt(): Date {
    return this.props.createdAt;
  }
  public get updatedAt(): Date {
    return this.props.updatedAt;
  }
  public get failedAttempts(): number {
    return this.props.failedAttempts;
  }
  public get lockedUntil(): Date | null {
    return this.props.lockedUntil;
  }
  public get lastUsedStep(): number | null {
    return this.props.lastUsedStep;
  }

  /** Enrolls a new method in the `pending` state. */
  public static create(
    userId: UserId,
    type: MfaMethodType,
    secret: string | null = null,
    now: Date = new Date(),
  ): MfaMethod {
    return new MfaMethod({
      id: createId<"MfaMethodId">(),
      userId,
      type,
      status: "pending",
      createdAt: now,
      failedAttempts: 0,
      lockedUntil: undefined,
      lastUsedAt: undefined,
    });
  }

  static createActive(
    userId: Id<"UserId">,
    type: MfaMethodType,
    now: Date = new Date(),
  ): MfaMethod {
    return new MfaMethod({
      id: createId<"MfaMethodId">(),
      userId,
      type,
      status: "active",
      createdAt: now,
      failedAttempts: 0,
      lockedUntil: undefined,
      lastUsedAt: undefined,
    });
  }

  static reconstitute(props: MfaMethodProps): MfaMethod {
    return new MfaMethod(props);
  }

  activate(): MfaMethod {
    if (this.props.status !== "pending") {
      throw new Error("Only pending methods can be activated.");
    }
    return new MfaMethod({
      ...this.props,
      status: "active",
      failedAttempts: 0,
      lockedUntil: undefined,
    });
  }

  disable(): MfaMethod {
    return new MfaMethod({
      ...this.props,
      status: "disabled",
    });
  }

  recordUse(now: Date = new Date()): MfaMethod {
    if (this.props.status !== "active") {
      throw new Error("Only active methods can satisfy an MFA challenge.");
    }
    return new MfaMethod({
      ...this.props,
      lastUsedAt: now,
      failedAttempts: 0,
      lockedUntil: undefined,
    });
  }

  recordFailedAttempt(now: Date = new Date()): MfaMethod {
    const attempts = this.props.failedAttempts + 1;
    const lockDurationMs = attempts >= 5 ? 60 * 1000 * Math.pow(2, attempts - 5) : 0;
    const lockedUntil =
      lockDurationMs > 0
        ? new Date(now.getTime() + Math.min(lockDurationMs, 60 * 60 * 1000))
        : undefined;

    return new MfaMethod({
      ...this.props,
      failedAttempts: attempts,
      lockedUntil,
    });
  }

  isLockedAt(now: Date = new Date()): boolean {
    if (!this.props.lockedUntil) return false;
    return now.getTime() < this.props.lockedUntil.getTime();
      secret,
      lastUsedAt: null,
      createdAt: now,
      updatedAt: now,
      failedAttempts: 0,
      lockedUntil: null,
      lastUsedStep: null,
    });
  }

  /**
   * Enrolls a pending TOTP method, storing the base32 secret as a plain string.
   * Only the value is persisted; the provisioning URI is derived on demand.
   */
  public static createPendingTotp(
    userId: UserId,
    secret: TotpSecretLike,
    now: Date = new Date(),
  ): MfaMethod {
    return MfaMethod.create(userId, "totp", secret.value, now);
  }

  /** Rehydrates a method from persistence. */
  public static load(props: MfaMethodProps): MfaMethod {
    return new MfaMethod(props);
  }

  /** Moves a `pending` or `disabled` method to `active`, clearing any lockout. */
  public activate(now: Date = new Date()): this {
    if (this.props.status === "active") {
      throw new Error("Method is already active.");
    }
    this.props = {
      ...this.props,
      status: "active",
      failedAttempts: 0,
      lockedUntil: null,
      updatedAt: now,
    };
    return this;
  }

  /** Disables an enrolled method. A disabled method cannot satisfy a challenge. */
  disable(now: Date = new Date()): this {
    if (this.props.status === "disabled") {
      throw new Error("Method is already disabled.");
    }
    this.props = { ...this.props, status: "disabled", updatedAt: now };
    return this;
  }

  /** Replaces the stored secret (used when regenerating backup codes). */
  updateSecret(secret: string, now: Date = new Date()): this {
    this.props = { ...this.props, secret, updatedAt: now };
    return this;
  }

  /** Clears the stored secret without deleting the method (Issue 118 recovery). */
  clearSecret(now: Date = new Date()): this {
    this.props = { ...this.props, secret: null, updatedAt: now };
    return this;
  }

  /** Whether the method is currently rate-limited at `now`. */
  isLockedAt(now: Date = new Date()): boolean {
    return this.props.lockedUntil !== null && now < this.props.lockedUntil;
  }

  /**
   * Records a failed challenge. Once {@link LOCKOUT_THRESHOLD} consecutive
   * failures accumulate, the method is locked for an exponentially increasing
   * duration (capped at one hour) — the 6-digit code space is small enough that
   * unthrottled guessing within a 30-second window is trivial.
   */
  recordFailedAttempt(now: Date = new Date()): this {
    const attempts = this.props.failedAttempts + 1;
    const exponent = attempts - LOCKOUT_THRESHOLD;
    const lockedUntil =
      exponent >= 0
        ? new Date(now.getTime() + Math.min(LOCKOUT_BASE_MS * 2 ** exponent, MAX_LOCKOUT_MS))
        : null;

    this.props = { ...this.props, failedAttempts: attempts, lockedUntil, updatedAt: now };
    return this;
  }

  /**
   * Records a successful challenge at a particular TOTP time step.
   *
   * Rejects replays: clock-drift tolerance widens the window in which a single
   * code is valid, so a code whose step is not strictly greater than the last
   * consumed step is refused. Resets the failure counter on success.
   */
  recordUse(matchedStep: number, now: Date = new Date()): this {
    if (this.props.status !== "active") {
      throw new Error("Only active methods can be used for verification.");
    }
    if (this.props.lastUsedStep !== null && matchedStep <= this.props.lastUsedStep) {
      throw new Error("Replay detected: step has already been consumed.");
    }
    this.props = {
      ...this.props,
      lastUsedAt: now,
      failedAttempts: 0,
      lockedUntil: null,
      lastUsedStep: matchedStep,
      updatedAt: now,
    };
    return this;
  }
}
