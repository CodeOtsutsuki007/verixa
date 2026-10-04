import type { MfaMethodType } from "../entities/mfa-method.js";

/** Whether a subject must present a second factor. */
export type MfaEnforcementLevel = "required" | "optional" | "disabled";

/**
 * A scope-specific override. Every field is optional so an organization (or a
 * role) can tighten exactly one of the two knobs — level or permitted methods —
 * without restating the other.
 */
export interface MfaEnforcementOverride {
  readonly level?: MfaEnforcementLevel;
  readonly allowedMethods?: readonly MfaMethodType[];
}

/**
 * The inputs to a single resolution.
 *
 * Scopes are ordered from least to most specific and each scope may set either
 * the enforcement level, the permitted method types, or both. `enrolledMethods`
 * is the set the user actually has today, which is what makes the
 * "required but nothing enrolled" case detectable.
 */
export interface MfaEnforcementPolicyInput {
  readonly globalDefault?: MfaEnforcementLevel;
  readonly allowedMethods?: readonly MfaMethodType[];
  readonly organization?: MfaEnforcementOverride;
  readonly role?: MfaEnforcementOverride;
  readonly user?: MfaEnforcementOverride;
  readonly enrolledMethods?: readonly MfaMethodType[];
}

export interface MfaEnforcementDecision {
  /** The resolved level after precedence is applied. */
  readonly level: MfaEnforcementLevel;
  /** The method types a user is permitted to enroll or use. */
  readonly allowedMethods: readonly MfaMethodType[];
  /** The user's enrolled methods that are permitted by the resolved policy. */
  readonly enrolledAllowedMethods: readonly MfaMethodType[];
  /**
   * True when MFA is `required` but the user has no permitted method enrolled,
   * so enrollment must happen before the session can be issued.
   */
  readonly requiresEnrollment: boolean;
  /** True when the user cannot proceed until they enroll (Issue 116 behaviour). */
  readonly blocked: boolean;
}

const ALL_METHODS: readonly MfaMethodType[] = ["totp", "webauthn", "backup_codes"];

/**
 * Resolves whether MFA is required, optional, or disabled for a subject, and
 * which method types are permitted.
 *
 * ## Precedence
 *
 * The most specific scope that sets a value wins, per knob:
 *
 * ```
 * user  >  role  >  organization  >  global default
 * ```
 *
 * This is deliberately resolved independently for the *level* and for the
 * *allowed methods*. A bank can mandate MFA organization-wide while letting a
 * service account's role relax only the permitted method set, and an individual
 * user's exemption does not accidentally widen everyone else's.
 *
 * *Alternative considered:* a single merged "policy object" where the first
 * scope that defines anything supplies the whole policy. Rejected because it
 * makes "inherit the org's method list but keep the stricter level" impossible
 * without duplicating the org's list at every scope — the bug that shows up as
 * an org adding WebAuthn only for users who never customized their settings.
 *
 * ## Required but unenrolled
 *
 * A `required` decision with no permitted method enrolled yields
 * `requiresEnrollment` (and `blocked`). The login flow uses this to force
 * enrollment before issuing a session rather than failing the login — see
 * Issue 116 and docs/security/mfa-design.md.
 */
export class MfaEnforcementPolicy {
  public static resolve(input: MfaEnforcementPolicyInput): MfaEnforcementDecision {
    const level =
      input.user?.level ??
      input.role?.level ??
      input.organization?.level ??
      input.globalDefault ??
      "optional";

    const allowedMethods =
      input.user?.allowedMethods ??
      input.role?.allowedMethods ??
      input.organization?.allowedMethods ??
      input.allowedMethods ??
      ALL_METHODS;

    const enrolled = input.enrolledMethods ?? [];
    const enrolledAllowedMethods = enrolled.filter((method) => allowedMethods.includes(method));

    const requiresEnrollment = level === "required" && enrolledAllowedMethods.length === 0;

    return {
      level,
      allowedMethods: [...allowedMethods],
      enrolledAllowedMethods,
      requiresEnrollment,
      blocked: requiresEnrollment,
    };
  }
}
