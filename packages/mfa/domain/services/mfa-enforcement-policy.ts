import type { MfaMethodTypeValue } from "../value-objects/mfa-method-type.js";

/**
 * The three stances an org or user can be in with respect to MFA.
 *
 * - `required`: the user must complete an MFA challenge before a session is
 *   issued. If they have no enrolled methods, the login flow must gate on
 *   enrollment before completing.
 * - `optional`: the user may choose to enroll but is not forced to. A
 *   session is issued regardless.
 * - `disabled`: MFA is not permitted at all — useful for service accounts or
 *   orgs that manage authentication externally.
 */
export type MfaEnforcementLevel = "required" | "optional" | "disabled";

/**
 * Configuration that drives policy resolution at one scope (global, org,
 * role, or user). Every field is optional — absent fields inherit from the
 * next-broader scope.
 *
 * Why a plain object rather than a class? Policy configs travel across the
 * config/env boundary and are compared by value; a plain object is simpler
 * to serialise, merge, and test.
 */
export interface MfaEnforcementConfig {
  /** Whether MFA is required, optional, or disabled at this scope. */
  readonly level?: MfaEnforcementLevel;
  /**
   * Which MFA method types are permitted. Absent means "all types allowed".
   * An empty array means the same as `disabled` — no method can satisfy the
   * policy — and the service normalises that to `disabled`.
   */
  readonly allowedMethods?: ReadonlyArray<MfaMethodTypeValue>;
}

/**
 * The fully-resolved policy for one user in one org.
 *
 * Produced by `MfaEnforcementPolicy.resolve()` — always a concrete answer,
 * never a partial config.
 */
export interface ResolvedMfaPolicy {
  readonly level: MfaEnforcementLevel;
  /** Methods the user is permitted to enroll or use. Never empty when level
   *  is "required" or "optional"; always empty when level is "disabled". */
  readonly allowedMethods: ReadonlyArray<MfaMethodTypeValue>;
}

const ALL_METHOD_TYPES: ReadonlyArray<MfaMethodTypeValue> = [
  "totp",
  "webauthn",
  "backup-codes",
];

/**
 * Context fed into the resolver. Every field is optional because a policy
 * check might occur before all of it is known (e.g. before role assignments
 * have been loaded).
 */
export interface MfaEnforcementContext {
  /** Per-user override — highest precedence. */
  readonly userConfig?: MfaEnforcementConfig;
  /**
   * Per-role configs, one per role the user holds in the current org.
   * When multiple roles are present, the strictest level wins (required >
   * optional > disabled), matching the principle of least surprise: if any
   * role an admin assigns requires MFA, it takes effect.
   */
  readonly roleConfigs?: ReadonlyArray<MfaEnforcementConfig>;
  /** Per-org override — lower precedence than user and role. */
  readonly orgConfig?: MfaEnforcementConfig;
  /** Deployment-wide default — lowest precedence. */
  readonly globalConfig?: MfaEnforcementConfig;
}

/**
 * Resolves the effective MFA enforcement policy for a user given layered
 * configuration.
 *
 * ## Precedence (highest → lowest)
 *
 *   user > role (strictest of all roles) > org > global default
 *
 * The first scope that explicitly sets `level` wins for `level`; the first
 * scope that explicitly sets `allowedMethods` wins for `allowedMethods`.
 * The two fields are resolved independently so an org can mandate TOTP-only
 * without also overriding the enforcement level.
 *
 * ## Why "strictest role wins" for the role tier
 *
 * The alternative — "any role can relax enforcement" — is insecure: an admin
 * could attach a permissive role to themselves to bypass the org's MFA
 * mandate. Strictest-wins means adding a role never reduces security; it can
 * only add constraints.
 *
 * ## Why `required` with no enrolled methods blocks login
 *
 * Accepting a `required` level but then letting unenrolled users through
 * would make the policy decorative. The service returns the resolved policy;
 * the login flow (Issue 116) consults it and gates on enrollment when the
 * user has no active methods.
 */
export class MfaEnforcementPolicy {
  private static readonly LEVEL_RANK: Record<MfaEnforcementLevel, number> = {
    required: 2,
    optional: 1,
    disabled: 0,
  };

  /**
   * Resolves the effective policy from the supplied context.
   *
   * Always returns a fully-specified `ResolvedMfaPolicy` — callers do not
   * need to handle absent fields.
   */
  static resolve(context: MfaEnforcementContext = {}): ResolvedMfaPolicy {
    const { userConfig, roleConfigs = [], orgConfig, globalConfig } = context;

    // --- Resolve level ---
    // Walk scopes in precedence order; take the first explicit value.
    // For the role tier, take the strictest level across all roles.
    let level: MfaEnforcementLevel | undefined;

    if (userConfig?.level !== undefined) {
      level = userConfig.level;
    } else if (roleConfigs.length > 0) {
      const roleLevel = MfaEnforcementPolicy.strictestRoleLevel(roleConfigs);
      if (roleLevel !== undefined) {
        level = roleLevel;
      }
    }

    if (level === undefined && orgConfig?.level !== undefined) {
      level = orgConfig.level;
    }

    if (level === undefined && globalConfig?.level !== undefined) {
      level = globalConfig.level;
    }

    // Fall back to "optional" — opt-in by default, never mandatory unless
    // someone explicitly configured it. Changing the implicit default to
    // "required" would break every deployment that has not thought about MFA.
    level ??= "optional";

    // --- Resolve allowedMethods ---
    // Same precedence order, but independent of level.
    let allowedMethods: ReadonlyArray<MfaMethodTypeValue> | undefined;

    if (userConfig?.allowedMethods !== undefined) {
      allowedMethods = userConfig.allowedMethods;
    } else if (roleConfigs.length > 0) {
      const roleAllowed = MfaEnforcementPolicy.intersectRoleAllowedMethods(roleConfigs);
      if (roleAllowed !== undefined) {
        allowedMethods = roleAllowed;
      }
    }

    if (allowedMethods === undefined && orgConfig?.allowedMethods !== undefined) {
      allowedMethods = orgConfig.allowedMethods;
    }

    if (allowedMethods === undefined && globalConfig?.allowedMethods !== undefined) {
      allowedMethods = globalConfig.allowedMethods;
    }

    // Default to all types when no scope restricts.
    allowedMethods ??= ALL_METHOD_TYPES;

    // Normalise: if disabled, no methods are usable regardless.
    if (level === "disabled") {
      return { level, allowedMethods: [] };
    }

    // An empty allowedMethods with a non-disabled level is effectively
    // disabled — no method can satisfy the requirement.
    if (allowedMethods.length === 0) {
      return { level: "disabled", allowedMethods: [] };
    }

    return { level, allowedMethods };
  }

  /**
   * Returns the strictest level found across all role configs, or `undefined`
   * if no role config specifies a level.
   *
   * "Strictest" is defined by LEVEL_RANK: required > optional > disabled.
   * This means a role that sets "required" wins over one that sets "optional".
   */
  private static strictestRoleLevel(
    roleConfigs: ReadonlyArray<MfaEnforcementConfig>,
  ): MfaEnforcementLevel | undefined {
    let best: MfaEnforcementLevel | undefined;
    let bestRank = -1;

    for (const config of roleConfigs) {
      if (config.level === undefined) continue;
      const rank = MfaEnforcementPolicy.LEVEL_RANK[config.level];
      if (rank > bestRank) {
        best = config.level;
        bestRank = rank;
      }
    }

    return best;
  }

  /**
   * Intersects allowed-method sets across all role configs.
   *
   * Returns `undefined` if no role config specifies allowedMethods (so the
   * next-broader scope can contribute). When at least one role restricts
   * methods, returns the intersection of all such restrictions — a method
   * must be permitted by every restricting role to remain allowed.
   *
   * Why intersection rather than union? Union would let a permissive role
   * undo the restrictions of a stricter one, which breaks the "adding a role
   * never reduces security" guarantee.
   */
  private static intersectRoleAllowedMethods(
    roleConfigs: ReadonlyArray<MfaEnforcementConfig>,
  ): ReadonlyArray<MfaMethodTypeValue> | undefined {
    const restrictingRoles = roleConfigs.filter(
      (c) => c.allowedMethods !== undefined,
    );
    if (restrictingRoles.length === 0) return undefined;

    // Start from the full set; narrow it with each restriction.
    let result: Set<MfaMethodTypeValue> = new Set(
      restrictingRoles[0]!.allowedMethods as MfaMethodTypeValue[],
    );

    for (let i = 1; i < restrictingRoles.length; i++) {
      const allowed = new Set(restrictingRoles[i]!.allowedMethods as MfaMethodTypeValue[]);
      result = new Set([...result].filter((m) => allowed.has(m)));
    }

    return [...result];
  }

  /**
   * Returns `true` when the policy requires MFA but the user has no active
   * enrolled methods — the login flow must gate on enrollment.
   *
   * This is a pure predicate; it does not throw or redirect. The caller
   * (Issue 116 step-up/enrollment gate) decides what to do.
   */
  static isEnrollmentRequired(
    policy: ResolvedMfaPolicy,
    enrolledMethodTypes: ReadonlyArray<MfaMethodTypeValue>,
  ): boolean {
    if (policy.level !== "required") return false;
    return enrolledMethodTypes.every((t) => !policy.allowedMethods.includes(t));
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
