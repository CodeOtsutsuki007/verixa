import { describe, expect, it } from "vitest";

import {
  MfaEnforcementPolicy,
  type MfaEnforcementContext,
} from "./mfa-enforcement-policy.js";

describe("MfaEnforcementPolicy.resolve", () => {
  describe("defaults", () => {
    it("returns optional with all method types when nothing is configured", () => {
      const policy = MfaEnforcementPolicy.resolve();
      expect(policy.level).toBe("optional");
      expect(policy.allowedMethods).toEqual(
        expect.arrayContaining(["totp", "webauthn", "backup-codes"]),
      );
      expect(policy.allowedMethods).toHaveLength(3);
    });

    it("returns optional with all method types when only an empty context is given", () => {
      const policy = MfaEnforcementPolicy.resolve({});
      expect(policy.level).toBe("optional");
    });
  });

  describe("global config", () => {
    it("applies the global level when no narrower scope is set", () => {
      const policy = MfaEnforcementPolicy.resolve({
        globalConfig: { level: "required" },
      });
      expect(policy.level).toBe("required");
    });

    it("restricts allowed methods from global config", () => {
      const policy = MfaEnforcementPolicy.resolve({
        globalConfig: { allowedMethods: ["totp"] },
      });
      expect(policy.allowedMethods).toEqual(["totp"]);
    });
  });

  describe("org config overrides global", () => {
    it("uses org level over global level", () => {
      const policy = MfaEnforcementPolicy.resolve({
        globalConfig: { level: "optional" },
        orgConfig: { level: "required" },
      });
      expect(policy.level).toBe("required");
    });

    it("uses org allowedMethods over global allowedMethods", () => {
      const policy = MfaEnforcementPolicy.resolve({
        globalConfig: { allowedMethods: ["totp", "webauthn"] },
        orgConfig: { allowedMethods: ["totp"] },
      });
      expect(policy.allowedMethods).toEqual(["totp"]);
    });

    it("inherits global allowedMethods when org does not restrict", () => {
      const policy = MfaEnforcementPolicy.resolve({
        globalConfig: { allowedMethods: ["totp"] },
        orgConfig: { level: "required" },
      });
      expect(policy.allowedMethods).toEqual(["totp"]);
      expect(policy.level).toBe("required");
    });
  });

  describe("role config overrides org and global", () => {
    it("takes the strictest level across all role configs", () => {
      const policy = MfaEnforcementPolicy.resolve({
        globalConfig: { level: "optional" },
        orgConfig: { level: "optional" },
        roleConfigs: [{ level: "optional" }, { level: "required" }],
      });
      expect(policy.level).toBe("required");
    });

    it("required beats optional beats disabled at the role tier", () => {
      const ctx: MfaEnforcementContext = {
        roleConfigs: [
          { level: "disabled" },
          { level: "optional" },
          { level: "required" },
        ],
      };
      expect(MfaEnforcementPolicy.resolve(ctx).level).toBe("required");
    });

    it("optional beats disabled when required is absent", () => {
      const ctx: MfaEnforcementContext = {
        roleConfigs: [{ level: "disabled" }, { level: "optional" }],
      };
      expect(MfaEnforcementPolicy.resolve(ctx).level).toBe("optional");
    });

    it("intersects allowedMethods across roles so the strictest set wins", () => {
      const policy = MfaEnforcementPolicy.resolve({
        roleConfigs: [
          { allowedMethods: ["totp", "webauthn"] },
          { allowedMethods: ["totp", "backup-codes"] },
        ],
      });
      // Only "totp" is in both sets
      expect(policy.allowedMethods).toEqual(["totp"]);
    });

    it("ignores role configs that do not set allowedMethods", () => {
      const policy = MfaEnforcementPolicy.resolve({
        roleConfigs: [
          { level: "required" },
          { allowedMethods: ["totp"] },
        ],
      });
      expect(policy.allowedMethods).toEqual(["totp"]);
    });

    it("falls through to org allowedMethods when no role restricts methods", () => {
      const policy = MfaEnforcementPolicy.resolve({
        orgConfig: { allowedMethods: ["webauthn"] },
        roleConfigs: [{ level: "required" }],
      });
      expect(policy.allowedMethods).toEqual(["webauthn"]);
    });
  });

  describe("user config overrides everything", () => {
    it("user level wins over role, org, and global", () => {
      const policy = MfaEnforcementPolicy.resolve({
        globalConfig: { level: "optional" },
        orgConfig: { level: "required" },
        roleConfigs: [{ level: "required" }],
        userConfig: { level: "disabled" },
      });
      expect(policy.level).toBe("disabled");
    });

    it("user allowedMethods wins over org and role", () => {
      const policy = MfaEnforcementPolicy.resolve({
        orgConfig: { allowedMethods: ["totp", "webauthn"] },
        roleConfigs: [{ allowedMethods: ["totp"] }],
        userConfig: { allowedMethods: ["webauthn"] },
      });
      expect(policy.allowedMethods).toEqual(["webauthn"]);
    });

    it("user can independently override level without touching allowedMethods", () => {
      const policy = MfaEnforcementPolicy.resolve({
        orgConfig: { level: "optional", allowedMethods: ["totp"] },
        userConfig: { level: "required" },
      });
      expect(policy.level).toBe("required");
      expect(policy.allowedMethods).toEqual(["totp"]);
    });
  });

  describe("normalisation edge cases", () => {
    it("a disabled level yields an empty allowedMethods regardless of config", () => {
      const policy = MfaEnforcementPolicy.resolve({
        userConfig: { level: "disabled", allowedMethods: ["totp"] },
      });
      expect(policy.level).toBe("disabled");
      expect(policy.allowedMethods).toHaveLength(0);
    });

    it("an empty allowedMethods with a required level resolves to disabled", () => {
      const policy = MfaEnforcementPolicy.resolve({
        userConfig: { level: "required", allowedMethods: [] },
      });
      expect(policy.level).toBe("disabled");
      expect(policy.allowedMethods).toHaveLength(0);
    });

    it("returns disabled level with empty methods when roles fully restrict each other", () => {
      const policy = MfaEnforcementPolicy.resolve({
        roleConfigs: [
          { allowedMethods: ["totp"] },
          { allowedMethods: ["webauthn"] },
        ],
      });
      // Intersection of {totp} and {webauthn} is empty → normalised to disabled
      expect(policy.level).toBe("disabled");
      expect(policy.allowedMethods).toHaveLength(0);
    });
  });
});

describe("MfaEnforcementPolicy.isEnrollmentRequired", () => {
  it("returns false when level is optional", () => {
    const policy = { level: "optional" as const, allowedMethods: ["totp"] as const };
    expect(MfaEnforcementPolicy.isEnrollmentRequired(policy, [])).toBe(false);
  });

  it("returns false when level is disabled", () => {
    const policy = { level: "disabled" as const, allowedMethods: [] as const };
    expect(MfaEnforcementPolicy.isEnrollmentRequired(policy, [])).toBe(false);
  });

  it("returns true when required and user has no enrolled methods", () => {
    const policy = { level: "required" as const, allowedMethods: ["totp"] as const };
    expect(MfaEnforcementPolicy.isEnrollmentRequired(policy, [])).toBe(true);
  });

  it("returns false when required and user has an allowed enrolled method", () => {
    const policy = { level: "required" as const, allowedMethods: ["totp"] as const };
    expect(MfaEnforcementPolicy.isEnrollmentRequired(policy, ["totp"])).toBe(false);
  });

  it("returns true when required but enrolled methods are not in the allowed set", () => {
    const policy = { level: "required" as const, allowedMethods: ["webauthn"] as const };
    expect(MfaEnforcementPolicy.isEnrollmentRequired(policy, ["totp"])).toBe(true);
  });

  it("returns false when user has backup-codes but policy allows them", () => {
    const policy = {
      level: "required" as const,
      allowedMethods: ["totp", "backup-codes"] as const,
    };
    expect(MfaEnforcementPolicy.isEnrollmentRequired(policy, ["backup-codes"])).toBe(false);
  });
});
import { MfaEnforcementPolicy } from "./mfa-enforcement-policy.js";

describe("MfaEnforcementPolicy", () => {
  describe("level precedence", () => {
    it("defaults to optional when nothing is configured", () => {
      expect(MfaEnforcementPolicy.resolve({}).level).toBe("optional");
    });

    it("falls back to the global default", () => {
      expect(MfaEnforcementPolicy.resolve({ globalDefault: "required" }).level).toBe("required");
    });

    it("lets the organization override the global default", () => {
      const decision = MfaEnforcementPolicy.resolve({
        globalDefault: "optional",
        organization: { level: "required" },
      });
      expect(decision.level).toBe("required");
    });

    it("lets a role override the organization", () => {
      const decision = MfaEnforcementPolicy.resolve({
        organization: { level: "optional" },
        role: { level: "required" },
      });
      expect(decision.level).toBe("required");
    });

    it("lets a user override the role", () => {
      const decision = MfaEnforcementPolicy.resolve({
        role: { level: "required" },
        user: { level: "disabled" },
      });
      expect(decision.level).toBe("disabled");
    });

    it("applies user > role > organization > global in one pass", () => {
      const decision = MfaEnforcementPolicy.resolve({
        globalDefault: "disabled",
        organization: { level: "optional" },
        role: { level: "required" },
        user: { level: "disabled" },
      });
      expect(decision.level).toBe("disabled");
    });
  });

  describe("allowed methods precedence", () => {
    it("defaults to every method type", () => {
      expect(MfaEnforcementPolicy.resolve({}).allowedMethods).toEqual([
        "totp",
        "webauthn",
        "backup_codes",
      ]);
    });

    it("narrows methods at the organization scope", () => {
      const decision = MfaEnforcementPolicy.resolve({
        allowedMethods: ["totp", "webauthn", "backup_codes"],
        organization: { allowedMethods: ["webauthn"] },
      });
      expect(decision.allowedMethods).toEqual(["webauthn"]);
    });

    it("resolves the method list independently of the level", () => {
      const decision = MfaEnforcementPolicy.resolve({
        organization: { level: "required" },
        user: { allowedMethods: ["totp"] },
      });
      // The org's level still applies even though the user set only methods.
      expect(decision.level).toBe("required");
      expect(decision.allowedMethods).toEqual(["totp"]);
    });
  });

  describe("required but unenrolled", () => {
    it("requires enrollment when required with no methods", () => {
      const decision = MfaEnforcementPolicy.resolve({
        organization: { level: "required" },
        enrolledMethods: [],
      });
      expect(decision.requiresEnrollment).toBe(true);
      expect(decision.blocked).toBe(true);
    });

    it("is satisfied when a permitted method is enrolled", () => {
      const decision = MfaEnforcementPolicy.resolve({
        organization: { level: "required", allowedMethods: ["totp"] },
        enrolledMethods: ["totp"],
      });
      expect(decision.requiresEnrollment).toBe(false);
      expect(decision.blocked).toBe(false);
    });

    it("still requires enrollment when only disallowed methods are enrolled", () => {
      const decision = MfaEnforcementPolicy.resolve({
        organization: { level: "required", allowedMethods: ["webauthn"] },
        enrolledMethods: ["totp", "backup_codes"],
      });
      expect(decision.enrolledAllowedMethods).toEqual([]);
      expect(decision.requiresEnrollment).toBe(true);
    });

    it("does not require enrollment when MFA is only optional", () => {
      const decision = MfaEnforcementPolicy.resolve({
        organization: { level: "optional" },
        enrolledMethods: [],
      });
      expect(decision.requiresEnrollment).toBe(false);
    });

    it("is deterministic for the same inputs", () => {
      const input = {
        globalDefault: "optional" as const,
        role: { level: "required" as const },
        enrolledMethods: [] as const,
      };
      expect(MfaEnforcementPolicy.resolve(input)).toEqual(MfaEnforcementPolicy.resolve(input));
    });
  });
});
