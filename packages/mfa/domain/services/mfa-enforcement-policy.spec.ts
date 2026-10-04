import { describe, expect, it } from "vitest";

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
