import { createId } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { MfaMethod } from "./mfa-method.js";

describe("MfaMethod", () => {
  const userId = createId<"UserId">();

  describe("create", () => {
    it("starts a method in the pending state", () => {
      const method = MfaMethod.create(userId, "totp", "SECRET");
      expect(method.userId).toBe(userId);
      expect(method.type).toBe("totp");
      expect(method.status).toBe("pending");
      expect(method.secret).toBe("SECRET");
      expect(method.createdAt).toBeInstanceOf(Date);
      expect(method.lastUsedAt).toBeNull();
      expect(method.failedAttempts).toBe(0);
    });

    it("creates a pending TOTP method from a generated secret", () => {
      const method = MfaMethod.createPendingTotp(userId, { value: "BASE32" });
      expect(method.type).toBe("totp");
      expect(method.status).toBe("pending");
      expect(method.secret).toBe("BASE32");
    });
  });

  describe("activate", () => {
    it("transitions a pending method to active", () => {
      const method = MfaMethod.create(userId, "totp").activate();
      expect(method.status).toBe("active");
    });

    it("can reactivate a disabled method", () => {
      const method = MfaMethod.create(userId, "totp").activate().disable().activate();
      expect(method.status).toBe("active");
    });

    it("rejects activating an already-active method", () => {
      const method = MfaMethod.create(userId, "totp").activate();
      expect(() => method.activate()).toThrow(/already active/);
    });
  });

  describe("disable", () => {
    it("transitions an active method to disabled", () => {
      const method = MfaMethod.create(userId, "totp").activate().disable();
      expect(method.status).toBe("disabled");
    });

    it("transitions a pending method to disabled", () => {
      const method = MfaMethod.create(userId, "totp").disable();
      expect(method.status).toBe("disabled");
    });

    it("rejects disabling an already-disabled method", () => {
      const method = MfaMethod.create(userId, "totp").disable();
      expect(() => method.disable()).toThrow(/already disabled/);
    });
  });

  describe("recordUse", () => {
    it("records the matched step and last-used time for an active method", () => {
      const before = Date.now();
      const method = MfaMethod.create(userId, "totp").activate().recordUse(1000);

      expect(method.lastUsedStep).toBe(1000);
      expect(method.lastUsedAt).not.toBeNull();
      expect(method.lastUsedAt!.getTime()).toBeGreaterThanOrEqual(before);
    });

    it("refuses to use a pending method", () => {
      const method = MfaMethod.create(userId, "totp");
      expect(() => method.recordUse(1000)).toThrow(/Only active methods/);
    });

    it("refuses a replayed step", () => {
      const method = MfaMethod.create(userId, "totp").activate().recordUse(1000);
      expect(() => method.recordUse(1000)).toThrow(/Replay detected/);
    });
  });

  describe("rate limiting", () => {
    it("locks after five consecutive failures", () => {
      const now = new Date();
      const method = MfaMethod.create(userId, "totp");
      for (let i = 0; i < 5; i += 1) {
        method.recordFailedAttempt(now);
      }
      expect(method.failedAttempts).toBe(5);
      expect(method.isLockedAt(now)).toBe(true);
    });

    it("remains unlocked below the threshold", () => {
      const now = new Date();
      const method = MfaMethod.create(userId, "totp");
      method.recordFailedAttempt(now).recordFailedAttempt(now);
      expect(method.isLockedAt(now)).toBe(false);
    });

    it("clears the lock on a successful use", () => {
      const now = new Date();
      const method = MfaMethod.create(userId, "totp").activate();
      for (let i = 0; i < 5; i += 1) {
        method.recordFailedAttempt(now);
      }
      method.recordUse(1000, now);
      expect(method.isLockedAt(now)).toBe(false);
      expect(method.failedAttempts).toBe(0);
    });
  });

  describe("updateSecret", () => {
    it("replaces the stored secret", () => {
      const method = MfaMethod.create(userId, "backup_codes", "old").updateSecret("new");
      expect(method.secret).toBe("new");
    });
  });
});
