import { ValidationError } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { SessionExpiryPolicy } from "./session-expiry-policy.js";

describe("SessionExpiryPolicy", () => {
  describe("sliding mode", () => {
    it("creates a sliding policy with a valid positive duration", () => {
      const policy = SessionExpiryPolicy.sliding(3600000); // 1 hour

      expect(policy.mode).toBe("sliding");
      expect(policy.durationMs).toBe(3600000);
    });

    it("rejects non-positive durations", () => {
      expect(() => SessionExpiryPolicy.sliding(0)).toThrow(ValidationError);
      expect(() => SessionExpiryPolicy.sliding(-1000)).toThrow(ValidationError);
      expect(() => SessionExpiryPolicy.sliding(NaN)).toThrow(ValidationError);
    });

    it("rejects non-finite numbers", () => {
      expect(() => SessionExpiryPolicy.sliding(Infinity)).toThrow(ValidationError);
      expect(() => SessionExpiryPolicy.sliding(-Infinity)).toThrow(ValidationError);
    });

    it("extends expiresAt by durationMs when computeNewExpiresAt is called", () => {
      const policy = SessionExpiryPolicy.sliding(3600000); // 1 hour
      const previousExpiresAt = new Date("2024-01-15T12:00:00Z");
      const touchedAt = new Date("2024-01-15T11:30:00Z");

      const newExpiresAt = policy.computeNewExpiresAt(previousExpiresAt, touchedAt);

      // Should be touchedAt + durationMs = 11:30 + 1 hour = 12:30
      expect(newExpiresAt.getTime()).toBe(touchedAt.getTime() + 3600000);
      // Not equal to previous expiry
      expect(newExpiresAt.getTime()).not.toBe(previousExpiresAt.getTime());
    });

    it("extends expiresAt even when called well before previous expiry", () => {
      const policy = SessionExpiryPolicy.sliding(3600000);
      const previousExpiresAt = new Date("2024-01-15T12:00:00Z");
      const touchedAt = new Date("2024-01-15T10:00:00Z"); // 2 hours before previous expiry

      const newExpiresAt = policy.computeNewExpiresAt(previousExpiresAt, touchedAt);

      // Should be 10:00 + 1 hour = 11:00, which is still before previous expiry
      expect(newExpiresAt.getTime()).toBe(touchedAt.getTime() + 3600000);
      expect(newExpiresAt.getTime()).toBeLessThan(previousExpiresAt.getTime());
    });
  });

  describe("absolute mode", () => {
    it("creates an absolute policy with a valid positive duration", () => {
      const policy = SessionExpiryPolicy.absolute(86400000); // 1 day

      expect(policy.mode).toBe("absolute");
      expect(policy.durationMs).toBe(86400000);
    });

    it("rejects non-positive durations", () => {
      expect(() => SessionExpiryPolicy.absolute(0)).toThrow(ValidationError);
      expect(() => SessionExpiryPolicy.absolute(-1000)).toThrow(ValidationError);
      expect(() => SessionExpiryPolicy.absolute(NaN)).toThrow(ValidationError);
    });

    it("rejects non-finite numbers", () => {
      expect(() => SessionExpiryPolicy.absolute(Infinity)).toThrow(ValidationError);
      expect(() => SessionExpiryPolicy.absolute(-Infinity)).toThrow(ValidationError);
    });

    it("leaves expiresAt unchanged when computeNewExpiresAt is called", () => {
      const policy = SessionExpiryPolicy.absolute(86400000);
      const previousExpiresAt = new Date("2024-01-15T12:00:00Z");
      const touchedAt = new Date("2024-01-15T11:30:00Z");

      const newExpiresAt = policy.computeNewExpiresAt(previousExpiresAt, touchedAt);

      // Should be identical to previous expiry
      expect(newExpiresAt.getTime()).toBe(previousExpiresAt.getTime());
      expect(newExpiresAt).toEqual(previousExpiresAt);
    });

    it("ignores activity and never extends expiry", () => {
      const policy = SessionExpiryPolicy.absolute(3600000);
      const previousExpiresAt = new Date("2024-01-15T12:00:00Z");

      // Call touch at various times
      const touch1 = policy.computeNewExpiresAt(previousExpiresAt, new Date("2024-01-15T10:00:00Z"));
      const touch2 = policy.computeNewExpiresAt(previousExpiresAt, new Date("2024-01-15T11:00:00Z"));
      const touch3 = policy.computeNewExpiresAt(previousExpiresAt, new Date("2024-01-15T11:59:00Z"));

      // All should be unchanged
      expect(touch1).toEqual(previousExpiresAt);
      expect(touch2).toEqual(previousExpiresAt);
      expect(touch3).toEqual(previousExpiresAt);
    });
  });

  describe("equals", () => {
    it("considers two sliding policies with the same duration equal", () => {
      const policy1 = SessionExpiryPolicy.sliding(3600000);
      const policy2 = SessionExpiryPolicy.sliding(3600000);

      expect(policy1.equals(policy2)).toBe(true);
    });

    it("considers two absolute policies with the same duration equal", () => {
      const policy1 = SessionExpiryPolicy.absolute(86400000);
      const policy2 = SessionExpiryPolicy.absolute(86400000);

      expect(policy1.equals(policy2)).toBe(true);
    });

    it("considers two policies with different durations not equal", () => {
      const policy1 = SessionExpiryPolicy.sliding(3600000);
      const policy2 = SessionExpiryPolicy.sliding(7200000);

      expect(policy1.equals(policy2)).toBe(false);
    });

    it("considers a sliding and absolute policy with the same duration not equal", () => {
      const sliding = SessionExpiryPolicy.sliding(3600000);
      const absolute = SessionExpiryPolicy.absolute(3600000);

      expect(sliding.equals(absolute)).toBe(false);
    });

    it("is not reflexively equal to different instances even with same values", () => {
      const policy1 = SessionExpiryPolicy.sliding(3600000);
      const policy2 = SessionExpiryPolicy.sliding(3600000);

      // Different object references
      expect(policy1).not.toBe(policy2);
      // But equal by value
      expect(policy1.equals(policy2)).toBe(true);
    });
  });
});
