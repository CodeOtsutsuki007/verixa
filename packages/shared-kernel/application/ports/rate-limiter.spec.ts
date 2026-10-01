import { describe, expect, it } from "vitest";

import { NoopRateLimiter } from "../../infrastructure/adapters/noop-rate-limiter.js";
import {
  RateLimitExceededError,
  type RateLimitKey,
  type RateLimiter,
  type RateLimitResult,
} from "./rate-limiter.js";

/**
 * Test double: SpyRateLimiter that records all calls for verification.
 */
class SpyRateLimiter implements RateLimiter {
  checkCalls: RateLimitKey[] = [];
  failureCalls: RateLimitKey[] = [];
  resetCalls: RateLimitKey[] = [];
  shouldAllow = true;

  // eslint-disable-next-line @typescript-eslint/require-await
  async check(key: RateLimitKey) {
    this.checkCalls.push(key);
    return this.shouldAllow
      ? { allowed: true, remaining: 10, resetAt: Date.now() + 60000, limit: 10 }
      : { allowed: false, remaining: 0, resetAt: Date.now() + 60000, limit: 10 };
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async recordFailure(key: RateLimitKey) {
    this.failureCalls.push(key);
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async reset(key: RateLimitKey) {
    this.resetCalls.push(key);
  }
}

describe("RateLimiter port", () => {
  describe("RateLimitExceededError", () => {
    it("includes resetAt and limit in the error", () => {
      const key: RateLimitKey = { action: "login", identifier: "user@example.com" };
      const resetAt = Date.now() + 60000;
      const limit = 10;

      const error = new RateLimitExceededError(key, resetAt, limit);

      expect(error.name).toBe("RateLimitExceededError");
      expect(error.key).toEqual(key);
      expect(error.resetAt).toBe(resetAt);
      expect(error.limit).toBe(limit);
      expect(error.message).toContain("Rate limit exceeded");
      expect(error.message).toContain("login");
      expect(error.message).toContain("user@example.com");
    });

    it("includes ISO timestamp in error message", () => {
      const key: RateLimitKey = { action: "register", identifier: "user@example.com" };
      const resetAt = new Date("2026-09-25T12:00:00Z").getTime();

      const error = new RateLimitExceededError(key, resetAt, 5);

      expect(error.message).toContain("2026-09-25");
    });
  });

  describe("SpyRateLimiter test double", () => {
    it("records all check calls", async () => {
      const spy = new SpyRateLimiter();

      const key1: RateLimitKey = { action: "login", identifier: "alice@example.com" };
      const key2: RateLimitKey = { action: "register", identifier: "bob@example.com" };

      await spy.check(key1);
      await spy.check(key2);

      expect(spy.checkCalls).toHaveLength(2);
      expect(spy.checkCalls[0]).toEqual(key1);
      expect(spy.checkCalls[1]).toEqual(key2);
    });

    it("records all failure calls", async () => {
      const spy = new SpyRateLimiter();

      const key: RateLimitKey = { action: "login", identifier: "user@example.com" };

      await spy.recordFailure(key);
      await spy.recordFailure(key);

      expect(spy.failureCalls).toHaveLength(2);
    });

    it("records all reset calls", async () => {
      const spy = new SpyRateLimiter();

      const key: RateLimitKey = { action: "login", identifier: "user@example.com" };

      await spy.reset(key);
      await spy.reset(key);

      expect(spy.resetCalls).toHaveLength(2);
    });

    it("allows requests when shouldAllow is true", async () => {
      const spy = new SpyRateLimiter();
      spy.shouldAllow = true;

      const result = await spy.check({ action: "login", identifier: "user@example.com" });

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBeGreaterThan(0);
    });

    it("denies requests when shouldAllow is false", async () => {
      const spy = new SpyRateLimiter();
      spy.shouldAllow = false;

      const result = await spy.check({ action: "login", identifier: "user@example.com" });

      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });
  });

  describe("NoopRateLimiter", () => {
    it("always allows requests", async () => {
      const noop = new NoopRateLimiter();

      const result = await noop.check({ action: "login", identifier: "user@example.com" });

      expect(result.allowed).toBe(true);
    });

    it("returns reasonable metrics", async () => {
      const noop = new NoopRateLimiter();

      const result = await noop.check({ action: "login", identifier: "user@example.com" });

      expect(result.remaining).toBeGreaterThan(0);
      expect(result.limit).toBeGreaterThan(result.remaining);
      expect(result.resetAt).toBeGreaterThan(Date.now());
    });

    it("does not throw on recordFailure", async () => {
      const noop = new NoopRateLimiter();

      await expect(
        noop.recordFailure({ action: "login", identifier: "user@example.com" }),
      ).resolves.not.toThrow();
    });

    it("does not throw on reset", async () => {
      const noop = new NoopRateLimiter();

      await expect(
        noop.reset({ action: "login", identifier: "user@example.com" }),
      ).resolves.not.toThrow();
    });

    it("handles all action types", async () => {
      const noop = new NoopRateLimiter();

      const actions: RateLimitKey["action"][] = [
        "login",
        "register",
        "password-reset",
        "email-verification",
      ];

      for (const action of actions) {
        const result = await noop.check({ action, identifier: "user@example.com" });
        expect(result.allowed).toBe(true);
      }
    });

    it("supports optional namespace", async () => {
      const noop = new NoopRateLimiter();

      const result = await noop.check({
        action: "login",
        identifier: "user@example.com",
        namespace: "tenant-123",
      });

      expect(result.allowed).toBe(true);
    });
  });

  describe("RateLimitKey", () => {
    it("requires action and identifier", () => {
      const key: RateLimitKey = {
        action: "login",
        identifier: "user@example.com",
      };

      expect(key.action).toBeDefined();
      expect(key.identifier).toBeDefined();
    });

    it("accepts optional namespace", () => {
      const key: RateLimitKey = {
        action: "login",
        identifier: "user@example.com",
        namespace: "tenant-456",
      };

      expect(key.namespace).toBe("tenant-456");
    });

    it("supports all action types", () => {
      const actions = ["login", "register", "password-reset", "email-verification"] as const;

      for (const action of actions) {
        const key: RateLimitKey = {
          action,
          identifier: "user@example.com",
        };
        expect(key.action).toBe(action);
      }
    });
  });

  describe("RateLimitResult", () => {
    it("contains all required fields", async () => {
      const noop = new NoopRateLimiter();
      const result = await noop.check({ action: "login", identifier: "user@example.com" });

      expect(result.allowed).toBeDefined();
      expect(typeof result.allowed).toBe("boolean");
      expect(result.remaining).toBeDefined();
      expect(typeof result.remaining).toBe("number");
      expect(result.resetAt).toBeDefined();
      expect(typeof result.resetAt).toBe("number");
      expect(result.limit).toBeDefined();
      expect(typeof result.limit).toBe("number");
    });

    it("remaining is never negative", async () => {
      const spy = new SpyRateLimiter();
      spy.shouldAllow = false;

      const result = await spy.check({ action: "login", identifier: "user@example.com" });

      expect(result.remaining).toBeGreaterThanOrEqual(0);
    });

    it("resetAt is in the future", async () => {
      const noop = new NoopRateLimiter();

      const beforeCheck = Date.now();
      const result = await noop.check({ action: "login", identifier: "user@example.com" });
      const afterCheck = Date.now();

      expect(result.resetAt).toBeGreaterThan(beforeCheck);
      expect(result.resetAt).toBeGreaterThan(afterCheck);
    });

    it("limit is greater than or equal to remaining", async () => {
      const noop = new NoopRateLimiter();

      const result = await noop.check({ action: "login", identifier: "user@example.com" });

      expect(result.limit).toBeGreaterThanOrEqual(result.remaining);
    });
  });
});
