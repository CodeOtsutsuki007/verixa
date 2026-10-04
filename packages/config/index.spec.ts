import { describe, expect, it } from "vitest";

import { ConfigError, loadConfig } from "./index.js";

describe("loadConfig", () => {
  it("produces a typed config object from a fully-specified environment", () => {
    const config = loadConfig({
      NODE_ENV: "production",
      PORT: "8080",
      HOST: "127.0.0.1",
      LOG_LEVEL: "warn",
      DATABASE_URL: "postgres://user:pass@db.example.com:5432/verixa",
    });

    expect(config).toEqual({
      NODE_ENV: "production",
      PORT: 8080,
      HOST: "127.0.0.1",
      LOG_LEVEL: "warn",
      DATABASE_URL: "postgres://user:pass@db.example.com:5432/verixa",
      DATABASE_POOL_SIZE: 10,
      DATABASE_POOL_TIMEOUT_SECONDS: 10,
      SESSION_MAX_CONCURRENT_SESSIONS: 0,
      MFA_ENFORCEMENT_LEVEL: "optional",
      MFA_ALLOWED_METHODS: [],
    });
  });

  it("coerces PORT from a string to a number", () => {
    const config = loadConfig({ PORT: "4000" });

    expect(config.PORT).toBe(4000);
    expect(typeof config.PORT).toBe("number");
  });

  it("applies defaults when optional variables are missing", () => {
    const config = loadConfig({});

    expect(config).toEqual({
      NODE_ENV: "development",
      PORT: 3000,
      HOST: "0.0.0.0",
      LOG_LEVEL: "info",
      DATABASE_URL: "postgres://verixa:verixa@localhost:5432/verixa",
      DATABASE_POOL_SIZE: 10,
      DATABASE_POOL_TIMEOUT_SECONDS: 10,
      SESSION_MAX_CONCURRENT_SESSIONS: 0,
      MFA_ENFORCEMENT_LEVEL: "optional",
      MFA_ALLOWED_METHODS: [],
    });
  });

  it("returns an immutable object", () => {
    const config = loadConfig({});

    expect(() => {
      // @ts-expect-error — the returned config is Readonly; this must fail to typecheck too.
      config.PORT = 9999;
    }).toThrow(TypeError);
  });

  it("throws a ConfigError listing every invalid field when values are malformed", () => {
    expect(() => loadConfig({ NODE_ENV: "staging", PORT: "not-a-number", HOST: "" })).toThrowError(
      ConfigError,
    );

    try {
      loadConfig({ NODE_ENV: "staging", PORT: "not-a-number", HOST: "" });
      expect.unreachable("loadConfig should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      const message = (error as ConfigError).message;
      expect(message).toContain("NODE_ENV");
      expect(message).toContain("PORT");
      expect(message).toContain("HOST");
    }
  });

  it("rejects a port outside the valid TCP range", () => {
    expect(() => loadConfig({ PORT: "70000" })).toThrowError(ConfigError);
  });

  it("coerces pool settings from strings and applies defaults", () => {
    const config = loadConfig({ DATABASE_POOL_SIZE: "25" });

    expect(config.DATABASE_POOL_SIZE).toBe(25);
    expect(config.DATABASE_POOL_TIMEOUT_SECONDS).toBe(10);
  });

  it("rejects a pool size above a stock Postgres max_connections", () => {
    // Above ~100 the failure mode changes from "requests queue" to
    // "connections are refused outright", which is much harder to diagnose.
    expect(() => loadConfig({ DATABASE_POOL_SIZE: "500" })).toThrowError(ConfigError);
  });

  it("rejects a non-positive pool size", () => {
    expect(() => loadConfig({ DATABASE_POOL_SIZE: "0" })).toThrowError(ConfigError);
  });

  it("rejects a malformed DATABASE_URL", () => {
    expect(() => loadConfig({ DATABASE_URL: "not-a-url" })).toThrowError(ConfigError);
  });

  it("defaults SESSION_MAX_CONCURRENT_SESSIONS to 0 (disabled)", () => {
    const config = loadConfig({});

    expect(config.SESSION_MAX_CONCURRENT_SESSIONS).toBe(0);
  });

  it("coerces SESSION_MAX_CONCURRENT_SESSIONS from a string", () => {
    const config = loadConfig({ SESSION_MAX_CONCURRENT_SESSIONS: "3" });

    expect(config.SESSION_MAX_CONCURRENT_SESSIONS).toBe(3);
    expect(typeof config.SESSION_MAX_CONCURRENT_SESSIONS).toBe("number");
  });

  it("rejects a negative SESSION_MAX_CONCURRENT_SESSIONS", () => {
    expect(() => loadConfig({ SESSION_MAX_CONCURRENT_SESSIONS: "-1" })).toThrowError(ConfigError);
  });
});
