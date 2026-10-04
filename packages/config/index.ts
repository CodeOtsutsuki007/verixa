import { z } from "zod";

import { ConfigError } from "./config-error.js";

export { ConfigError } from "./config-error.js";
export { loadSigningKeys, SIGNING_KEY_ALGORITHMS, SIGNING_KEYS_ENV_VAR } from "./signing-keys.js";
export type { SigningKeyAlgorithm, SigningKeyConfig } from "./signing-keys.js";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().max(65535).default(3000),
  HOST: z.string().min(1).default("0.0.0.0"),
  LOG_LEVEL: z.enum(["trace", "debug", "info", "warn", "error", "fatal", "silent"]).default("info"),
  // Not yet read by any repository (that starts with Issue 046) — present
  // now so it flows through the same validated, fail-fast config loading
  // as everything else, and so tooling like scripts/db-wait.mjs has one
  // canonical place to get it from instead of reading process.env directly.
  DATABASE_URL: z.string().url().default("postgres://verixa:verixa@localhost:5432/verixa"),

  /**
   * Maximum Postgres connections this process will hold open (Issue 053).
   *
   * Sizing formula: `pool size ≈ (peak concurrent requests that touch the
   * database) / (number of app instances)`, then round up modestly. It is
   * deliberately *not* "as high as the database allows."
   *
   * Raising this is the reflexive fix for connection-pool timeouts and
   * usually makes throughput worse. Every Postgres connection is a separate
   * OS process with its own memory (work_mem is per-operation, per-connection),
   * and past the point where active connections exceed available cores, they
   * compete for CPU and lock contention rather than doing more work — so
   * total throughput falls while every individual query gets slower. A pool
   * that is "too small" and briefly queues requests generally beats one that
   * lets a hundred connections thrash.
   *
   * Timeouts under load usually mean queries are too slow or held too long
   * (a transaction awaiting a network call, a missing index), and the pool is
   * just where the symptom appears. Fix the query before touching this.
   *
   * Capped at 100 because exceeding a stock Postgres `max_connections` (also
   * 100) means connection *errors*, not slowness — and the failure is far
   * more confusing than a queue. Multiple app instances share that budget:
   * ten instances at 20 each is 200, and the eleventh connection past the
   * limit fails outright.
   */
  DATABASE_POOL_SIZE: z.coerce.number().int().positive().max(100).default(10),

  /**
   * Seconds to wait for a free connection before giving up.
   *
   * Bounded on purpose. Waiting indefinitely turns pool exhaustion into a
   * hang that looks like a dead process, and each waiting request keeps
   * holding memory and an inbound socket — so an unbounded queue converts a
   * slow database into a full outage. Failing fast sheds load and surfaces
   * the real problem.
   */
  DATABASE_POOL_TIMEOUT_SECONDS: z.coerce.number().int().positive().max(300).default(10),

  /**
   * Maximum simultaneous active sessions a single user may hold (Issue 094).
   * Logging in past this limit evicts the least-recently-active session —
   * see `IssueSession` in `@verixa/sessions`.
   *
   * `0` (the default) disables enforcement entirely, per that issue's own
   * acceptance criterion. Unlike `DATABASE_POOL_SIZE`, there is no safe
   * non-zero default to fall back to: a banking-style deployment might want
   * `1`, a consumer product might never want this on, and guessing wrong in
   * either direction is a product decision this package has no basis to
   * make on a deployment's behalf. Zero is the only default that cannot
   * surprise anyone who has not deliberately opted in.
   */
  SESSION_MAX_CONCURRENT_SESSIONS: z.coerce.number().int().min(0).default(0),

  // ---------------------------------------------------------------------------
  // MFA enforcement — global defaults (Issue 114)
  //
  // These are the *global* defaults that apply when no org, role, or user
  // override is present. Individual orgs and users can raise or lower the bar
  // via runtime configuration stored in the database (not environment
  // variables), because per-tenant config cannot live in environment variables
  // — you would need one deployment per tenant if it did. The fields here give
  // operators a baseline that matches their deployment's security posture
  // without requiring every newly-created org to be individually configured.
  // ---------------------------------------------------------------------------

  /**
   * Global default MFA enforcement level (Issue 114).
   *
   * - `optional` (default): users may enroll but are not required to. A
   *   session is issued regardless. Safe for consumer-facing products where
   *   mandating MFA would cause friction before users understand the value.
   * - `required`: every user must complete an MFA challenge before a session
   *   is issued. Choose this for admin consoles, banking-style products, or
   *   any deployment where the threat model justifies the enrollment friction.
   * - `disabled`: MFA is blocked globally. Useful when authentication is
   *   delegated entirely to an external IdP that already enforces MFA and you
   *   do not want a second factor in Verixa itself.
   *
   * Per-org and per-user overrides take precedence over this value; see
   * `MfaEnforcementPolicy` in `packages/mfa`.
   */
  MFA_ENFORCEMENT_LEVEL: z.enum(["required", "optional", "disabled"]).default("optional"),

  /**
   * Comma-separated list of MFA method types permitted globally (Issue 114).
   *
   * Absent (empty string) means all types are permitted. Supply a list to
   * restrict: e.g. `MFA_ALLOWED_METHODS=totp,webauthn` to ban backup codes
   * org-wide when your security policy requires phishing-resistant factors.
   *
   * Valid values: `totp`, `webauthn`, `backup-codes`.
   *
   * The alternative — a separate boolean env var per method type — was
   * rejected because it scales poorly (N env vars for N methods, combinatorial
   * interactions) and cannot express "any subset of the three" cleanly.
   */
  MFA_ALLOWED_METHODS: z
    .string()
    .optional()
    .transform((val) =>
      val
        ? val
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
        : [],
    ),
});

/** The fully validated, immutable application configuration. */
export type Config = Readonly<z.infer<typeof envSchema>>;

/**
 * Validates `process.env` (or a supplied source, for testing) against the
 * application's configuration schema. Throws a {@link ConfigError} listing
 * every problem found, rather than letting an invalid or missing variable
 * surface later as a confusing runtime failure somewhere unrelated.
 */
export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const result = envSchema.safeParse(env);

  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `  - ${issue.path.join(".") || "(root)"}: ${issue.message}`)
      .join("\n");
    throw new ConfigError(`Invalid environment configuration:\n${details}`);
  }

  return Object.freeze(result.data);
}
