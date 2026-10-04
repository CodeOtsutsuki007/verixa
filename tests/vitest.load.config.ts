import { defineConfig, mergeConfig } from "vitest/config";

import config from "./vitest.config.js";

/**
 * Separate config for the audit write-path load test (Issue #134).
 *
 * It has its own file for the same reason `packages/stellar-anchor/
 * vitest.testnet.config.ts` does: the default config excludes these specs, and
 * Vitest applies `exclude` even to files named on the command line, so there
 * is no way to opt one back in without a second config.
 *
 * Kept out of the default run deliberately. The numbers it produces are only
 * meaningful against a specific machine, and putting them in a shared CI log
 * invites exactly the cross-machine comparison `docs/performance/baseline.md`
 * warns against. Run it with `pnpm test:load`.
 *
 * The specs are named `*.load.ts` rather than `*.load.spec.ts` so that the
 * default `vitest run` in this package cannot match them at all — Vitest's
 * built-in include pattern looks only for `.spec`/`.test` files, so exclusion
 * needs no change to `vitest.config.ts` and cannot be undone by accident.
 */
export default mergeConfig(
  config,
  defineConfig({
    test: {
      name: "@verixa/integration-tests:load",
      include: ["load/**/*.load.ts"],
      // Thousands of real inserts, plus warm-up runs.
      testTimeout: 180_000,
      hookTimeout: 180_000,
      // One database, and the suites truncate the audit table between runs.
      fileParallelism: false,
    },
  }),
);
