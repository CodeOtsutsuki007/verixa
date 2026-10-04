import { defineConfig, mergeConfig } from "vitest/config";

import baseConfig from "../../vitest.config.js";

export default mergeConfig(
  baseConfig,
  defineConfig({
    test: {
      name: "@verixa/audit",
      coverage: {
        // The same gate `packages/identity` runs under (Issue 037), with the
        // same reason for each exclusion: the threshold should measure "is
        // this code tested", not "what kind of file is it".
        exclude: [
          // Interface-only files have no executable statements to cover — a
          // TypeScript `interface` is erased entirely at compile time, so there
          // is nothing a test could ever exercise.
          "**/application/ports/**",
          "index.ts",
          // Database adapters are exercised by the Postgres-backed suite in
          // `tests/integration`, which only runs where a real database exists.
          // Counting them here would make the gate measure "was a database
          // present" rather than "is this code tested", so it would fail on a
          // laptop without Docker while passing in CI for the same commit.
          "**/infrastructure/persistence/**",
          // The operator CLI is the same problem one layer up: it needs a live
          // `DATABASE_URL`, is run by hand during an incident, and its logic is
          // the use case it delegates to — which *is* covered. What is left in
          // the file is argument parsing and printing.
          "**/infrastructure/cli/**",
          // A demo script, never imported by anything that ships.
          "**/scripts/**",
        ],
        thresholds: {
          statements: 90,
          lines: 90,
          functions: 85,
          branches: 85,
        },
      },
    },
  }),
);
