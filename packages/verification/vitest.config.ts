import { defineConfig, mergeConfig } from "vitest/config";

import baseConfig from "../../vitest.config.js";

export default mergeConfig(
  baseConfig,
  defineConfig({
    test: {
      name: "@verixa/verification",
      coverage: {
        // Interface-only ports have no executable statements to cover — a
        // TypeScript `interface` is erased at compile time, so there is
        // nothing a test could exercise. The Prisma adapter is covered by the
        // shared repository contract suite, which only runs where a real
        // Postgres is reachable; counting it here would make the gate measure
        // "was a database present" rather than "is this code tested". See
        // `docs/guides/testing.md`.
        exclude: [
          "**/application/ports/**",
          "index.ts",
          "**/infrastructure/persistence/**",
          "**/infrastructure/testing/contracts/**",
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
