import { defineConfig, mergeConfig } from "vitest/config";

import baseConfig from "../../vitest.config.js";

export default mergeConfig(
  baseConfig,
  defineConfig({
    test: {
      name: "@verixa/authorization",
      coverage: {
        // Ports are interface-only files: a TypeScript `interface` is erased at
        // compile time, so there is no executable statement a test could cover.
        // Counting them would report a meaningless 0% for a file with zero
        // total statements, the same reasoning @verixa/identity documents.
        exclude: ["**/application/ports/**", "index.ts"],
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
