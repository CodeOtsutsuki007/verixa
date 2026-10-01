// @ts-check
import js from "@eslint/js";
import eslintConfigPrettier from "eslint-config-prettier";
import { createTypeScriptImportResolver } from "eslint-import-resolver-typescript";
import importPlugin from "eslint-plugin-import-x";
import security from "eslint-plugin-security";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    // scripts/** holds standalone Node scripts that aren't part of any
    // workspace package's tsconfig project (see docs/guides/database.md) —
    // type-aware linting needs a project to check against, which these
    // deliberately don't have.
    ignores: [
      "**/dist/**",
      "**/coverage/**",
      "**/node_modules/**",
      "**/*.config.*",
      "planning/**",
      "scripts/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  security.configs.recommended,
  importPlugin.flatConfigs.recommended,
  importPlugin.flatConfigs.typescript,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    settings: {
      "import-x/resolver-next": [createTypeScriptImportResolver()],
    },
    rules: {
      // Async bugs (unhandled rejections) are a common real-world production
      // failure mode; this rule requires promises to be awaited, returned, or
      // explicitly voided.
      "@typescript-eslint/no-floating-promises": "error",
      "import-x/order": [
        "error",
        {
          "newlines-between": "always",
          alphabetize: { order: "asc", caseInsensitive: true },
        },
      ],
      // TypeScript's own resolution already catches unresolved imports.
      "import-x/no-unresolved": "off",
    },
  },
  {
    // Package boundary enforcement: everything outside a context package
    // must go through its curated index.ts, never a deep path into its
    // domain/application internals — see docs/guides/domain-modeling.md
    // ("Package encapsulation"). Scoped to exclude packages/identity and
    // packages/credentials themselves, since their own internal files
    // legitimately import each other by relative path; this rule targets
    // deep imports from *other* packages.
    files: ["**/*.ts"],
    ignores: [
      "packages/identity/**",
      "packages/credentials/**",
      "packages/sessions/**",
      "packages/authorization/**",
    ],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["@verixa/identity/*", "@verixa/credentials/*", "@verixa/sessions/*"],
              message:
                "Import from the package root (`@verixa/identity`, `@verixa/credentials`, `@verixa/sessions`), not a deep path — a context's domain/application internals are not part of its public API. See docs/guides/domain-modeling.md.",
            },
          ],
        },
      ],
    },
  },
  {
    // Layering enforcement, which is the rule this whole architecture rests
    // on and the one a new contributor breaks first.
    //
    // Domain and application code must not reach for infrastructure. A domain
    // entity that imports Prisma cannot be unit-tested without a database, and
    // a use case that imports Fastify cannot be reused outside HTTP — at which
    // point the ports are decoration and the layering is a naming convention.
    //
    // The fix, when this fires, is almost always to define a port in
    // `application/ports/` and let the composition root supply the adapter.
    // See docs/guides/domain-modeling.md.
    files: ["packages/*/domain/**/*.ts", "packages/*/application/**/*.ts"],
    ignores: ["**/*.spec.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: [
                "**/infrastructure/**",
                "@prisma/client",
                "@verixa/database",
                "fastify",
                "@stellar/stellar-sdk",
              ],
              message:
                "Domain and application layers must not import infrastructure. Define a port in `application/ports/` and wire the concrete implementation in the composition root instead. See docs/guides/domain-modeling.md.",
            },
          ],
        },
      ],
    },
  },
  eslintConfigPrettier,
);
