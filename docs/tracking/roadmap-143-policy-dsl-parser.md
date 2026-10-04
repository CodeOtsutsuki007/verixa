# Tracking: [143] Policy DSL lexer & parser

## Status

**Blocked** — depends on #78 and #79, both open.

- Issue: https://github.com/Kyvera-Labs/verixa/issues/80
- Phase: 08 — Authorization: ABAC / Policy Engine, roadmap issue 143
- Verified at: `138d1e0` (`master`)

This is a tracking note, not an implementation.

## Blocking dependencies

- #78 — roadmap 141: Policy domain model (Policy, Rule, Effect, Condition) (open)
- #79 — roadmap 142: Policy DSL grammar design (open)

## Why this is blocked

The parser's whole contract is to translate #79's grammar into #78's
`Condition`/`Rule`/`Policy` AST and to report a `PolicyParseError` with
line/column position information. Neither the grammar nor the AST exists on
`master`, so there is no target model to produce, no grammar corpus to parse
against, and no package (`packages/authorization`) to place `domain/dsl/` in.

## What unblocks it

#78 (the AST) and #79 (the grammar and its example corpus) merging.

## Plan once unblocked

1. Hand-written lexer and recursive-descent parser in
   `packages/authorization/domain/dsl/` (`lexer.ts`, `parser.ts`, `errors.ts`).
2. `PolicyParseError` carrying line/column and an expected-token message; no raw
   exceptions escape to callers.
3. Unit tests: the valid-grammar corpus parses to the expected AST; the
   malformed-input corpus produces accurate error positions; precedence and
   associativity edges are covered. The parser contains no evaluation logic —
   parsing and evaluation stay separate.
